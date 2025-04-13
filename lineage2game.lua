--[[
    License: GPL3
    Author: Eldar Khayrullin
    Email: eldar.khayrullin@mail.ru
    Date: 2024
    Description: Wireshark Dissector for Lineage2Game
]]--

local DESC = "Lineage2 Game Protocol"
local NAME = "LINEAGE2GAME"

set_plugin_info({
    version = "0.5.0",
    description = DESC,
    author = "Eldar Khayrullin",
    repository = "https://gitlab.com/eldarkg/lineage2wireshark"
})

local util = require("common.utils")
local packet = require("common.packet")
local xor = require("decrypt.xor")

local PORT = 7777
local INIT_COUNT = 2

-- TODO generate by list of names vs protocol version
local VERSIONS = {
    {1, "Chronicle 1: Harbingers of War (419)", 419},
    {2, "Chronicle 4: Scions of Destiny Update 1 (660)", 660},
    {3, "Chronicle 5: Oath of Blood Update 2 (709)", 709},
    {4, "CT0: Interlude Update 2 (746)", 746},
}
local DEFAULT_VERSION = VERSIONS[1][3]

local tap = Listener.new("tcp", "tcp")

local proto = Proto(NAME, DESC)
local pf = require("common.protofields").init(proto.name)
proto.fields = pf
local pe = require("common.protoexperts").init(proto.name)
proto.experts = pe
proto.prefs.version = Pref.enum("Protocol Version", DEFAULT_VERSION,
                                "Protocol Version", VERSIONS, false)
proto.prefs.high_xor_key_hex = Pref.string("Init high part of XOR Key",
                                           "", "Format: hex stream")
proto.prefs.init_server_xor_key_hex = Pref.string("Init server XOR Key",
                                                  "", "Format: hex stream")
proto.prefs.init_client_xor_key_hex = Pref.string("Init client XOR Key",
                                                  "", "Format: hex stream")

---@param ver integer
---@return string
local function version_str(ver)
    return string.format("%d", ver)
end

local decode
---@param ver integer
local function init_decode(ver)
    local ver_str = version_str(ver)
    decode = require("common.decode").init(pf, pe, true, ver_str, "en")
end

init_decode(DEFAULT_VERSION)

-- TODO implement module cache. Methods: new, set(number, val), last, get(number)?

---Init by proto.init
local high_xor_key
---Last packet pinfo.number
local last_packet_number
---Last sub packet number
local last_subpacket_number
---Opcode stat in last packet
---Key: opcode. Value: sub packet count
local last_opcode_stat
---Key: pinfo.number. Value: sub packet count
local subpacket_count_cache
---Server send SYN,ACK to Client. Next count number of init packets
local init_count
---Init packet numbers
local init_packet_number_cache

---Accumulator XOR decrypt length in current pinfo.number
local xor_accum_len
local server_xor_key
local client_xor_key
-- TODO save only dynamic part
---Key: pinfo.number. Value: XOR key
local xor_key_cache

---@param pinfo Pinfo
---@return boolean isserver
local function is_server(pinfo)
    return pinfo.src_port == PORT
end

---@param pinfo Pinfo
---@param tvb Tvb
---@param tapinfo table
function tap.packet(pinfo, tvb, tapinfo)
    local TH_SYN_ACK = 0x0012
    if is_server(pinfo) and tapinfo.th_flags == TH_SYN_ACK then
        init_count = INIT_COUNT
    end
end

---@param opcode integer
---@param isserver boolean
---@return string
local function opcode_str(opcode, isserver)
    return tostring(decode.OPCODE_NAME[isserver and "server" or "client"][opcode])
end

---@param key ByteArray Server XOR key
local function init_xor_keys(key)
    server_xor_key = xor.create_key(key, high_xor_key)
    client_xor_key = server_xor_key
end

---@param plen integer Previous decrypted data length
---@param isserver boolean
local function update_xor_key(plen, isserver)
    xor_accum_len = xor_accum_len + plen

    if isserver then
        server_xor_key = xor.next_key(server_xor_key, plen)
    else
        client_xor_key = xor.next_key(client_xor_key, plen)
    end
end

---@param opcode integer
local function update_last_opcode_stat(opcode)
    local count = last_opcode_stat[opcode]
    last_opcode_stat[opcode] = count and count + 1 or 1
end

---@param tvb Tvb
---@param pinfo Pinfo
---@param tree TreeItem
---@param isserver boolean
local function dissect_1pass(tvb, pinfo, tree, isserver)
    if pinfo.number == last_packet_number then
        subpacket_count_cache[pinfo.number] =
            subpacket_count_cache[pinfo.number] + 1
    else
        subpacket_count_cache[pinfo.number] = 1
        last_packet_number = pinfo.number

        if 0 < init_count then
            init_packet_number_cache[pinfo.number] = true
            init_count = init_count - 1
        else
            xor_accum_len = 0
            xor_key_cache[pinfo.number] = isserver and server_xor_key
                                                    or client_xor_key
        end
    end

    local isencrypted = not init_packet_number_cache[pinfo.number]
    local payload = packet.payload(tvb)
    if isencrypted then
        update_xor_key(payload:len(), isserver)
    elseif isserver then
        local opcode_len = packet.opcode_len(payload, true)
        local opcode = packet.opcode(payload, opcode_len)
        -- TODO test by opcode number "0x00" KeyInit ?
        if opcode_str(opcode, true) == "KeyInit" then
            local data = packet.data(payload, opcode_len)
            local values = decode:get_values(data, opcode, true)
            init_xor_keys(values.Key)
        end
    end

    return tvb:len()
end

---@param tvb Tvb
---@param pinfo Pinfo
---@param tree TreeItem
---@param isserver boolean
local function dissect_2pass(tvb, pinfo, tree, isserver)
    if pinfo.number == last_packet_number then
        if subpacket_count_cache[pinfo.number] <= last_subpacket_number then
            last_subpacket_number = 1
            xor_accum_len = 0
        else
            last_subpacket_number = last_subpacket_number + 1
        end
    else
        last_packet_number = pinfo.number
        last_subpacket_number = 1
        last_opcode_stat = {}
        xor_accum_len = 0
    end

    local isencrypted = not init_packet_number_cache[pinfo.number]

    local xor_key
    local payload
    if isencrypted then
        xor_key = xor.next_key(xor_key_cache[pinfo.number], xor_accum_len)
        payload = xor.decrypt(packet.payload(tvb), xor_key)
        xor_accum_len = xor_accum_len + payload:len()
    else
        payload = packet.payload(tvb)
    end

    local opcode_len = packet.opcode_len(payload, isserver)
    local opcode = packet.opcode(payload, opcode_len)
    update_last_opcode_stat(opcode)

    local subtree = tree:add(proto, tvb(),
                             tostring(last_subpacket_number) .. ". " ..
                             opcode_str(opcode, isserver))

    decode:length(subtree, packet.length_tvbr(tvb))

    if isencrypted then
        decode:bytes(subtree, xor_key, "XOR Key")
    end

    local payload_tvbr = isencrypted and payload:tvb("Decrypted")()
                                     or packet.payload_tvbr(tvb)

    local opcode_tvbr = packet.opcode_tvbr(payload_tvbr, opcode_len)
    if opcode_tvbr then
        decode:opcode(subtree, opcode_tvbr, isencrypted)

        -- TODO simple packet.data_tvbr, opcode_len = 1 always
        local data_tvbr = packet.data_tvbr(payload_tvbr, 1)
        if data_tvbr then
            decode:data(pinfo, subtree, data_tvbr, opcode, isencrypted, isserver)
        end
    end

    if subpacket_count_cache[pinfo.number] <= last_subpacket_number then
        util.set_info_field_stat(pinfo, isserver, isencrypted, last_opcode_stat,
                                 opcode_str)
    end

    return tvb:len()
end

---@param tvb Tvb
---@param pinfo Pinfo
---@param tree TreeItem
local function dissect(tvb, pinfo, tree)
    -- FIXME is it need?
    if tvb:len() == 0 then
        return 0
    end

    local isserver = is_server(pinfo)
    return pinfo.visited and dissect_2pass(tvb, pinfo, tree, isserver)
                         or dissect_1pass(tvb, pinfo, tree, isserver)
end

function proto.init()
    last_packet_number = nil
    last_subpacket_number = 1
    last_opcode_stat = {}
    subpacket_count_cache = {}
    init_count = 0
    init_packet_number_cache = {}

    xor_accum_len = nil
    xor_key_cache = {}

    local high_xor_key_hex = proto.prefs.high_xor_key_hex
    if #high_xor_key_hex == 0 then
        local ver = proto.prefs.version
        -- TODO get high xor key from KeyInit
        if ver == 419 then
            high_xor_key = ByteArray.new("")
        elseif ver == 746 then
            high_xor_key = ByteArray.new("C8 27 93 01 A1 6C 31 97")
        else
            high_xor_key = ByteArray.new("A1 6C 54 87")
        end
    else
        high_xor_key = ByteArray.new(high_xor_key_hex)
    end

    local init_server_xor_key_hex = proto.prefs.init_server_xor_key_hex
    if #init_server_xor_key_hex ~= 0 then
        server_xor_key = ByteArray.new(init_server_xor_key_hex)
    end

    local init_client_xor_key_hex = proto.prefs.init_client_xor_key_hex
    if #init_client_xor_key_hex ~= 0 then
        client_xor_key = ByteArray.new(init_client_xor_key_hex)
    end
end

function proto.prefs_changed()
    local ver = proto.prefs.version
    -- TODO select protocol by preference or by catch ProtocolVersion?
    -- TODO select lang by preference
    init_decode(ver)
end

---@param tvb Tvb
---@param pinfo Pinfo
---@param tree TreeItem
function proto.dissector(tvb, pinfo, tree)
    pinfo.cols.protocol = proto.name
    pinfo.cols.info = ""

    -- TODO multi instance by pinfo.src_port
    local ver = version_str(proto.prefs.version)
    local subtree = tree:add(proto, tvb(), DESC .. " (" .. ver .. ")")
    dissect_tcp_pdus(tvb, subtree, packet.HEADER_LEN, packet.get_len, dissect)
end

local tcp_port = DissectorTable.get("tcp.port")
tcp_port:add(PORT, proto)
