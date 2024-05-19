--[[
    License: GPL3
    Author: Eldar Khayrullin
    Email: eldar.khayrullin@mail.ru
    Date: 2024
    Description: Wireshark Dissector for Lineage2Login
    Protocol: 785a
]]--

local DESC = "Lineage2 Login Protocol"
local NAME = "LINEAGE2LOGIN"

set_plugin_info({
    version = "0.5.0",
    description = DESC,
    author = "Eldar Khayrullin",
    repository = "https://gitlab.com/eldarkg/lineage2wireshark"
})

local bf = require("decrypt.blowfish")
local util = require("common.utils")
local packet = require("common.packet")

-- TODO generate by list of names vs protocol version
local VERSIONS = {
    {1, "Without GG (785a)", 0x785A},
    {2, "With GG (c621)", 0xC621}, -- TODO implement
}
local DEFAULT_VERSION = VERSIONS[1][3]
local DEFAULT_PORT = 2106
local DEFAULT_BLOWFISH_PK_HEX =
    "64 10 30 10 AE 06 31 10 16 95 30 10 32 65 30 10 71 44 30 10 00"

local PORT = DEFAULT_PORT
local BLOWFISH_PK = ByteArray.new(DEFAULT_BLOWFISH_PK_HEX)

local proto = Proto(NAME, DESC)
local pf = require("common.protofields").init(proto.name)
proto.fields = pf
local pe = require("common.protoexperts").init(proto.name)
proto.experts = pe
proto.prefs.version = Pref.enum("Protocol Version",
                                DEFAULT_VERSION,
                                "Protocol Version", VERSIONS, false)
proto.prefs.port = Pref.uint("Server port",
                             DEFAULT_PORT,
                             "Default: " .. DEFAULT_PORT)
proto.prefs.bf_pk_hex = Pref.string("Blowfish private key",
                                    DEFAULT_BLOWFISH_PK_HEX,
                                    "Default: " .. DEFAULT_BLOWFISH_PK_HEX)

---@param ver integer
---@return string
local function version_str(ver)
    return string.format("%x", ver)
end

local decode
---@param ver integer
local function init_decode(ver)
    local ver_str = version_str(ver)
    decode = require("common.decode").init(pf, pe, false, ver_str, "en")
end

init_decode(DEFAULT_VERSION)

---Init by proto.init
---Last packet pinfo.number
local last_packet_number
---Last sub packet number
local last_subpacket_number
---Opcode stat in last packet
---Key: opcode. Value: sub packet count
local last_opcode_stat
---Key: pinfo.number. Value: sub packet count
local subpacket_count_cache

---@param opcode integer
---@param isserver boolean
---@return string
local function opcode_str(opcode, isserver)
    return tostring(decode.OPCODE_NAME[isserver and "server" or "client"][opcode])
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
        else
            last_subpacket_number = last_subpacket_number + 1
        end
    else
        last_packet_number = pinfo.number
        last_subpacket_number = 1
        last_opcode_stat = {}
    end

    local isencrypted = packet.is_encrypted_login_packet(tvb, decode.OPCODE_NAME,
                                                         isserver)
    local payload
    if isencrypted then
        payload = bf.decrypt(packet.payload(tvb), BLOWFISH_PK:raw())
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
        decode:bytes(subtree, BLOWFISH_PK, "Blowfish PK")
    end

    local payload_tvbr = isencrypted and payload:tvb("Decrypted")()
                                     or packet.payload_tvbr(tvb)

    local opcode_tvbr = packet.opcode_tvbr(payload_tvbr, opcode_len)
    if opcode_tvbr then
        decode:opcode(subtree, opcode_tvbr, isencrypted)

        -- TODO simple packet.data_tvbr, opcode_len = 1 always
        local data_tvbr = packet.data_tvbr(payload_tvbr, 1)
        if data_tvbr then
            decode:data(subtree, data_tvbr, opcode, isencrypted, isserver)
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
    if tvb:len() == 0 then
        return 0
    end

    local isserver = (pinfo.src_port == PORT)
    return pinfo.visited and dissect_2pass(tvb, pinfo, tree, isserver)
                         or dissect_1pass(tvb, pinfo, tree, isserver)
end

function proto.init()
    last_packet_number = nil
    last_subpacket_number = nil
    last_opcode_stat = nil
    subpacket_count_cache = {}
end

function proto.prefs_changed()
    -- TODO select protocol by preference or by catch ProtocolVersion?
    -- TODO select lang by preference
    init_decode(proto.prefs.version)

    PORT = proto.prefs.port
    BLOWFISH_PK = ByteArray.new(proto.prefs.bf_pk_hex)
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
