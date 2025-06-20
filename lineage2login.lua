--[[
    License: GPL3
    Author: Eldar Khayrullin
    Email: eldar.khayrullin@mail.ru
    Date: 2024-2025
    Description: Wireshark Dissector for Lineage2Login
]]--

local DESC = "Lineage2 Login Protocol"
local NAME = "LINEAGE2LOGIN"

set_plugin_info({
    version = "0.6.0",
    description = DESC,
    author = "Eldar Khayrullin",
    repository = "https://gitlab.com/eldarkg/lineage2wireshark"
})

local bf = require("decrypt.blowfish")
local util = require("common.utils")
local packet = require("common.packet")

local PORT = 2106
local INIT_COUNT = 1

-- TODO generate by list of names vs protocol version
-- FIXME what difference in versions?
local VERSIONS = {
    {1, "Static Blowfish (785a)", 0x785A},
    {2, "Blowfish + RSA (c621)", 0xC621},
}
local DEFAULT_VERSION = VERSIONS[1][3]
-- TODO select PK for lineage version or use custom Init BlowfishPK
local BLOWFISH_PK_HEX = {
    -- original C1, Elmore: C2, C3
    [0x785A] = "5B 3B 27 2E 5D 39 34 2D 33 31 3D 3D 2D 25 26 40 21 5E 2B 5D 00",
    -- original C1
    [0xC621] = "5B 3B 27 2E 5D 39 34 2D 33 31 3D 3D 2D 25 26 40 21 5E 2B 5D 00",
    -- original C4
	-- [0x785A] = "5F 3B 35 2E 5D 39 34 2D 33 31 3D 3D 2D 25 78 54 21 5E 5B 24 00",
    -- Elmore C4
    -- [0xC621] = "2D BB 10 02 41 11 AF FF 61 18 BB 51 11 FD DD 33 1D 1D 22 76 00",
    -- Elmore
    -- [0x785A] = "64 10 30 10 AE 06 31 10 16 95 30 10 32 65 30 10 71 44 30 10 00",
}
-- TODO Add pref: RSA PK

local tap = Listener.new("tcp", "tcp")

local proto = Proto(NAME, DESC)
local pf = require("common.protofields").init(proto.name)
proto.fields = pf
local pe = require("common.protoexperts").init(proto.name)
proto.experts = pe
proto.prefs.version = Pref.enum("Protocol Version", DEFAULT_VERSION,
                                "Protocol Version", VERSIONS, false)
proto.prefs.bf_pk_hex = Pref.string("Init Blowfish Private Key",
                                    "", "Format: hex stream")

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
local blowfish_pk
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
        end
    end

    local isencrypted = not init_packet_number_cache[pinfo.number]
    local payload = packet.payload(tvb)
    if not isencrypted and isserver then
        local opcode_len = packet.opcode_len(payload, true)
        local opcode = packet.opcode(payload, opcode_len)
        -- TODO test by opcode number "0x00" Init ?
        if opcode_str(opcode, true) == "Init" then
            local data = packet.data(payload, opcode_len)
            local values = decode:get_values(data, opcode, true)
            if values.BlowfishPK then
                blowfish_pk = values.BlowfishPK
            end
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
        else
            last_subpacket_number = last_subpacket_number + 1
        end
    else
        last_packet_number = pinfo.number
        last_subpacket_number = 1
        last_opcode_stat = {}
    end

    local isencrypted = not init_packet_number_cache[pinfo.number]

    local payload
    if isencrypted then
        payload = bf.decrypt(packet.payload(tvb), blowfish_pk:raw())
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
        decode:bytes(subtree, blowfish_pk, "Blowfish PK")
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
    last_subpacket_number = nil
    last_opcode_stat = nil
    subpacket_count_cache = {}
    init_count = 0
    init_packet_number_cache = {}

    local bf_pk_hex = proto.prefs.bf_pk_hex
    if #bf_pk_hex == 0 then
        local ver = proto.prefs.version
        bf_pk_hex = BLOWFISH_PK_HEX[ver]
        if bf_pk_hex then
            blowfish_pk = ByteArray.new(bf_pk_hex)
        end
    else
        blowfish_pk = ByteArray.new(bf_pk_hex)
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
