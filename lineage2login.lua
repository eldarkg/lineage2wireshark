--[[
    License: GPL3
    Author: Eldar Khayrullin
    Email: eldar.khayrullin@mail.ru
    Date: 2024
    Description: Wireshark Dissector for Lineage2Login
    Protocol: 785a
]]--

set_plugin_info({
    version = "0.1.0",
    description = "Lineage2Login",
    author = "Eldar Khayrullin",
    repository = "https://gitlab.com/eldarkg/lineage2wireshark"
})

local bf = require("decrypt.blowfish")
local util = require("common.utils")
local packet = require("common.packet")
-- TODO use decode
local pf = require("login.protofield")

local decode_server_data = require("login.decode.server").decode_server_data
local decode_client_data = require("login.decode.client").decode_client_data

local SERVER_OPCODE_TXT = require("login.opcode.server").SERVER_OPCODE_TXT
local CLIENT_OPCODE_TXT = require("login.opcode.client").CLIENT_OPCODE_TXT

local DEFAULT_LOGIN_PORT = 2106
local DEFAULT_BLOWFISH_PK_HEX =
    "64 10 30 10 AE 06 31 10 16 95 30 10 32 65 30 10 71 44 30 10 00"

local LOGIN_PORT = DEFAULT_LOGIN_PORT
local BLOWFISH_PK = ByteArray.new(DEFAULT_BLOWFISH_PK_HEX)

local lineage2login = Proto("lineage2login", "Lineage2 Login Protocol")
lineage2login.fields = require("login.protofield").init()
lineage2login.prefs.login_port =
    Pref.uint("Login server port", DEFAULT_LOGIN_PORT,
              "Default: " .. tostring(DEFAULT_LOGIN_PORT))
lineage2login.prefs.bf_pk_hex =
    Pref.string("Blowfish private key", DEFAULT_BLOWFISH_PK_HEX,
                "Default: " .. DEFAULT_BLOWFISH_PK_HEX)

---Init by lineage2login.init
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
    return isserver and tostring(SERVER_OPCODE_TXT[opcode])
                    or tostring(CLIENT_OPCODE_TXT[opcode])
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
    local isencrypted = packet.is_encrypted_login_packet(tvb, isserver)
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

    local isencrypted = packet.is_encrypted_login_packet(tvb, isserver)
    local payload = isencrypted
                        and bf.decrypt(packet.payload(tvb), BLOWFISH_PK:raw())
                        or packet.payload(tvb)

    local opcode_len = packet.opcode_len(payload, isserver)
    local opcode = packet.opcode(payload, opcode_len)
    update_last_opcode_stat(opcode)

    local subtree = tree:add(lineage2login, tvb(),
                             tostring(last_subpacket_number) .. ". " ..
                             opcode_str(opcode, isserver))
    util.add_le(subtree, pf.u16, packet.length_tvbr(tvb), "Length", false)

    if isencrypted then
        local label = "Blowfish PK"
        local bf_pk_tvb = BLOWFISH_PK:tvb(label)
        util.add_le(subtree, pf.bytes, bf_pk_tvb(), label, true)
    end

    local payload_tvbr = isencrypted and payload:tvb("Decrypted")()
                                     or packet.payload_tvbr(tvb)

    local opcode_tvbr = packet.opcode_tvbr(payload_tvbr, opcode_len)
    if opcode_tvbr then
        local pf_opcode = isserver and pf.server_opcode or pf.client_opcode
        util.add_be(subtree, pf_opcode, opcode_tvbr, nil, isencrypted)
    end

    -- TODO simple packet.data_tvbr, opcode_len = 1 always
    local data_tvbr = packet.data_tvbr(payload_tvbr, 1)
    if data_tvbr then
        local data_st = util.generated(subtree:add(lineage2login, data_tvbr, "Data"),
                                       isencrypted)
        local decode_data = isserver and decode_server_data or decode_client_data
        decode_data(data_st, opcode, data_tvbr, isencrypted)
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

    local isserver = (pinfo.src_port == LOGIN_PORT)
    return pinfo.visited and dissect_2pass(tvb, pinfo, tree, isserver)
                         or dissect_1pass(tvb, pinfo, tree, isserver)
end

function lineage2login.init()
    last_packet_number = nil
    last_subpacket_number = nil
    last_opcode_stat = nil
    subpacket_count_cache = {}
end

function lineage2login.prefs_changed()
    LOGIN_PORT = lineage2login.prefs.login_port
    BLOWFISH_PK = ByteArray.new(lineage2login.prefs.bf_pk_hex)
end

---@param tvb Tvb
---@param pinfo Pinfo
---@param tree TreeItem
function lineage2login.dissector(tvb, pinfo, tree)
    pinfo.cols.protocol = lineage2login.name
    pinfo.cols.info = ""

    -- TODO multi instance by pinfo.src_port
    local subtree = tree:add(lineage2login, tvb(), "Lineage2 Login Protocol")
    dissect_tcp_pdus(tvb, subtree, packet.HEADER_LEN, packet.get_len, dissect)
end

local tcp_port = DissectorTable.get("tcp.port")
tcp_port:add(LOGIN_PORT, lineage2login)