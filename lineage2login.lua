--[[
    License: GPL3
    Author: Eldar Khayrullin
    Email: eldar.khayrullin@mail.ru
    Date: 2024
    Description: Wireshark Dissector for Lineage2Login
    Protocol: 785a
]]--

local bf = require("blowfish")
local cmn = require("common")
local packet = require("packet")
local pf = require("login.protofield")

local decode_server_data = require("login.decode.server").decode_server_data
local decode_client_data = require("login.decode.client").decode_client_data

local SERVER_OPCODE_TXT = require("login.opcode.server").SERVER_OPCODE_TXT
local CLIENT_OPCODE_TXT = require("login.opcode.client").CLIENT_OPCODE_TXT

-- TODO move to protocol preferences
local LOGIN_PORT = 2106
local BLOWFISH_PK =
"\x64\x10\x30\x10\xAE\x06\x31\x10\x16\x95\x30\x10\x32\x65\x30\x10\x71\x44\x30\x10\x00"

local lineage2login = Proto("lineage2login", "Lineage2 Login Protocol")
lineage2login.fields = {
    pf.bytes,
    pf.bool,
    pf.uint8,
    pf.uint16,
    pf.uint32,
    pf.bin32,
    pf.string,
    pf.ipv4,
    pf.server_opcode,
    pf.client_opcode,
    pf.login_fail_reason,
    pf.account_kicked_reason,
    pf.play_fail_reason,
    pf.gg_auth_response,
}

---@param opcode number
---@param isserver boolean
---@return string
local function opcode_str(opcode, isserver)
    return tostring(isserver and SERVER_OPCODE_TXT[opcode]
                             or CLIENT_OPCODE_TXT[opcode])
end

---@param tvb Tvb
---@param pinfo Pinfo
---@param tree TreeItem
local function dissect(tvb, pinfo, tree)
    if tvb:len() == 0 then
        return 0
    end

    local isserver = (pinfo.src_port == LOGIN_PORT)
    local pf_opcode = isserver and pf.server_opcode or pf.client_opcode
    local isencrypted = packet.is_encrypted_login_packet(tvb, isserver)

    cmn.add_le(tree, pf.uint16, packet.length_tvbr(tvb), "Length", false)

    if isencrypted then
        local label = "Blowfish PK"
        local bf_pk_tvb = ByteArray.new(BLOWFISH_PK, true):tvb(label)
        cmn.add_le(tree, pf.bytes, bf_pk_tvb(), label, isencrypted)
    end

    local opcode_tvbr
    local data_tvbr
    if isencrypted then
        local dec_payload = bf.decrypt(packet.payload(tvb), BLOWFISH_PK)
        local dec_payload_tvb = ByteArray.tvb(dec_payload, "Decrypted")

        opcode_tvbr = packet.opcode_tvbr(dec_payload_tvb(), isserver)
        data_tvbr = dec_payload_tvb(opcode_tvbr:len())
    else
        opcode_tvbr = packet.opcode_tvbr(packet.payload_tvbr(tvb), isserver)
        data_tvbr = packet.data_tvbr(tvb)
    end

    cmn.add_be(tree, pf_opcode, opcode_tvbr, nil, isencrypted)

    -- TODO move to tree
    local data_st = cmn.generated(tree:add(lineage2login, data_tvbr, "Data"),
                                  isencrypted)

    local opcode = cmn.be(opcode_tvbr)
    local decode_data = isserver and decode_server_data or decode_client_data
    decode_data(data_st, opcode, data_tvbr, isencrypted)

    -- TODO use same algo as game
    cmn.set_info_field(pinfo, isserver, isencrypted, opcode_str(opcode, isserver))

    return tvb:len()
end

function lineage2login.init()
end

---@param tvb Tvb
---@param pinfo Pinfo
---@param tree TreeItem
function lineage2login.dissector(tvb, pinfo, tree)
    pinfo.cols.protocol = lineage2login.name
    pinfo.cols.info = ""

    local subtree = tree:add(lineage2login, tvb(), "Lineage2 Login Protocol")
    dissect_tcp_pdus(tvb, subtree, packet.HEADER_LEN, packet.get_len, dissect)
end

local tcp_port = DissectorTable.get("tcp.port")
tcp_port:add(LOGIN_PORT, lineage2login)