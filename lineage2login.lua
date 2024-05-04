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

local SERVER_OPCODE = require("login.opcode.server").SERVER_OPCODE
local CLIENT_OPCODE = require("login.opcode.client").CLIENT_OPCODE
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

---@param tvb Tvb
---@param isserver boolean
---@return boolean
local function is_encrypted_packet(tvb, isserver)
    if isserver then
        local len = packet.length(tvb)
        local opcode = packet.opcode(tvb)
        return not (len == 11 and opcode == SERVER_OPCODE.Init)
    else
        return true
    end
end

local function decode_server_data(tree, opcode, data, isencrypted)
    if opcode == SERVER_OPCODE.Init then
        cmn.add_le(tree, pf.bin32, data(0, 4), "Session ID", isencrypted)
        cmn.add_le(tree, pf.bin32, data(4, 4), "Protocol version", isencrypted)
    elseif opcode == SERVER_OPCODE.LoginFail then
        cmn.add_le(tree, pf.login_fail_reason, data(0, 4), nil, isencrypted)
    elseif opcode == SERVER_OPCODE.AccountKicked then
        cmn.add_le(tree, pf.account_kicked_reason, data(0, 4), nil, isencrypted)
    elseif opcode == SERVER_OPCODE.LoginOk then
        cmn.add_le(tree, pf.bin32, data(0, 4), "Session Key 1.1", isencrypted)
        cmn.add_le(tree, pf.bin32, data(4, 4), "Session Key 1.2", isencrypted)
    elseif opcode == SERVER_OPCODE.ServerList then
        cmn.add_le(tree, pf.uint8, data(0, 1), "Count", isencrypted)
        local blk_sz = 21
        for i = 0, cmn.le(data(0, 1)) - 1 do
            local b = blk_sz * i
            local serv_st = cmn.generated(tree:add(lineage2login,
                                          data(b + 2, blk_sz),
                                          "Server " .. (i + 1)), isencrypted)
            cmn.add_le(serv_st, pf.uint8, data(b + 2, 1), "Server ID", isencrypted)
            cmn.add_be(serv_st, pf.ipv4, data(b + 3, 4), "Game Server IP", isencrypted)
            cmn.add_le(serv_st, pf.uint32, data(b + 7, 4), "Port", isencrypted)
            cmn.add_le(serv_st, pf.uint8, data(b + 11, 1), "Age limit", isencrypted)
            cmn.add_le(serv_st, pf.bool, data(b + 12, 1), "PVP server", isencrypted)
            cmn.add_le(serv_st, pf.uint16, data(b + 13, 2), "Online", isencrypted)
            cmn.add_le(serv_st, pf.uint16, data(b + 15, 2), "Max", isencrypted)
            cmn.add_le(serv_st, pf.bool, data(b + 17, 1), "Test server", isencrypted)
        end
    elseif opcode == SERVER_OPCODE.PlayFail then
        cmn.add_le(tree, pf.play_fail_reason, data(0, 4), nil, isencrypted)
    elseif opcode == SERVER_OPCODE.PlayOk then
        cmn.add_le(tree, pf.bin32, data(0, 4), "Session Key 2.1", isencrypted)
        cmn.add_le(tree, pf.bin32, data(4, 4), "Session Key 2.2", isencrypted)
    elseif opcode == SERVER_OPCODE.GGAuth then
        cmn.add_le(tree, pf.gg_auth_response, data(0, 4), nil, isencrypted)
    end
end

local function decode_client_data(tree, opcode, data, isencrypted)
    if opcode == CLIENT_OPCODE.RequestAuthLogin then
        cmn.add_le(tree, pf.string, data(0, 14), "Login", isencrypted)
        cmn.add_le(tree, pf.string, data(14, 16), "Password", isencrypted)
    elseif opcode == CLIENT_OPCODE.RequestServerLogin then
        cmn.add_le(tree, pf.bin32, data(0, 4), "Session Key 1.1", isencrypted)
        cmn.add_le(tree, pf.bin32, data(4, 4), "Session Key 1.2", isencrypted)
        cmn.add_le(tree, pf.uint8, data(8, 1), "Server ID", isencrypted)
    elseif opcode == CLIENT_OPCODE.RequestServerList then
        cmn.add_le(tree, pf.bin32, data(0, 4), "Session Key 1.1", isencrypted)
        cmn.add_le(tree, pf.bin32, data(4, 4), "Session Key 1.2", isencrypted)
    elseif opcode == CLIENT_OPCODE.RequestGGAuth then
        cmn.add_le(tree, pf.bin32, data(0, 4), "Session ID", isencrypted)
    end
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
    local opcode_txt_tbl = isserver and SERVER_OPCODE_TXT or CLIENT_OPCODE_TXT
    local isencrypted = is_encrypted_packet(tvb, isserver)

    cmn.add_le(tree, pf.uint16, packet.length_tvb(tvb), "Length", false)

    if isencrypted then
        local label = "Blowfish PK"
        local bf_pk_tvb = ByteArray.tvb(ByteArray.new(BLOWFISH_PK, true), label)
        cmn.add_le(tree, pf.bytes, bf_pk_tvb(), label, isencrypted)
    end

    local opcode_tvb = nil
    local data_tvb = nil
    if isencrypted then
        local dec = bf.decrypt(packet.encrypted_block(tvb), BLOWFISH_PK)
        local dec_tvb = ByteArray.tvb(ByteArray.new(dec, true), "Decrypted")

        opcode_tvb = packet.decrypted_opcode_tvb(dec_tvb(), isserver)
        data_tvb = dec_tvb(opcode_tvb:len())
    else
        opcode_tvb = packet.opcode_tvb(tvb)
        data_tvb = packet.data_tvb(tvb)
    end

    cmn.add_be(tree, pf_opcode, opcode_tvb, nil, isencrypted)

    -- TODO move to tree
    local data_st = cmn.generated(tree:add(lineage2login, data_tvb, "Data"),
                                  isencrypted)

    local opcode = cmn.be(opcode_tvb)
    local decode_data = isserver and decode_server_data or decode_client_data
    decode_data(data_st, opcode, data_tvb, isencrypted)

    cmn.set_info_field(pinfo, isserver, isencrypted, opcode_txt_tbl[opcode])

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