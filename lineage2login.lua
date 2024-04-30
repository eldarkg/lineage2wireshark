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

local LOGIN_PORT = 2106
local BLOWFISH_PK =
"\x64\x10\x30\x10\xAE\x06\x31\x10\x16\x95\x30\x10\x32\x65\x30\x10\x71\x44\x30\x10\x00"

local SERVER_OPCODE = {
    Init = 0x00,
    LoginFail = 0x01,
    AccountKicked = 0x02,
    LoginOk = 0x03,
    ServerList = 0x04,
    PlayFail = 0x06,
    PlayOk = 0x07,
    GGAuth = 0x0B,
}
local SERVER_OPCODE_TXT = cmn.invert(SERVER_OPCODE)

CLIENT_OPCODE = {
    RequestAuthLogin = 0x00,
    RequestServerLogin = 0x02,
    RequestServerList = 0x05,
    RequestGGAuth = 0x07,
}
local CLIENT_OPCODE_TXT = cmn.invert(CLIENT_OPCODE)

local LOGIN_FAIL_REASON = {
    [0x01] = "System error",
    [0x02] = "Invalid password",
    [0x03] = "Invalid login or password",
    [0x04] = "Access denied",
    [0x05] = "Invalid account",
    [0x07] = "Account is used",
    [0x09] = "Account is banned",
    [0x10] = "Server is service",
    [0x12] = "Validity period expired",
    [0x13] = "Account time is over",
}

local ACCOUNT_KICKED_REASON = {
    [0x01] = "Data stealer",
    [0x08] = "Generic violation",
    [0x10] = "7 days suspended",
    [0x20] = "Permanently banned",
}

local PLAY_FAIL_REASON = {
    [0x03] = "Invalid password",
    [0x04] = "Access failed. Please try again later",
    [0x0F] = "Server overloaded",
}

local GG_AUTH_RESPONSE = {
    [0x0B] = "Skip authorization",
}

local pf_bool = ProtoField.bool("lineage2login.bool", " ")
local pf_uint8 = ProtoField.uint8("lineage2login.uint8", " ", base.DEC)
local pf_uint16 = ProtoField.uint16("lineage2login.uint16", " ", base.DEC)
local pf_uint32 = ProtoField.uint32("lineage2login.uint32", " ", base.DEC)
local pf_bin32 = ProtoField.uint32("lineage2login.bin32", " ", base.HEX)
local pf_string = ProtoField.string("lineage2login.string", " ", base.ASCII)
local pf_ipv4 = ProtoField.ipv4("lineage2login.ipv4", " ")
local pf_server_opcode = ProtoField.uint8("lineage2login.server_opcode",
                                          "Opcode", base.HEX, SERVER_OPCODE_TXT)
local pf_client_opcode = ProtoField.uint8("lineage2login.client_opcode",
                                          "Opcode", base.HEX, CLIENT_OPCODE_TXT)
local pf_login_fail_reason = ProtoField.uint32("lineage2login.login_fail_reason",
                                               "Reason", base.HEX,
                                               LOGIN_FAIL_REASON)
local pf_account_kicked_reason = ProtoField.uint32("lineage2login.account_kicked_reason",
                                                   "Reason", base.HEX,
                                                   ACCOUNT_KICKED_REASON)
local pf_play_fail_reason = ProtoField.uint32("lineage2login.play_fail_reason",
                                              "Reason", base.HEX,
                                              PLAY_FAIL_REASON)
local pf_gg_auth_response = ProtoField.uint32("lineage2login.gg_auth_response",
                                              "Response", base.HEX,
                                              GG_AUTH_RESPONSE)

local lineage2login = Proto("lineage2login", "Lineage2 Login Protocol")
lineage2login.fields = {
    pf_bool,
    pf_uint8,
    pf_uint16,
    pf_uint32,
    pf_bin32,
    pf_string,
    pf_ipv4,
    pf_server_opcode,
    pf_client_opcode,
    pf_login_fail_reason,
    pf_account_kicked_reason,
    pf_play_fail_reason,
    pf_gg_auth_response,
}

---@param buffer ByteArray
---@param isserver boolean
---@return boolean
local function is_encrypted_packet(buffer, isserver)
    if isserver then
        local len = packet.length(buffer)
        local opcode = packet.opcode(buffer)
        return not (len == 11 and opcode == SERVER_OPCODE.Init)
    else
        return true
    end
end

local function decode_server_data(tree, opcode, data, isencrypted)
    if opcode == SERVER_OPCODE.Init then
        cmn.add_le(tree, pf_bin32, data(0, 4), "Session ID", isencrypted)
        cmn.add_le(tree, pf_bin32, data(4, 4), "Protocol version", isencrypted)
    elseif opcode == SERVER_OPCODE.LoginFail then
        cmn.add_le(tree, pf_login_fail_reason, data(0, 4), nil, isencrypted)
    elseif opcode == SERVER_OPCODE.AccountKicked then
        cmn.add_le(tree, pf_account_kicked_reason, data(0, 4), nil, isencrypted)
    elseif opcode == SERVER_OPCODE.LoginOk then
        cmn.add_le(tree, pf_bin32, data(0, 4), "Session Key 1.1", isencrypted)
        cmn.add_le(tree, pf_bin32, data(4, 4), "Session Key 1.2", isencrypted)
    elseif opcode == SERVER_OPCODE.ServerList then
        cmn.add_le(tree, pf_uint8, data(0, 1), "Count", isencrypted)
        local blk_sz = 21
        for i = 0, cmn.le(data(0, 1)) - 1 do
            local b = blk_sz * i
            local serv_st = cmn.generated(tree:add(lineage2login,
                                          data(b + 2, blk_sz),
                                          "Server " .. (i + 1)), isencrypted)
            cmn.add_le(serv_st, pf_uint8, data(b + 2, 1), "Server ID", isencrypted)
            cmn.add_be(serv_st, pf_ipv4, data(b + 3, 4), "Game Server IP", isencrypted)
            cmn.add_le(serv_st, pf_uint32, data(b + 7, 4), "Port", isencrypted)
            cmn.add_le(serv_st, pf_uint8, data(b + 11, 1), "Age limit", isencrypted)
            cmn.add_le(serv_st, pf_bool, data(b + 12, 1), "PVP server", isencrypted)
            cmn.add_le(serv_st, pf_uint16, data(b + 13, 2), "Online", isencrypted)
            cmn.add_le(serv_st, pf_uint16, data(b + 15, 2), "Max", isencrypted)
            cmn.add_le(serv_st, pf_bool, data(b + 17, 1), "Test server", isencrypted)
        end
    elseif opcode == SERVER_OPCODE.PlayFail then
        cmn.add_le(tree, pf_play_fail_reason, data(0, 4), nil, isencrypted)
    elseif opcode == SERVER_OPCODE.PlayOk then
        cmn.add_le(tree, pf_bin32, data(0, 4), "Session Key 2.1", isencrypted)
        cmn.add_le(tree, pf_bin32, data(4, 4), "Session Key 2.2", isencrypted)
    elseif opcode == SERVER_OPCODE.GGAuth then
        cmn.add_le(tree, pf_gg_auth_response, data(0, 4), nil, isencrypted)
    end
end

local function decode_client_data(tree, opcode, data, isencrypted)
    if opcode == CLIENT_OPCODE.RequestAuthLogin then
        cmn.add_le(tree, pf_string, data(0, 14), "Login", isencrypted)
        cmn.add_le(tree, pf_string, data(14, 16), "Password", isencrypted)
    elseif opcode == CLIENT_OPCODE.RequestServerLogin then
        cmn.add_le(tree, pf_bin32, data(0, 4), "Session Key 1.1", isencrypted)
        cmn.add_le(tree, pf_bin32, data(4, 4), "Session Key 1.2", isencrypted)
        cmn.add_le(tree, pf_uint8, data(8, 1), "Server ID", isencrypted)
    elseif opcode == CLIENT_OPCODE.RequestServerList then
        cmn.add_le(tree, pf_bin32, data(0, 4), "Session Key 1.1", isencrypted)
        cmn.add_le(tree, pf_bin32, data(4, 4), "Session Key 1.2", isencrypted)
    elseif opcode == CLIENT_OPCODE.RequestGGAuth then
        cmn.add_le(tree, pf_bin32, data(0, 4), "Session ID", isencrypted)
    end
end

function lineage2login.dissector(buffer, pinfo, tree)
    pinfo.cols.protocol = lineage2login.name

    if buffer:len() == 0 then return end

    local isserver = (pinfo.src_port == LOGIN_PORT)
    local pf_opcode = isserver and pf_server_opcode or pf_client_opcode
    local opcode_txt_tbl = isserver and SERVER_OPCODE_TXT or CLIENT_OPCODE_TXT
    local isencrypted = is_encrypted_packet(buffer, isserver)

    local subtree = tree:add(lineage2login, buffer(), "Lineage2 Login Protocol")
    cmn.add_le(subtree, pf_uint16, packet.length_buffer(buffer), "Length",
               false)

    local opcode_p = nil
    local data_p = nil
    if isencrypted then
        local dec = bf.decrypt(packet.encrypted_block(buffer), BLOWFISH_PK)
        local dec_tvb = ByteArray.tvb(ByteArray.new(dec, true), "Decrypted")

        opcode_p = dec_tvb(0, 1)
        data_p = dec_tvb(1)
    else
        opcode_p = packet.opcode_buffer(buffer)
        data_p = packet.data_buffer(buffer)
    end

    cmn.add_le(subtree, pf_opcode, opcode_p, nil, isencrypted)

    local data_st = cmn.generated(tree:add(lineage2login, data_p, "Data"),
                                  isencrypted)

    local opcode = cmn.le(opcode_p)
    local decode_data = isserver and decode_server_data or decode_client_data
    decode_data(data_st, opcode, data_p, isencrypted)

    cmn.set_info_field(pinfo, isserver, isencrypted, opcode_txt_tbl[opcode])
end

local tcp_port = DissectorTable.get("tcp.port")
tcp_port:add(LOGIN_PORT, lineage2login)