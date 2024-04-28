--[[
    License: GPL3
    Author: Eldar Khayrullin
    Email: eldar.khayrullin@mail.ru
    Date: 2024
    Description: Wireshark Dissector for Lineage2Login
    Protocol: 785a
]]--

local cmn = require("common")

local LOGIN_PORT = 2106

local INIT = 0x00
local LOGIN_FAIL = 0x01
local ACCOUNT_KICKED = 0x02
local LOGIN_OK = 0x03
local SERVER_LIST = 0x04
local PLAY_FAIL = 0x06
local PLAY_OK = 0x07
local GG_AUTH = 0x0B
local SERVER_OPCODE = {
    [INIT] = "Init",
    [LOGIN_FAIL] = "LoginFail",
    [ACCOUNT_KICKED] = "AccountKicked",
    [LOGIN_OK] = "LoginOk",
    [SERVER_LIST] = "ServerList",
    [PLAY_FAIL] = "PlayFail",
    [PLAY_OK] = "PlayOk",
    [GG_AUTH] = "GGAuth",
}

local REQUEST_AUTH_LOGIN = 0x00
local REQUEST_SERVER_LOGIN = 0x02
local REQUEST_SERVER_LIST = 0x05
local REQUEST_GG_AUTH = 0x07
local CLIENT_OPCODE = {
    [REQUEST_AUTH_LOGIN] = "RequestAuthLogin",
    [REQUEST_SERVER_LOGIN] = "RequestServerLogin",
    [REQUEST_SERVER_LIST] = "RequestServerList",
    [REQUEST_GG_AUTH] = "RequestGGAuth",
}

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

local pf_length = ProtoField.uint16("lineage2login.length", "Length", base.DEC)
local pf_bool = ProtoField.bool("lineage2login.bool", " ")
local pf_uint8 = ProtoField.uint8("lineage2login.uint8", " ", base.DEC)
local pf_uint16 = ProtoField.uint16("lineage2login.uint16", " ", base.DEC)
local pf_uint32 = ProtoField.uint32("lineage2login.uint32", " ", base.DEC)
local pf_dword = ProtoField.uint32("lineage2login.dword", " ", base.HEX)
local pf_string = ProtoField.string("lineage2login.string", " ", base.ASCII)
local pf_stringz = ProtoField.stringz("lineage2login.stringz", " ", base.ASCII)
local pf_ipv4 = ProtoField.ipv4("lineage2login.ipv4", " ")
local pf_server_opcode = ProtoField.uint8("lineage2login.server_opcode",
                                          "Opcode", base.HEX, SERVER_OPCODE)
local pf_client_opcode = ProtoField.uint8("lineage2login.client_opcode",
                                          "Opcode", base.HEX, CLIENT_OPCODE)
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
    pf_length,
    pf_server_opcode,
    pf_client_opcode,
    pf_bool,
    pf_uint8,
    pf_uint16,
    pf_uint32,
    pf_dword,
    pf_string,
    pf_stringz,
    pf_ipv4,
    pf_login_fail_reason,
    pf_account_kicked_reason,
    pf_play_fail_reason,
    pf_gg_auth_response,
}

local function is_encrypted_packet(buffer, isserver)
    return not (isserver and buffer:len() == 11 and buffer(2, 1):uint() == 0x00)
end

local function decode_server_data(opcode, data, isencrypted, tree)
    if opcode == INIT then
        cmn.add_le(tree, pf_dword, data(0, 4), "Session ID", isencrypted)
        cmn.add_le(tree, pf_dword, data(4, 4), "Protocol version", isencrypted)
    elseif opcode == LOGIN_FAIL then
        cmn.add_le(tree, pf_login_fail_reason, data(0, 4), nil, isencrypted)
    elseif opcode == ACCOUNT_KICKED then
        cmn.add_le(tree, pf_account_kicked_reason, data(0, 4), nil, isencrypted)
    elseif opcode == LOGIN_OK then
        cmn.add_le(tree, pf_dword, data(0, 4), "Session Key 1.1", isencrypted)
        cmn.add_le(tree, pf_dword, data(4, 4), "Session Key 1.2", isencrypted)
    elseif opcode == SERVER_LIST then
        cmn.add_le(tree, pf_uint8, data(0, 1), "Count", isencrypted)
        local blk_sz = 21
        for i = 0, data(0, 1):uint() - 1 do
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
    elseif opcode == PLAY_FAIL then
        cmn.add_le(tree, pf_play_fail_reason, data(0, 4), nil, isencrypted)
    elseif opcode == PLAY_OK then
        cmn.add_le(tree, pf_dword, data(0, 4), "Session Key 2.1", isencrypted)
        cmn.add_le(tree, pf_dword, data(4, 4), "Session Key 2.2", isencrypted)
    elseif opcode == GG_AUTH then
        cmn.add_le(tree, pf_gg_auth_response, data(0, 4), nil, isencrypted)
    end
end

local function decode_client_data(opcode, data, isencrypted, tree)
    if opcode == REQUEST_AUTH_LOGIN then
        cmn.add_le(tree, pf_string, data(0, 14), "Login", isencrypted)
        cmn.add_le(tree, pf_string, data(14, 16), "Password", isencrypted)
    elseif opcode == REQUEST_SERVER_LOGIN then
        cmn.add_le(tree, pf_dword, data(0, 4), "Session Key 1.1", isencrypted)
        cmn.add_le(tree, pf_dword, data(4, 4), "Session Key 1.2", isencrypted)
        cmn.add_le(tree, pf_uint8, data(8, 1), "Server ID", isencrypted)
    elseif opcode == REQUEST_SERVER_LIST then
        cmn.add_le(tree, pf_dword, data(0, 4), "Session Key 1.1", isencrypted)
        cmn.add_le(tree, pf_dword, data(4, 4), "Session Key 1.2", isencrypted)
    elseif opcode == REQUEST_GG_AUTH then
        cmn.add_le(tree, pf_dword, data(0, 4), "Session ID", isencrypted)
    end
end

function lineage2login.dissector(buffer, pinfo, tree)
    pinfo.cols.protocol = lineage2login.name

    if buffer:len() == 0 then return end

    local isserver = (pinfo.src_port == LOGIN_PORT)
    local opcode_field = isserver and pf_server_opcode or pf_client_opcode
    local opcode_tbl = isserver and SERVER_OPCODE or CLIENT_OPCODE
    local isencrypted = is_encrypted_packet(buffer, isserver)

    local subtree = tree:add(lineage2login, buffer(), "Lineage2 Login Protocol")
    subtree:add_le(pf_length, buffer(0, 2))

    local opcode_p = nil
    local data_p = nil
    if isencrypted then
        local dec = cmn.decrypt(buffer(2):bytes():raw())
        local dec_tvb = ByteArray.tvb(ByteArray.new(dec, true), "Decrypted")

        opcode_p = dec_tvb(0, 1)
        data_p = dec_tvb(1)
    else
        opcode_p = buffer(2, 1)
        data_p = buffer(3)
    end

    cmn.add_le(subtree, opcode_field, opcode_p, nil, isencrypted)

    local data_st = cmn.generated(tree:add(lineage2login, data_p, "Data"),
                                  isencrypted)

    local opcode = opcode_p:uint()
    local decode_data = isserver and decode_server_data or decode_client_data
    decode_data(opcode, data_p, isencrypted, data_st)

    cmn.set_info_field(isserver, isencrypted, opcode_tbl[opcode], pinfo)
end

local tcp_port = DissectorTable.get("tcp.port")
tcp_port:add(LOGIN_PORT, lineage2login)