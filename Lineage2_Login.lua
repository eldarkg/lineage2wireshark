--[[
    License: GPL3
    Author: Eldar Khayrullin
    Email: eldar.khayrullin@mail.ru
    Date: 2024
    Description: Wireshark Dissector for "Lineage2_Login"
    Protocol: 785a
]]--

local cmn = require("common")
local pf = require("protofields")

local LOGIN_PORT = 2106

local Lineage2Login = Proto("Lineage2_Login", "Lineage2 Login Protocol")

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

local ServerOpcode = ProtoField.uint8("lineage2_login.ServerOpcode", "Opcode",
                                      base.HEX, SERVER_OPCODE)
local ClientOpcode = ProtoField.uint8("lineage2_login.ClientOpcode", "Opcode",
                                      base.HEX, CLIENT_OPCODE)
local LoginFailReason = ProtoField.uint32("lineage2_login.LoginFailReason",
                                          "Reason", base.HEX, LOGIN_FAIL_REASON)
local AccountKickedReason = ProtoField.uint32("lineage2_login.AccountKickedReason",
                                              "Reason", base.HEX,
                                              ACCOUNT_KICKED_REASON)
local PlayFailReason = ProtoField.uint32("lineage2_login.PlayFailReason",
                                         "Reason", base.HEX, PLAY_FAIL_REASON)
local GGAuthResponse = ProtoField.uint32("lineage2_login.GGAuthResponse",
                                         "Response", base.HEX, GG_AUTH_RESPONSE)

Lineage2Login.fields = {
    pf.Length,
    ServerOpcode,
    ClientOpcode,
    pf.Data,
    pf.Bool,
    pf.Uint8,
    pf.Uint16,
    pf.Uint32,
    pf.Dword,
    pf.String,
    pf.Stringz,
    pf.IPv4,
    LoginFailReason,
    AccountKickedReason,
    PlayFailReason,
    GGAuthResponse,
}

local function is_encrypted_packet(buffer, isserver)
    return not (isserver and buffer:len() == 11 and buffer(2, 1):uint() == 0x00)
end

local function decode_server_data(opcode, data, isencrypted, tree)
    if opcode == INIT then
        cmn.add_le(tree, pf.Dword, data(0, 4), "Session ID", isencrypted)
        cmn.add_le(tree, pf.Dword, data(4, 4), "Protocol version", isencrypted)
    elseif opcode == LOGIN_FAIL then
        cmn.add_le(tree, LoginFailReason, data(0, 4), nil, isencrypted)
    elseif opcode == ACCOUNT_KICKED then
        cmn.add_le(tree, AccountKickedReason, data(0, 4), nil, isencrypted)
    elseif opcode == LOGIN_OK then
        cmn.add_le(tree, pf.Dword, data(0, 4), "Session Key 1.1", isencrypted)
        cmn.add_le(tree, pf.Dword, data(4, 4), "Session Key 1.2", isencrypted)
    elseif opcode == SERVER_LIST then
        cmn.add_le(tree, pf.Uint8, data(0, 1), "Count", isencrypted)
        local blk_sz = 21
        for i = 0, data(0, 1):uint() - 1 do
            local b = blk_sz * i
            local serv_st = cmn.generated(tree:add(Lineage2Login,
                                          data(b + 2, blk_sz),
                                          "Server " .. (i + 1)), isencrypted)
            cmn.add_le(serv_st, pf.Uint8, data(b + 2, 1), "Server ID", isencrypted)
            cmn.add_be(serv_st, pf.IPv4, data(b + 3, 4), "Game Server IP", isencrypted)
            cmn.add_le(serv_st, pf.Uint32, data(b + 7, 4), "Port", isencrypted)
            cmn.add_le(serv_st, pf.Uint8, data(b + 11, 1), "Age limit", isencrypted)
            cmn.add_le(serv_st, pf.Bool, data(b + 12, 1), "PVP server", isencrypted)
            cmn.add_le(serv_st, pf.Uint16, data(b + 13, 2), "Online", isencrypted)
            cmn.add_le(serv_st, pf.Uint16, data(b + 15, 2), "Max", isencrypted)
            cmn.add_le(serv_st, pf.Bool, data(b + 17, 1), "Test server", isencrypted)
        end
    elseif opcode == PLAY_FAIL then
        cmn.add_le(tree, PlayFailReason, data(0, 4), nil, isencrypted)
    elseif opcode == PLAY_OK then
        cmn.add_le(tree, pf.Dword, data(0, 4), "Session Key 2.1", isencrypted)
        cmn.add_le(tree, pf.Dword, data(4, 4), "Session Key 2.2", isencrypted)
    elseif opcode == GG_AUTH then
        cmn.add_le(tree, GGAuthResponse, data(0, 4), nil, isencrypted)
    end
end

local function decode_client_data(opcode, data, isencrypted, tree)
    if opcode == REQUEST_AUTH_LOGIN then
        cmn.add_le(tree, pf.String, data(0, 14), "Login", isencrypted)
        cmn.add_le(tree, pf.String, data(14, 16), "Password", isencrypted)
    elseif opcode == REQUEST_SERVER_LOGIN then
        cmn.add_le(tree, pf.Dword, data(0, 4), "Session Key 1.1", isencrypted)
        cmn.add_le(tree, pf.Dword, data(4, 4), "Session Key 1.2", isencrypted)
        cmn.add_le(tree, pf.Uint8, data(8, 1), "Server ID", isencrypted)
    elseif opcode == REQUEST_SERVER_LIST then
        cmn.add_le(tree, pf.Dword, data(0, 4), "Session Key 1.1", isencrypted)
        cmn.add_le(tree, pf.Dword, data(4, 4), "Session Key 1.2", isencrypted)
    elseif opcode == REQUEST_GG_AUTH then
        cmn.add_le(tree, pf.Dword, data(0, 4), "Session ID", isencrypted)
    end
end

function Lineage2Login.dissector(buffer, pinfo, tree)
    pinfo.cols.protocol = Lineage2Login.name

    if buffer:len() == 0 then return end

    local isserver = (pinfo.src_port == LOGIN_PORT)
    local opcode_field = isserver and ServerOpcode or ClientOpcode
    local opcode_tbl = isserver and SERVER_OPCODE or CLIENT_OPCODE
    local isencrypted = is_encrypted_packet(buffer, isserver)

    local subtree = tree:add(Lineage2Login, buffer(), "Lineage2 Login Protocol")
    subtree:add_le(pf.Length, buffer(0, 2))

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

    local data_st = cmn.generated(tree:add(Lineage2Login, data_p, "Data"),
                                  isencrypted)

    local opcode = opcode_p:uint()
    local decode_data = isserver and decode_server_data or decode_client_data
    decode_data(opcode, data_p, isencrypted, data_st)

    cmn.set_info_field(isserver, isencrypted, opcode_tbl[opcode], pinfo)
end

local tcp_port = DissectorTable.get("tcp.port")
tcp_port:add(LOGIN_PORT, Lineage2Login)