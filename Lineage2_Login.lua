--[[
    License: GPL3
    Author: Eldar Khayrullin
    Email: eldar.khayrullin@mail.ru
    Date: 2024
    Description: Wireshark Dissector for "Lineage2_Login"
    Protocol: 785a
]]--

local crypto = require("crypto")

local LOGIN_PORT = 2106
local BLOWFISH_PK = "64 10 30 10 ae 06 31 10 16 95 30 10 32 65 30 10 71 44 30 10 00"

local function align_size(data, bs)
    alen = (bs - #data % bs) % bs
    for i = 1, alen do
        data = data .. "\x00"
    end

    return data
end

local function swap_endian(data, bs)
    local swapped = ""
    for i = 1, #data, bs do
        for j = i + bs - 1, i, -1 do
            local b = (j <= #data) and string.char(data:byte(j)) or "\x00"
            swapped = swapped .. b
        end
    end

    return swapped
end

local function decrypt(enc)
    local bf_bs = 8
    enc = align_size(enc, bf_bs)

    local bs = 4
    local enc_be = swap_endian(enc, bs)

    local cipher =
        crypto.decrypt.new("bf-ecb", Struct.fromhex(BLOWFISH_PK, " "))

    local dec_be = cipher:update(enc_be)
    local dec_be_next = cipher:final()
    dec_be = dec_be .. (dec_be_next and dec_be_next or "")

    -- FIXME not work?
    -- local dec_be = crypto.decrypt("bf-ecb", enc_be, Struct.fromhex(BLOWFISH_PK, " "))

    local dec = swap_endian(dec_be, bs)
    return dec
end

local function get_opcode_str(table, id)
    return table[id] and table[id] or ""
end

local function is_encrypted_packet(buffer, isserver)
    return not (isserver and buffer:len() == 11 and buffer(2, 1):uint() == 0x00)
end

local function generated(obj, isencrypted)
    return isencrypted and obj:set_generated() or obj
end

local function add_generic(add, obj, protofield, tvbrange, label, isencrypted)
    obj = generated(add(obj, protofield, tvbrange), isencrypted)
    obj = label and obj:prepend_text(label) or obj
end

local function add_le(obj, protofield, tvbrange, label, isencrypted)
    add_generic(obj.add_le, obj, protofield, tvbrange, label, isencrypted)
end

local function add_be(obj, protofield, tvbrange, label, isencrypted)
    add_generic(obj.add, obj, protofield, tvbrange, label, isencrypted)
end

local Lineage2Login = Proto("Lineage2_Login", "Lineage2 Login Protocol")

local SERVER_OPCODE = {
    [0x00] = "Init",
    [0x01] = "LoginFail",
    [0x02] = "AccountKicked",
    [0x03] = "LoginOk",
    [0x04] = "ServerList",
    [0x06] = "PlayFail",
    [0x07] = "PlayOk",
    [0x0B] = "GGAuth",
}

local CLIENT_OPCODE = {
    [0x00] = "RequestAuthLogin",
    [0x02] = "RequestServerLogin",
    [0x05] = "RequestServerList",
    [0x07] = "RequestGGAuth",
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
    [0x0f] = "Server overloaded",
}

local Length = ProtoField.uint16("lineage2_login.Length", "Length", base.DEC)
local ServerOpcode = ProtoField.uint8("lineage2_login.ServerOpcode", "Opcode",
                                      base.HEX, SERVER_OPCODE)
local ClientOpcode = ProtoField.uint8("lineage2_login.ClientOpcode", "Opcode",
                                      base.HEX, CLIENT_OPCODE)
local Data = ProtoField.bytes("lineage2_login.Data", "Data", base.NONE)
local Bool = ProtoField.bool("lineage2_login.Bool", " ")
local Uint8 = ProtoField.uint8("lineage2_login.Uint8", " ", base.DEC)
local Uint16 = ProtoField.uint16("lineage2_login.Uint16", " ", base.DEC)
local Uint32 = ProtoField.uint32("lineage2_login.Uint32", " ", base.DEC)
local Dword = ProtoField.uint32("lineage2_login.Dword", " ", base.HEX)
local String = ProtoField.string("lineage2_login.String", " ", base.ASCII)
local Stringz = ProtoField.stringz("lineage2_login.Stringz", " ", base.ASCII)
local IPv4 = ProtoField.ipv4("lineage2_login.IPv4", " ")
local LoginFailReason = ProtoField.uint32("lineage2_login.LoginFailReason",
                                          "Reason", base.HEX, LOGIN_FAIL_REASON)
local AccountKickedReason = ProtoField.uint32("lineage2_login.AccountKickedReason",
                                              "Reason", base.HEX,
                                              ACCOUNT_KICKED_REASON)
local PlayFailReason = ProtoField.uint32("lineage2_login.PlayFailReason",
                                         "Reason", base.HEX, PLAY_FAIL_REASON)


Lineage2Login.fields = {
    Length,
    ServerOpcode,
    ClientOpcode,
    Data,
    Bool,
    Uint8,
    Uint16,
    Uint32,
    Dword,
    String,
    Stringz,
    IPv4,
    LoginFailReason,
    AccountKickedReason,
    PlayFailReason,
}

local function decode_server_data(opcode, data, isencrypted, tree)
    if opcode == 0x00 then
        add_le(tree, Dword, data(0, 4), "Session ID", isencrypted)
        add_le(tree, Dword, data(4, 4), "Protocol ver.", isencrypted)
    elseif opcode == 0x01 then
        add_le(tree, LoginFailReason, data(0, 4), nil, isencrypted)
    elseif opcode == 0x02 then
        add_le(tree, AccountKickedReason, data(0, 4), nil, isencrypted)
    elseif opcode == 0x03 then
        add_le(tree, Dword, data(0, 4), "Session Key 1.1", isencrypted)
        add_le(tree, Dword, data(4, 4), "Session Key 1.2", isencrypted)
    elseif opcode == 0x04 then
        add_le(tree, Uint8, data(0, 1), "Count", isencrypted)
        local blk_sz = 21
        for i = 0, data(0, 1):uint() - 1 do
            local b = blk_sz * i
            local serv_st = generated(tree:add(Lineage2Login,
                                      data(b + 2, blk_sz),
                                      "Server " .. (i + 1)), isencrypted)
            add_le(serv_st, Uint8, data(b + 2, 1), "Server ID", isencrypted)
            add_be(serv_st, IPv4, data(b + 3, 4), "Game Server IP", isencrypted)
            add_le(serv_st, Uint32, data(b + 7, 4), "Port", isencrypted)
            add_le(serv_st, Uint8, data(b + 11, 1), "Age limit", isencrypted)
            add_le(serv_st, Bool, data(b + 12, 1), "PVP server", isencrypted)
            add_le(serv_st, Uint16, data(b + 13, 2), "Online", isencrypted)
            add_le(serv_st, Uint16, data(b + 15, 2), "Max", isencrypted)
            add_le(serv_st, Bool, data(b + 17, 1), "Test server", isencrypted)
        end
    elseif opcode == 0x06 then
        add_le(tree, PlayFailReason, data(0, 4), nil, isencrypted)
    elseif opcode == 0x07 then
        add_le(tree, Dword, data(0, 4), "Session Key 2.1", isencrypted)
        add_le(tree, Dword, data(4, 4), "Session Key 2.2", isencrypted)
    end
    -- TODO
end

local function decode_client_data(opcode, data, isencrypted, tree)
    if opcode == 0x00 then
        add_le(tree, String, data(0, 14), "Login", isencrypted)
        add_le(tree, String, data(14, 16), "Password", isencrypted)
    elseif opcode == 0x02 then
        add_le(tree, Dword, data(0, 4), "Session Key 1.1", isencrypted)
        add_le(tree, Dword, data(4, 4), "Session Key 1.2", isencrypted)
        add_le(tree, Uint8, data(8, 1), "Server ID", isencrypted)
    elseif opcode == 0x05 then
        add_le(tree, Dword, data(0, 4), "Session Key 1.1", isencrypted)
        add_le(tree, Dword, data(4, 4), "Session Key 1.2", isencrypted)
    end
    -- TODO
end

function Lineage2Login.dissector(buffer, pinfo, tree)
    pinfo.cols.protocol = Lineage2Login.name

    if buffer:len() == 0 then return end

    local isserver = (pinfo.src_port == LOGIN_PORT)
    local opcode_field = isserver and ServerOpcode or ClientOpcode
    local opcode_tbl = isserver and SERVER_OPCODE or CLIENT_OPCODE
    local isencrypted = is_encrypted_packet(buffer, isserver)

    local subtree = tree:add(Lineage2Login, buffer(), "Lineage2 Login Protocol")
    subtree:add_le(Length, buffer(0, 2))

    local opcode_p = nil
    local data_p = nil
    if isencrypted then
        local dec = decrypt(buffer(2):bytes():raw())
        local dec_tvb = ByteArray.tvb(ByteArray.new(dec, true), "Decrypted")

        opcode_p = dec_tvb(0, 1)
        data_p = dec_tvb(1)
    else
        opcode_p = buffer(2, 1)
        data_p = buffer(3)
    end

    add_le(subtree, opcode_field, opcode_p, nil, isencrypted)

    local data_st = generated(subtree:add(Lineage2Login, data_p, "Data"),
                              isencrypted)

    local opcode = opcode_p:uint()
    local decode_data = isserver and decode_server_data or decode_client_data
    decode_data(opcode, data_p, isencrypted, data_st)

    local src_role = isserver and "Server" or "Client"
    local opcode_str = get_opcode_str(opcode_tbl, opcode)
    pinfo.cols.info =
        tostring(pinfo.src_port) .. " → " .. tostring(pinfo.dst_port) ..
        " " ..  src_role .. ": " ..
        (isencrypted and ("[" .. opcode_str .. "]") or opcode_str)
end

local tcp_port = DissectorTable.get("tcp.port")
tcp_port:add(LOGIN_PORT, Lineage2Login)