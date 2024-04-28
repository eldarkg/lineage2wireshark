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
}

-- TODO use isencrypted
local function decode_server_data(opcode, data, isencrypted, subtree)
    if opcode == 0x00 then
        subtree:add_le(Dword, data(0, 4)):prepend_text("Session ID")
        subtree:add_le(Dword, data(4, 4)):prepend_text("Protocol ver.")
    elseif opcode == 0x01 then
        subtree:add_le(LoginFailReason, data(0, 4)):set_generated()
    elseif opcode == 0x03 then
        subtree:add_le(Dword, data(0, 4)):prepend_text("Session Key 1.1"):set_generated()
        subtree:add_le(Dword, data(4, 4)):prepend_text("Session Key 1.2"):set_generated()
    elseif opcode == 0x04 then
        subtree:add_le(Uint8, data(0, 1)):prepend_text("Servers count"):set_generated()
        local blk_sz = 21
        for i = 0, data(0, 1):uint() - 1 do
            local b = blk_sz * i
            local subtree2 = subtree:add(Lineage2Login, data(b + 2, blk_sz),
                                         "Server " .. (i + 1)):set_generated()
            subtree2:add_le(Uint8, data(b + 2, 1)):prepend_text("Server ID")
            subtree2:add(IPv4, data(b + 3, 4)):prepend_text("Game Server IP")
            subtree2:add_le(Uint32, data(b + 7, 4)):prepend_text("Port")
            subtree2:add_le(Uint8, data(b + 11, 1)):prepend_text("Age limit")
            subtree2:add_le(Bool, data(b + 12, 1)):prepend_text("PVP server")
            subtree2:add_le(Uint16, data(b + 13, 2)):prepend_text("Online")
            subtree2:add_le(Uint16, data(b + 15, 2)):prepend_text("Max")
            subtree2:add_le(Bool, data(b + 17, 1)):prepend_text("Test server")
        end
    elseif opcode == 0x07 then
        subtree:add_le(Dword, data(0, 4)):prepend_text("Session Key 2.1"):set_generated()
        subtree:add_le(Dword, data(4, 4)):prepend_text("Session Key 2.2"):set_generated()
    end
    -- TODO
end

-- TODO use isencrypted
local function decode_client_data(opcode, data, isencrypted, subtree)
    if opcode == 0x00 then
        subtree:add_le(String, data(0, 14)):prepend_text("Login"):set_generated()
        subtree:add_le(String, data(14, 16)):prepend_text("Password"):set_generated()
    elseif opcode == 0x02 then
        subtree:add_le(Dword, data(0, 4)):prepend_text("Session Key 1.1"):set_generated()
        subtree:add_le(Dword, data(4, 4)):prepend_text("Session Key 1.2"):set_generated()
        subtree:add_le(Uint8, data(8, 1)):prepend_text("Server ID"):set_generated()
    elseif opcode == 0x05 then
        subtree:add_le(Dword, data(0, 4)):prepend_text("Session Key 1.1"):set_generated()
        subtree:add_le(Dword, data(4, 4)):prepend_text("Session Key 1.2"):set_generated()
    end
    -- TODO
end

function Lineage2Login.dissector(buffer, pinfo, tree)
    local length = buffer:len()
    if length == 0 then return end

    pinfo.cols.protocol = Lineage2Login.name
    local isserver = (pinfo.src_port == LOGIN_PORT)
    local src_role = isserver and "Server" or "Client"
    local opcode_field = isserver and ServerOpcode or ClientOpcode
    local opcode_tbl = isserver and SERVER_OPCODE or CLIENT_OPCODE
    local isencrypted = is_encrypted_packet(buffer, isserver)

    local subtree_main = tree:add(Lineage2Login, buffer(), "Lineage2 Login Protocol")
    local subtree = subtree_main:add(Lineage2Login, buffer(), "Packet")
    subtree:add_le(Length, buffer(0, 2))
    subtree:add_le(opcode_field, buffer(2, 1))
    subtree:add_le(Data, buffer(3))

    -- TODO only isencrypted
    local dec = decrypt(buffer(2):bytes():raw())

    local tvb = ByteArray.tvb(ByteArray.new(dec, true), "Decrypted Data")
    subtree:add_le(opcode_field, tvb(0, 1)):set_generated()
    subtree:add_le(Data, tvb(1)):set_generated()

    local opcode_p = isencrypted and tvb(0, 1) or buffer(2, 1)
    local opcode = opcode_p:uint()
    if isencrypted then
        subtree_main:add_le(opcode_field, opcode_p):set_generated()
    else
        subtree_main:add_le(opcode_field, opcode_p)
    end

    local data = isencrypted and tvb(1) or buffer(3)

    local decode_data = isserver and decode_server_data or decode_client_data
    decode_data(opcode, data, isencrypted, subtree_main)

    local opcode_str = get_opcode_str(opcode_tbl, opcode)
    pinfo.cols.info =
        tostring(pinfo.src_port) .. " → " .. tostring(pinfo.dst_port) ..
        " " ..  src_role .. ": " ..
        (isencrypted and ("[" .. opcode_str .. "]") or opcode_str)
end

local tcp_port = DissectorTable.get("tcp.port")
tcp_port:add(LOGIN_PORT, Lineage2Login)