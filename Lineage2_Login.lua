--[[
    Author: Eldar Khayrullin
    Email: eldar.khayrullin@mail.ru
    Date: 2024-04-20 18:32:30
    Description: Wireshark Dissector for "Lineage2_Login"
]]--

local crypto = require("crypto")

local LOGIN_PORT = 2106
local BLOWFISH_PK = "64 10 30 10 ae 06 31 10 16 95 30 10 32 65 30 10 71 44 30 10 00"

-- TODO is it need?
local function align_size(data, bs)
    alen = (bs - #data % bs) % bs
    for i = 1, alen do
        data = data .. "\x00"
    end

    return data
end

local function swap_endian(data, bs)
    local swapped = ""
    for i = 1, data:len(), bs do
        for j = i + bs - 1, i, -1 do
            local b = (j <= data:len()) and string.char(data:byte(j)) or "\x00"
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

local Length = ProtoField.uint16("lineage2_login.Length", "Length", base.DEC)
local ServerOpcode = ProtoField.uint8("lineage2_login.ServerOpcode", "Opcode", base.HEX, SERVER_OPCODE)
local ClientOpcode = ProtoField.uint8("lineage2_login.ClientOpcode", "Opcode", base.HEX, CLIENT_OPCODE)
local Data = ProtoField.bytes("lineage2_login.Data", "Data", base.NONE)

Lineage2Login.fields = {
    Length,
	ServerOpcode,
	ClientOpcode,
	Data,
}

function Lineage2Login.dissector(buffer, pinfo, tree)
    local length = buffer:len()
    if length == 0 then return end

    pinfo.cols.protocol = Lineage2Login.name

    local subtree = tree:add(Lineage2Login, buffer(), "Lineage2 Login Protocol")

    subtree:add_le(Length, buffer(0, 2))
    subtree:add_le(
        (pinfo.src_port == LOGIN_PORT) and ServerOpcode or ClientOpcode,
        buffer(2, 1))
    subtree:add_le(Data, buffer(3))

    local dec = decrypt(buffer(2):bytes():raw())

    local tvb = ByteArray.tvb(ByteArray.new(dec, true), "Decrypted Data")
    -- local subtree2 = subtree:add(Lineage2Login, tvb(), "Decrypted Data")

    if pinfo.src_port == LOGIN_PORT then
        subtree:add_le(ServerOpcode, tvb(0, 1)):set_generated()

        local opcode = tostring(SERVER_OPCODE[buffer(2, 1):uint()])
            .. " [" .. tostring(SERVER_OPCODE[tvb(0, 1):uint()]) .. "]"
        pinfo.cols.info = tostring(pinfo.src_port) .. " → "
            .. tostring(pinfo.dst_port) .. " Server: " .. opcode
    else
        subtree:add_le(ClientOpcode, tvb(0, 1)):set_generated()

        local opcode = tostring(CLIENT_OPCODE[buffer(2, 1):uint()])
            .. " [" .. tostring(CLIENT_OPCODE[tvb(0, 1):uint()]) .. "]"
        pinfo.cols.info = tostring(pinfo.src_port) .. " → "
            .. tostring(pinfo.dst_port) .. " Client: " .. opcode
    end

    subtree:add_le(Data, tvb(1)):set_generated()

end

local tcp_port = DissectorTable.get("tcp.port")
tcp_port:add(LOGIN_PORT, Lineage2Login)