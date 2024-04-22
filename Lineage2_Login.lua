--[[
    Author: Eldar Khayrullin
    Email: eldar.khayrullin@mail.ru
    Date: 2024-04-20 18:32:30
    Description: Wireshark Dissector for "Lineage2_Login"
]]--

local crypto = require("crypto")

local LOGIN_PORT = 2106

-- TODO use raw string instead ByteArray
local function swap_endian(data, bs)
    local swapped = ""
    for i = 0, data:len() - 1, bs do
        for j = i + bs - 1, i, -1 do
            local b = (j < data:len()) and data(j, 1):tohex() or "00"
            swapped = swapped .. b
        end
    end

    return ByteArray.new(swapped)
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
local Raw = ProtoField.bytes("lineage2_login.Raw", "Raw", base.NONE)
local ServerOpcode = ProtoField.uint8("lineage2_login.ServerOpcode", "Opcode", base.HEX, SERVER_OPCODE)
local ClientOpcode = ProtoField.uint8("lineage2_login.ClientOpcode", "Opcode", base.HEX, CLIENT_OPCODE)
local Data = ProtoField.bytes("lineage2_login.Data", "Data", base.NONE)

Lineage2Login.fields = {
    Length,
	Raw,
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
    subtree:add_le(Raw, buffer(0))
    if pinfo.src_port == LOGIN_PORT then
        subtree:add_le(ServerOpcode, buffer(2, 1))
    else
        subtree:add_le(ClientOpcode, buffer(2, 1))
    end
    subtree:add_le(Data, buffer(3))

    -- FIXME TEST OK
    -- local b = ByteArray.new("30 31 32")
    -- print(b)
    -- local r = b:raw()
    -- print(r)
    -- local br = ByteArray.new(r, true)
    -- print(br)
    -- FIXME TEST OK

    local bs = 4
    local le_data = swap_endian(buffer(2, length - 2):bytes(), bs)
    -- print(le_data)
    local le_data_raw = le_data:raw()
    -- print(le_data_raw)

    -- TODO key: hex string -> raw string
    local cipher = crypto.decrypt.new("blowfish",
        "\x64\x10\x30\x10\xae\x06\x31\x10\x16\x95\x30\x10\x32\x65\x30\x10\x71\x44\x30\x10\x00")
    local le_dec = cipher:update(le_data_raw)
    local le_dec2 = cipher:final()
    if le_dec2 == nil then le_dec2 = "" end

    le_dec = le_dec .. le_dec2

    -- local le_dec = crypto.decrypt("blowfish", le_data_raw,
    --     "\x64\x10\x30\x10\xae\x06\x31\x10\x16\x95\x30\x10\x32\x65\x30\x10\x71\x44\x30\x10\x00")
    -- print(le_dec)

    local dec = swap_endian(ByteArray.new(le_dec, true), bs)
    -- print(dec)
    local dec_raw = le_data:raw()
    -- print(dec_raw)

    -- print("NEXT")

    local tvb = ByteArray.tvb(dec, "Decrypt Data")
    -- local subtree2 = subtree:add(Lineage2Login, tvb(), "Decrypt")
    subtree:add_le(Raw, tvb()):set_generated()

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