--[[
    Author: Eldar Khayrullin
    Email: eldar.khayrullin@mail.ru
    Date: 2024-04-20 18:32:30
    Description: Wireshark Dissector for "Lineage2_Login"
]]--

local crypto = require("crypto")

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

local Length = ProtoField.uint16("lineage2_login.Length", "Length", base.DEC)
local Raw = ProtoField.bytes("lineage2_login.Raw", "Raw", base.NONE)
local Opcode = ProtoField.uint8("lineage2_login.Opcode", "Opcode", base.HEX, SERVER_OPCODE)
local Data = ProtoField.bytes("lineage2_login.Data", "Data", base.NONE)

Lineage2Login.fields = {
    Length,
	Raw,
	Opcode,
	Data,
}

function Lineage2Login.dissector(buffer, pinfo, tree)
    local length = buffer:len()
    if length == 0 then return end

    if pinfo.src_port ~= 2106 then return end

    -- Adds dissector name to protocol column
    pinfo.cols.protocol = Lineage2Login.name

    -- Creates the subtree
    local subtree = tree:add(Lineage2Login, buffer(), "Lineage2 Login Protocol")

    -- Adds Variables to the subtree
    subtree:add_le(Length, buffer(0, 2))
	subtree:add_le(Raw, buffer(0))
	subtree:add_le(Opcode, buffer(2, 1))
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
	subtree:add_le(Opcode, tvb(0, 1)):set_generated()
	subtree:add_le(Data, tvb(1)):set_generated()

end

local tcp_port = DissectorTable.get("tcp.port")
tcp_port:add(2106, Lineage2Login)