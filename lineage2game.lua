--[[
    License: GPL3
    Author: Eldar Khayrullin
    Email: eldar.khayrullin@mail.ru
    Date: 2024
    Description: Wireshark Dissector for Lineage2Game
    Protocol: 785a?
]]--

local cmn = require("common")

local GAME_PORT = 7777

local lineage2game = Proto("lineage2game", "Lineage2 Game Protocol")

local CRYPT_INIT = 0x00
local SERVER_OPCODE = {
    [CRYPT_INIT] = "CryptInit",
}

local PROTOCOL_VERSION = 0x00
local CLIENT_OPCODE = {
    [PROTOCOL_VERSION] = "ProtocolVersion",
}

local pf_bytes = ProtoField.bytes("lineage2game.bytes", " ", base.NONE)
local pf_bool = ProtoField.bool("lineage2game.bool", " ")
local pf_uint8 = ProtoField.uint8("lineage2game.uint8", " ", base.DEC)
local pf_uint16 = ProtoField.uint16("lineage2game.uint16", " ", base.DEC)
local pf_uint32 = ProtoField.uint32("lineage2game.uint32", " ", base.DEC)
local pf_bin32 = ProtoField.uint32("lineage2game.bin32", " ", base.HEX)
local pf_string = ProtoField.string("lineage2game.string", " ", base.ASCII)
local pf_stringz = ProtoField.stringz("lineage2game.stringz", " ", base.ASCII)
local pf_ipv4 = ProtoField.ipv4("lineage2game.ipv4", " ")
local pf_server_opcode = ProtoField.uint8("lineage2game.server_opcode",
                                          "Opcode", base.HEX, SERVER_OPCODE)
local pf_client_opcode = ProtoField.uint8("lineage2game.client_opcode",
                                          "Opcode", base.HEX, CLIENT_OPCODE)

lineage2game.fields = {
    pf_bytes,
    pf_uint16,
    pf_bin32,
    pf_server_opcode,
    pf_client_opcode,
}

local function decode_server_data(tree, opcode, data, isencrypted)
    if opcode == CRYPT_INIT then
        -- FIXME length 16 or 4 or full !?
        cmn.add_le(tree, pf_bytes, data(1), "XOR key", isencrypted)
    end
    -- TODO
end

local function decode_client_data(tree, opcode, data, isencrypted)
    if opcode == PROTOCOL_VERSION then
        cmn.add_le(tree, pf_bin32, data(0, 4), "Protocol version", isencrypted)
    end
    -- TODO
end

function lineage2game.dissector(buffer, pinfo, tree)
    pinfo.cols.protocol = lineage2game.name

    if buffer:len() == 0 then return end

    local isserver = (pinfo.src_port == GAME_PORT)
    local pf_opcode = isserver and pf_server_opcode or pf_client_opcode
    local opcode_tbl = isserver and SERVER_OPCODE or CLIENT_OPCODE
    local isencrypted = false -- FIXME

    local subtree = tree:add(lineage2game, buffer(), "Lineage2 Game Protocol")
    cmn.add_le(subtree, pf_uint16, buffer(0, 2), "Length", false)

    local opcode_p = buffer(2, 1)
    cmn.add_le(subtree, pf_opcode, opcode_p, nil, isencrypted)

    local data_p = buffer(3)
    local data_st = cmn.generated(tree:add(lineage2game, data_p, "Data"),
                                  isencrypted)

    local opcode = opcode_p:uint()
    local decode_data = isserver and decode_server_data or decode_client_data
    decode_data(data_st, opcode, data_p, isencrypted)

    cmn.set_info_field(pinfo, isserver, isencrypted, opcode_tbl[opcode])
end

local tcp_port = DissectorTable.get("tcp.port")
tcp_port:add(GAME_PORT, lineage2game)