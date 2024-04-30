--[[
    License: GPL3
    Author: Eldar Khayrullin
    Email: eldar.khayrullin@mail.ru
    Date: 2024
    Description: Wireshark Dissector for Lineage2Game
    Protocol: 709
]]--

local cmn = require("common")
local packet = require("packet")
local xor = require("xor")

local GAME_PORT = 7777
local STATIC_KEY = "\xA1\x6C\x54\x87"

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
    pf_uint32,
    pf_server_opcode,
    pf_client_opcode,
}

-- TODO save only dynamic part
local xor_key_cache = {}
local server_xor_key = ""
local client_xor_key = ""

---@param buffer ByteArray
---@param isserver boolean
---@return boolean
local function is_encrypted_packet(buffer, isserver)
    local len = packet.length(buffer)
    local opcode = packet.opcode(buffer)
    if isserver then
        return not (len == 16 and opcode == CRYPT_INIT)
    else
        return not (len == 263 and opcode == PROTOCOL_VERSION)
    end
end

local function decode_server_data(tree, opcode, data, isencrypted)
    if opcode == CRYPT_INIT then
        cmn.add_le(tree, pf_bytes, packet.xor_key_buffer(data), "XOR key",
                   isencrypted)
    end
    -- TODO
end

local function decode_client_data(tree, opcode, data, isencrypted)
    if opcode == PROTOCOL_VERSION then
        cmn.add_le(tree, pf_uint32, data(0, 4), "Protocol version", isencrypted)
    end
    -- TODO
end

function lineage2game.dissector(buffer, pinfo, tree)
    pinfo.cols.protocol = lineage2game.name
    -- TODO check pinfo.visited
    -- TODO check pinfo.conversation
    -- TODO if pinfo.visited then return end

    if buffer:len() == 0 then return end

    local isserver = (pinfo.src_port == GAME_PORT)
    local pf_opcode = isserver and pf_server_opcode or pf_client_opcode
    local opcode_tbl = isserver and SERVER_OPCODE or CLIENT_OPCODE
    local isencrypted = is_encrypted_packet(buffer, isserver)

    if not xor_key_cache[pinfo.number] then
        xor_key_cache[pinfo.number] =
            isserver and server_xor_key or client_xor_key
    end
    local xor_key = xor_key_cache[pinfo.number]

    local subtree = tree:add(lineage2game, buffer(), "Lineage2 Game Protocol")
    cmn.add_le(subtree, pf_uint16, packet.length_buffer(buffer), "Length", false)

    local opcode_p = nil
    local data_p = nil
    if isencrypted then
        local dec = xor.decrypt(packet.encrypted_block(buffer), xor_key)
        -- TODO only not in cache (flag)
        if isserver then
            server_xor_key = xor.next_key(xor_key, #dec)
        else
            client_xor_key = xor.next_key(xor_key, #dec)
        end

        local dec_tvb = ByteArray.tvb(ByteArray.new(dec, true), "Decrypted")

        opcode_p = dec_tvb(0, 1)
        data_p = dec_tvb(1)
    else
        opcode_p = packet.opcode_buffer(buffer)
        data_p = packet.data_buffer(buffer)
    end

    cmn.add_le(subtree, pf_opcode, opcode_p, nil, isencrypted)

    -- TODO show xor key in tree for debug

    local data_st = cmn.generated(tree:add(lineage2game, data_p, "Data"),
                                  isencrypted)

    local opcode = cmn.le(opcode_p)
    -- TODO move up
    if isserver and opcode == CRYPT_INIT then
        server_xor_key =
            xor.create_key(packet.xor_key(data_p), STATIC_KEY)
        client_xor_key = server_xor_key
    end
    local decode_data = isserver and decode_server_data or decode_client_data
    decode_data(data_st, opcode, data_p, isencrypted)

    cmn.set_info_field(pinfo, isserver, isencrypted, opcode_tbl[opcode])
end

local tcp_port = DissectorTable.get("tcp.port")
tcp_port:add(GAME_PORT, lineage2game)