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

local SERVER_OPCODE = require("game.opcode.server")
local CLIENT_OPCODE = require("game.opcode.client")

local SERVER_OPCODE_TXT = cmn.invert(SERVER_OPCODE)
local CLIENT_OPCODE_TXT = cmn.invert(CLIENT_OPCODE)

-- TODO move to protocol preferences
local GAME_PORT = 7777
local STATIC_XOR_KEY = "\xA1\x6C\x54\x87"
-- TODO preferences: offset, init key (while not found init)

-- TODO set protocol info

local f_bytes = ProtoField.bytes("lineage2game.bytes", " ", base.NONE)
local f_bool = ProtoField.bool("lineage2game.bool", " ")
local f_uint8 = ProtoField.uint8("lineage2game.uint8", " ", base.DEC)
local f_uint16 = ProtoField.uint16("lineage2game.uint16", " ", base.DEC)
local f_uint32 = ProtoField.uint32("lineage2game.uint32", " ", base.DEC)
local f_bin32 = ProtoField.uint32("lineage2game.bin32", " ", base.HEX)
local f_string = ProtoField.string("lineage2game.string", " ", base.ASCII)
local f_stringz = ProtoField.stringz("lineage2game.stringz", " ", base.ASCII)
local f_ipv4 = ProtoField.ipv4("lineage2game.ipv4", " ")
local f_server_opcode = ProtoField.uint8("lineage2game.server_opcode",
                                         "Opcode", base.HEX, SERVER_OPCODE_TXT)
local f_client_opcode = ProtoField.uint8("lineage2game.client_opcode",
                                         "Opcode", base.HEX, CLIENT_OPCODE_TXT)

local lineage2game = Proto("lineage2game", "Lineage2 Game Protocol")
lineage2game.fields = {
    f_bytes,
    f_uint16,
    f_uint32,
    f_server_opcode,
    f_client_opcode,
}

-- TODO implement module cache. Methods: new, set(number, val), last, get(number)

---Init by lineage2game.init
---Last packet pinfo.number
local last_packet_number
---Accumulator XOR decrypt length in current pinfo.number
local xor_accum_len

---Last sub packet number
local last_subpacket_number
---Key: pinfo.number. Value: sub packet count
local packet_count_cache

local server_xor_key
local client_xor_key
-- TODO save only dynamic part
---Key: pinfo.number. Value: XOR key
local xor_key_cache

---Opcode stat in last packet
---Key: opcode. Value: sub packet count
local last_opcode_stat

---@param tvb Tvb
---@param isserver boolean
---@return boolean
local function is_encrypted_packet(tvb, isserver)
    local len = packet.length(tvb)
    local opcode = packet.opcode(tvb)
    -- TODO check current *_xor_key for empty
    if isserver then
        return not (len == 16 and opcode == SERVER_OPCODE.KeyInit)
    else
        return not (len == 263 and opcode == CLIENT_OPCODE.ProtocolVersion)
    end
end

---@param tree        TreeItem
---@param opcode      number
---@param data        Tvb
---@param isencrypted boolean
local function decode_server_data(tree, opcode, data, isencrypted)
    if opcode == SERVER_OPCODE.KeyInit then
        cmn.add_le(tree, f_bytes, packet.xor_key_tvb(data), "XOR key",
                   isencrypted)
    end
    -- TODO
end

---@param tree        TreeItem
---@param opcode      number
---@param data        Tvb
---@param isencrypted boolean
local function decode_client_data(tree, opcode, data, isencrypted)
    if opcode == CLIENT_OPCODE.ProtocolVersion then
        cmn.add_le(tree, f_uint32, data(0, 4), "Protocol version", isencrypted)
    end
    -- TODO
end

---@param opcode number
---@param isserver boolean
---@return string
local function opcode_str(opcode, isserver)
    local str = isserver and SERVER_OPCODE_TXT[opcode] or CLIENT_OPCODE_TXT[opcode]
    return str and str or ""
end

---@param isserver boolean
local function process_xor_key_cache(isserver)
    local pnum = last_packet_number
    if xor_key_cache[pnum] then
        local xor_key = xor.next_key(xor_key_cache[pnum], xor_accum_len)
        if isserver then
            server_xor_key = xor_key
        else
            client_xor_key = xor_key
        end
    else
        xor_key_cache[pnum] = isserver and server_xor_key or client_xor_key
    end
end

---@param key string Server XOR key
local function init_xor_key(key)
    server_xor_key = xor.create_key(key, STATIC_XOR_KEY)
    client_xor_key = server_xor_key
end

---@param plen number Previous decrypted data length
---@param isserver boolean
local function update_xor_key(plen, isserver)
    xor_accum_len = xor_accum_len + plen

    if isserver then
        server_xor_key = xor.next_key(server_xor_key, plen)
    else
        client_xor_key = xor.next_key(client_xor_key, plen)
    end
end

---@param opcode number
local function update_last_opcode_stat(opcode)
    local count = last_opcode_stat[opcode]
    last_opcode_stat[opcode] = count and count + 1 or 1
end

---@return boolean false on 1 dissection pass
local function is_last_subpacket()
    return packet_count_cache[last_packet_number] and
           last_subpacket_number == packet_count_cache[last_packet_number]
end

---@param tvb Tvb
---@param pinfo Pinfo
---@param tree TreeItem
local function dissect(tvb, pinfo, tree)
    if tvb:len() == 0 then
        return 0
    end

    last_subpacket_number = last_subpacket_number + 1

    local isserver = (pinfo.src_port == GAME_PORT)
    local isencrypted = is_encrypted_packet(tvb, isserver)
    -- TODO check isencrypted and *_xor_key is empty then not process. Ret false. Print no XOR key

    if isencrypted then
        process_xor_key_cache(isserver)
    end

    local xor_key = isserver and server_xor_key or client_xor_key

    local opcode_tvb = nil
    local data_tvb = nil
    if isencrypted then
        -- TODO empty encrypted_block ?
        local dec = xor.decrypt(packet.encrypted_block(tvb), xor_key)
        -- TODO move down
        -- TODO show [Opcode name] instead Decrypted
        local dec_tvb = ByteArray.tvb(ByteArray.new(dec, true), "Decrypted")

        opcode_tvb = packet.decrypted_opcode_tvb(dec_tvb(), isserver)
        data_tvb = dec_tvb(opcode_tvb:len())
    else
        opcode_tvb = packet.opcode_tvb(tvb)
        data_tvb = packet.data_tvb(tvb)
    end

    local opcode = cmn.be(opcode_tvb)
    update_last_opcode_stat(opcode)

    -- TODO only not in cache (flag). Check is isencrypted?
    if isserver and opcode == SERVER_OPCODE.KeyInit then
        init_xor_key(packet.xor_key(data_tvb))
    end

    -- TODO before Decrypted in representation
    local subtree = tree:add(lineage2game, tvb(),
                             tostring(last_subpacket_number) .. ". " ..
                             opcode_str(opcode, isserver))
    cmn.add_le(subtree, f_uint16, packet.length_tvb(tvb), "Length", false)
    if isencrypted then
        local label = "XOR key"
        -- TODO make hidden
        local xor_key_tvb = ByteArray.tvb(ByteArray.new(xor_key, true), label)
        cmn.add_le(subtree, f_bytes, xor_key_tvb(), label, isencrypted)
    end

    local f_opcode = isserver and f_server_opcode or f_client_opcode
    cmn.add_be(subtree, f_opcode, opcode_tvb, nil, isencrypted)

    -- TODO move dec_tvb here
    local data_st = cmn.generated(subtree:add(lineage2game, data_tvb, "Data"),
                                  isencrypted)
    -- TODO decode_data call server or client by isserver
    local decode_data = isserver and decode_server_data or decode_client_data
    decode_data(data_st, opcode, data_tvb, isencrypted)

    if isencrypted then
        update_xor_key(packet.encrypted_block(tvb):len(), isserver)
    end

    if is_last_subpacket() then
        -- TODO move to common
        local str = ""
        for op, count in pairs(last_opcode_stat) do
            if #str ~= 0 then
                str = str .. ", "
            end
            str = str .. opcode_str(op, isserver)
            if 1 < count then
                str = str .. "(" .. count .. ")"
            end
        end
        cmn.set_info_field(pinfo, isserver, isencrypted, str)
    end

    return tvb:len()
end

function lineage2game.init()
    last_packet_number = nil
    xor_accum_len = 0

    last_subpacket_number = 0
    packet_count_cache = {}

    server_xor_key = ""
    client_xor_key = ""
    xor_key_cache = {}

    last_opcode_stat = {}
end

---@param tvb Tvb
---@param pinfo Pinfo
---@param tree TreeItem
function lineage2game.dissector(tvb, pinfo, tree)
    pinfo.cols.protocol = lineage2game.name
    pinfo.cols.info = ""

    if pinfo.number == last_packet_number then
        if packet_count_cache[last_packet_number] and
           packet_count_cache[last_packet_number] <= last_subpacket_number then
            xor_accum_len = 0
            last_subpacket_number = 0
        end
    else
        if last_packet_number and
           packet_count_cache[last_packet_number] == nil then
            packet_count_cache[last_packet_number] = last_subpacket_number
        end

        last_packet_number = pinfo.number
        xor_accum_len = 0
        last_subpacket_number = 0
        last_opcode_stat = {}
    end

    local subtree = tree:add(lineage2game, tvb(), "Lineage2 Game Protocol")
    dissect_tcp_pdus(tvb, subtree, packet.HEADER_LEN, packet.get_len, dissect)
end

local tcp_port = DissectorTable.get("tcp.port")
tcp_port:add(GAME_PORT, lineage2game)
-- TODO use treeitem:add_tvb_expert_info