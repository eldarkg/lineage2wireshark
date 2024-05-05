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
local pf = require("game.protofield")
local xor = require("xor")

local decode_server_data = require("game.decode.server").decode_server_data
local decode_client_data = require("game.decode.client").decode_client_data

local SERVER_OPCODE = require("game.opcode.server").SERVER_OPCODE
local SERVER_OPCODE_TXT = require("game.opcode.server").SERVER_OPCODE_TXT
local CLIENT_OPCODE_TXT = require("game.opcode.client").CLIENT_OPCODE_TXT

-- TODO move to protocol preferences
local GAME_PORT = 7777
local STATIC_XOR_KEY = "\xA1\x6C\x54\x87"
-- TODO preferences: offset, init key (while not found init)

-- TODO set protocol info

local lineage2game = Proto("lineage2game", "Lineage2 Game Protocol")
lineage2game.fields = {
    pf.bytes,
    pf.uint16,
    pf.uint32,
    pf.server_opcode,
    pf.client_opcode,
}

-- TODO implement module cache. Methods: new, set(number, val), last, get(number)

---Init by lineage2game.init
---Last packet pinfo.number
local last_packet_number
---Last sub packet number
local last_subpacket_number
---Opcode stat in last packet
---Key: opcode. Value: sub packet count
local last_opcode_stat
---Key: pinfo.number. Value: sub packet count
local packet_count_cache

---Accumulator XOR decrypt length in current pinfo.number
local xor_accum_len
local server_xor_key
local client_xor_key
-- TODO save only dynamic part
---Key: pinfo.number. Value: XOR key
local xor_key_cache

---@param opcode number
---@param isserver boolean
---@return string
local function opcode_str(opcode, isserver)
    return tostring(isserver and SERVER_OPCODE_TXT[opcode]
                             or CLIENT_OPCODE_TXT[opcode])
end

---@param isserver boolean
---@return ByteArray xor_key
local function process_xor_key_cache(isserver)
    local pnum = last_packet_number
    local xor_key
    if xor_key_cache[pnum] then
        xor_key = xor.next_key(xor_key_cache[pnum], xor_accum_len)
        if isserver then
            server_xor_key = xor_key
        else
            client_xor_key = xor_key
        end
    else
        xor_key = isserver and server_xor_key or client_xor_key
        xor_key_cache[pnum] = xor_key
    end
    return xor_key
end

---@param key ByteArray Server XOR key
local function init_xor_keys(key)
    server_xor_key = xor.create_key(key, ByteArray.new(STATIC_XOR_KEY, true))
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

---@return boolean false on 1st dissection pass
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
    local isencrypted = packet.is_encrypted_game_packet(tvb, isserver)

    local xor_key = isencrypted and process_xor_key_cache(isserver) or nil
    if isencrypted and not xor_key then
        return tvb:len()
    end
    local payload = isencrypted and xor.decrypt(packet.payload(tvb), xor_key)
                                or packet.payload(tvb)
    if isencrypted then
        update_xor_key(payload:len(), isserver)
    end

    local opcode_len = packet.opcode_len(payload, isserver)
    local opcode = packet.opcode(payload, opcode_len)
    update_last_opcode_stat(opcode)

    -- TODO only not in cache (flag). Check is isencrypted?
    if isserver and opcode == SERVER_OPCODE.KeyInit then
        init_xor_keys(packet.xor_key(packet.data(payload, opcode_len)))
    end

    local subtree = tree:add(lineage2game, tvb(),
                             tostring(last_subpacket_number) .. ". " ..
                             opcode_str(opcode, isserver))
    cmn.add_le(subtree, pf.uint16, packet.length_tvbr(tvb), "Length", false)

    if isencrypted then
        local label = "XOR key"
        -- TODO make hidden
        local xor_key_tvb = xor_key:tvb(label)
        cmn.add_le(subtree, pf.bytes, xor_key_tvb(), label, true)
    end

    local payload_tvbr = isencrypted and payload:tvb("Decrypted")()
                                     or packet.payload_tvbr(tvb)
    local opcode_tvbr = packet.opcode_tvbr(payload_tvbr, opcode_len)
    local data_tvbr = packet.data_tvbr(payload_tvbr, opcode_len)

    if opcode_tvbr then
        local pf_opcode = isserver and pf.server_opcode or pf.client_opcode
        cmn.add_be(subtree, pf_opcode, opcode_tvbr, nil, isencrypted)
    end

    if data_tvbr then
        local data_st = cmn.generated(subtree:add(lineage2game, data_tvbr, "Data"),
                                      isencrypted)
        -- TODO decode_data call server or client by isserver
        local decode_data = isserver and decode_server_data or decode_client_data
        decode_data(data_st, opcode, data_tvbr, isencrypted)
    end

    if is_last_subpacket() then
        cmn.set_info_field_stat(pinfo, isserver, isencrypted, last_opcode_stat,
                                opcode_str)
    end

    return tvb:len()
end

function lineage2game.init()
    last_packet_number = nil
    last_subpacket_number = 0
    last_opcode_stat = {}
    packet_count_cache = {}

    xor_accum_len = 0
    server_xor_key = nil
    client_xor_key = nil
    xor_key_cache = {}
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
            last_subpacket_number = 0
            xor_accum_len = 0
        end
    else
        if last_packet_number and
           packet_count_cache[last_packet_number] == nil then
            packet_count_cache[last_packet_number] = last_subpacket_number
        end

        last_packet_number = pinfo.number
        last_subpacket_number = 0
        last_opcode_stat = {}
        xor_accum_len = 0
    end

    local subtree = tree:add(lineage2game, tvb(), "Lineage2 Game Protocol")
    dissect_tcp_pdus(tvb, subtree, packet.HEADER_LEN, packet.get_len, dissect)
end

local tcp_port = DissectorTable.get("tcp.port")
tcp_port:add(GAME_PORT, lineage2game)
-- TODO use treeitem:add_tvb_expert_info
