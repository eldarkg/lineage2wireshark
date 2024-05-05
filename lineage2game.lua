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

    local opcode_tvbr
    local data_tvbr
    if isencrypted then
        if not xor_key then
            return tvb:len()
        end

        local dec_payload = xor.decrypt(packet.payload(tvb), xor_key)
        -- TODO move down
        local dec_payload_tvb = ByteArray.tvb(dec_payload, "Decrypted")

        opcode_tvbr = packet.opcode_tvbr(dec_payload_tvb(), isserver)
        data_tvbr = dec_payload_tvb(opcode_tvbr:len())
    else
        opcode_tvbr = packet.opcode_tvbr(packet.payload_tvbr(tvb), isserver)
        data_tvbr = packet.data_tvbr(tvb)
    end

    local opcode = cmn.be(opcode_tvbr)
    update_last_opcode_stat(opcode)

    -- TODO only not in cache (flag). Check is isencrypted?
    if isserver and opcode == SERVER_OPCODE.KeyInit then
        init_xor_keys(packet.xor_key(data_tvbr:bytes()))
    end

    -- TODO before Decrypted in representation
    local subtree = tree:add(lineage2game, tvb(),
                             tostring(last_subpacket_number) .. ". " ..
                             opcode_str(opcode, isserver))
    cmn.add_le(subtree, pf.uint16, packet.length_tvbr(tvb), "Length", false)
    if isencrypted then
        local label = "XOR key"
        -- TODO make hidden
        local xor_key_tvb = xor_key:tvb(label)
        cmn.add_le(subtree, pf.bytes, xor_key_tvb(), label, isencrypted)
    end

    local pf_opcode = isserver and pf.server_opcode or pf.client_opcode
    cmn.add_be(subtree, pf_opcode, opcode_tvbr, nil, isencrypted)

    -- TODO move dec_tvb here
    local data_st = cmn.generated(subtree:add(lineage2game, data_tvbr, "Data"),
                                  isencrypted)
    -- TODO decode_data call server or client by isserver
    local decode_data = isserver and decode_server_data or decode_client_data
    decode_data(data_st, opcode, data_tvbr, isencrypted)

    if isencrypted then
        update_xor_key(packet.payload(tvb):len(), isserver)
    end

    if is_last_subpacket() then
        cmn.set_info_field_stat(pinfo, isserver, isencrypted, last_opcode_stat,
                                opcode_str)
    end

    return tvb:len()
end

function lineage2game.init()
    last_packet_number = nil
    xor_accum_len = 0

    last_subpacket_number = 0
    packet_count_cache = {}

    server_xor_key = nil
    client_xor_key = nil
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