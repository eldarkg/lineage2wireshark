--[[
    License: GPL3
    Author: Eldar Khayrullin
    Email: eldar.khayrullin@mail.ru
    Date: 2024
    Description: Wireshark Dissector for Lineage2Game
    Protocol: 709
]]--

set_plugin_info({
    version = "0.1.0",
    description = "Lineage2Game",
    author = "Eldar Khayrullin",
    repository = "https://gitlab.com/eldarkg/lineage2wireshark"
})

local cmn = require("common")
local decode = require("decode")
local packet = require("packet")
local xor = require("xor")

local DEFAULT_GAME_PORT = 7777
local DEFAULT_STATIC_XOR_KEY_HEX = "A1 6C 54 87"

local GAME_PORT = DEFAULT_GAME_PORT
local STATIC_XOR_KEY = ByteArray.new(DEFAULT_STATIC_XOR_KEY_HEX)
local START_PNUM = 0
local INIT_SERVER_XOR_KEY = ByteArray.new("00 00 00 00")
local INIT_CLIENT_XOR_KEY = ByteArray.new("00 00 00 00")

local lineage2game = Proto("lineage2game", "Lineage2 Game Protocol")
lineage2game.prefs.game_port =
    Pref.uint("Game server port", DEFAULT_GAME_PORT,
              "Default: " .. DEFAULT_GAME_PORT)
lineage2game.prefs.static_xor_key_hex =
    Pref.string("Static part of XOR key", DEFAULT_STATIC_XOR_KEY_HEX,
                "Default: " .. DEFAULT_STATIC_XOR_KEY_HEX)
lineage2game.prefs.start_pnum =
    Pref.uint("Start packet number", START_PNUM,
              "Start analyze from selected packet number")
lineage2game.prefs.init_server_xor_key_hex =
    Pref.string("Init server part of XOR key", "", "Format: 00 00 00 00")
lineage2game.prefs.init_client_xor_key_hex =
    Pref.string("Init client part of XOR key", "", "Format: 00 00 00 00")

-- TODO select protocol by preference
-- TODO select lang by preference
decode.init(lineage2game, cmn.abs_path("content/game/packets/709.ini"), "en")
local OPCODE_NAME = decode.OPCODE_NAME

-- TODO implement module cache. Methods: new, set(number, val), last, get(number)

---Init by lineage2game.init
---Last packet pinfo.number
local last_packet_number
---Last sub packet number
local last_subpacket_number
local is_last_subpacket
---Opcode stat in last packet
---Key: opcode. Value: sub packet count
local last_opcode_stat
---Key: pinfo.number. Value: sub packet count
local subpacket_count_cache

---Accumulator XOR decrypt length in current pinfo.number
local xor_accum_len
local server_xor_key
local client_xor_key
-- TODO save only dynamic part
---Key: pinfo.number. Value: XOR key
local xor_key_cache

---@param opcode integer
---@param isserver boolean
---@return string
local function opcode_str(opcode, isserver)
    return tostring(OPCODE_NAME[isserver and "server" or "client"][opcode])
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
    server_xor_key = xor.create_key(key, STATIC_XOR_KEY)
    client_xor_key = server_xor_key
end

---@param plen integer Previous decrypted data length
---@param isserver boolean
local function update_xor_key(plen, isserver)
    xor_accum_len = xor_accum_len + plen

    if isserver then
        server_xor_key = xor.next_key(server_xor_key, plen)
    else
        client_xor_key = xor.next_key(client_xor_key, plen)
    end
end

---@param opcode integer
local function update_last_opcode_stat(opcode)
    local count = last_opcode_stat[opcode]
    last_opcode_stat[opcode] = count and count + 1 or 1
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
    local isencrypted = packet.is_encrypted_game_packet(tvb, OPCODE_NAME, isserver)

    local xor_key = isencrypted and process_xor_key_cache(isserver) or nil
    if isencrypted and not xor_key then
        return tvb:len()
    end
    local payload = xor_key and xor.decrypt(packet.payload(tvb), xor_key)
                            or packet.payload(tvb)
    if isencrypted then
        update_xor_key(payload:len(), isserver)
    end

    local opcode_len = packet.opcode_len(payload, isserver)
    local opcode = packet.opcode(payload, opcode_len)
    update_last_opcode_stat(opcode)

    -- TODO only not in cache (flag). Check is isencrypted?
    if isserver and opcode_str(opcode, true) == "KeyInit" then
        init_xor_keys(packet.xor_key(packet.data(payload, opcode_len)))
    end

    local subtree = tree:add(lineage2game, tvb(),
                             tostring(last_subpacket_number) .. ". " ..
                             opcode_str(opcode, isserver))

    decode.length(subtree, packet.length_tvbr(tvb))

    if xor_key then
        decode.bytes(subtree, xor_key, "XOR key")
    end

    local payload_tvbr = isencrypted and payload:tvb("Decrypted")()
                                     or packet.payload_tvbr(tvb)

    local opcode_tvbr = packet.opcode_tvbr(payload_tvbr, opcode_len)
    if opcode_tvbr then
        decode.opcode(subtree, opcode_tvbr, isencrypted, isserver)

        -- TODO simple packet.data_tvbr, opcode_len = 1 always
        local data_tvbr = packet.data_tvbr(payload_tvbr, 1)
        if data_tvbr then
            decode.data(subtree, data_tvbr, opcode, isencrypted, isserver)
        end
    end

    if is_last_subpacket then
        cmn.set_info_field_stat(pinfo, isserver, isencrypted, last_opcode_stat,
                                opcode_str)
    end

    return tvb:len()
end

---@param tvb Tvb Packet
---@param pinfo Pinfo
---@param offset integer
local function get_len(tvb, pinfo, offset)
    local len = packet.length(tvb(offset))
    local len_tvb = tvb(offset):len()

    is_last_subpacket = not (len + packet.HEADER_LEN <= len_tvb and
        packet.length(tvb(offset + len)) <= tvb(offset + len):len())

    return len
end

function lineage2game.init()
    last_packet_number = nil
    last_subpacket_number = 0
    is_last_subpacket = false
    last_opcode_stat = {}
    subpacket_count_cache = {}

    xor_accum_len = 0
    server_xor_key = nil
    client_xor_key = nil
    xor_key_cache = {}

    server_xor_key = xor.create_key(INIT_SERVER_XOR_KEY, STATIC_XOR_KEY)
    client_xor_key = xor.create_key(INIT_CLIENT_XOR_KEY, STATIC_XOR_KEY)
end

function lineage2game.prefs_changed()
    GAME_PORT = lineage2game.prefs.game_port
    STATIC_XOR_KEY = ByteArray.new(lineage2game.prefs.static_xor_key_hex)
    START_PNUM = lineage2game.prefs.start_pnum
    INIT_SERVER_XOR_KEY =
        ByteArray.new(lineage2game.prefs.init_server_xor_key_hex)
    INIT_CLIENT_XOR_KEY =
        ByteArray.new(lineage2game.prefs.init_client_xor_key_hex)
end

---@param tvb Tvb
---@param pinfo Pinfo
---@param tree TreeItem
function lineage2game.dissector(tvb, pinfo, tree)
    if pinfo.number < START_PNUM then
        return
    end

    pinfo.cols.protocol = lineage2game.name
    pinfo.cols.info = ""

    if pinfo.number == last_packet_number then
        if subpacket_count_cache[last_packet_number] and
           subpacket_count_cache[last_packet_number] <= last_subpacket_number then
            last_subpacket_number = 0
            xor_accum_len = 0
        end
    else
        if last_packet_number and
           subpacket_count_cache[last_packet_number] == nil then
            subpacket_count_cache[last_packet_number] = last_subpacket_number
        end

        last_packet_number = pinfo.number
        last_subpacket_number = 0
        last_opcode_stat = {}
        xor_accum_len = 0
    end

    local subtree = tree:add(lineage2game, tvb(), "Lineage2 Game Protocol")
    dissect_tcp_pdus(tvb, subtree, packet.HEADER_LEN, get_len, dissect)
end

local tcp_port = DissectorTable.get("tcp.port")
tcp_port:add(GAME_PORT, lineage2game)
