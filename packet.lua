--[[
    License: GPL3
    Author: Eldar Khayrullin
    Email: eldar.khayrullin@mail.ru
    Date: 2024
    Description: Packet
]]--

local LOGIN_SERVER_OPCODE = require("login.opcode.server").SERVER_OPCODE
local GAME_SERVER_OPCODE = require("game.opcode.server").SERVER_OPCODE
local GAME_CLIENT_OPCODE = require("game.opcode.client").CLIENT_OPCODE

local _M = {}

_M.HEADER_LEN = 2

local LENGTH_LEN = _M.HEADER_LEN
local XOR_KEY_LEN = 4

local LENGTH_OFFSET = 0

local OPCODE_PAYLOAD_OFFSET = 0

local XOR_KEY_DATA_OFFSET = 1

---@param tvb Tvb Packet
---@return TvbRange
function _M.length_tvbr(tvb)
    return tvb(LENGTH_OFFSET, LENGTH_LEN)
end

---@param tvb Tvb Packet
---@return number
function _M.length(tvb)
    return _M.length_tvbr(tvb):le_uint()
end

---@param tvb Tvb Packet
---@param pinfo Pinfo
---@param offset number
function _M.get_len(tvb, pinfo, offset)
    return _M.length(tvb(offset))
end

---@param tvb Tvb Packet
---@return TvbRange payload Packet payload without header length
function _M.payload_tvbr(tvb)
    return tvb(_M.HEADER_LEN)
end

---@param tvb Tvb Packet
---@return ByteArray payload Packet payload without header length
function _M.payload(tvb)
    return _M.payload_tvbr(tvb):bytes()
end

---@param payload ByteArray Payload
---@param isserver boolean
---@return number
function _M.opcode_len(payload, isserver)
    local len = 1
    local opcode1 = payload:uint(OPCODE_PAYLOAD_OFFSET, len)
    -- TODO generate extended opcode1 list from *_OPCODE table
    if isserver then
        if opcode1 == 0xFE then
            len = 2
        end
    elseif opcode1 == 0x39 or opcode1 == 0xD0 then
        len = 2
    end
    return len
end

---@param tvbr TvbRange Payload
---@param op_len number Opcode length
---@return TvbRange
function _M.opcode_tvbr(tvbr, op_len)
    return tvbr:range(OPCODE_PAYLOAD_OFFSET, op_len)
end

---@param payload ByteArray Payload
---@param op_len number Opcode length
---@return number
function _M.opcode(payload, op_len)
    return payload:uint(OPCODE_PAYLOAD_OFFSET, op_len)
end

---@param tvbr TvbRange Payload
---@param op_len number Opcode length
---@return TvbRange
function _M.data_tvbr(tvbr, op_len)
    return op_len < tvbr:len() and tvbr:range(op_len) or nil
end

---@param payload ByteArray Payload
---@param op_len number Opcode length
---@return ByteArray
function _M.data(payload, op_len)
    return op_len < payload:len()
            and payload:subset(op_len, payload:len() - op_len)
            or ByteArray.new()
end

---@param data Tvb Data
---@return TvbRange
function _M.xor_key_tvbr(data)
    return data(XOR_KEY_DATA_OFFSET, XOR_KEY_LEN)
end

---@param data ByteArray Data
---@return ByteArray
function _M.xor_key(data)
    return data:subset(XOR_KEY_DATA_OFFSET, XOR_KEY_LEN)
end

---@param tvb Tvb Packet
---@param isserver boolean
---@return boolean
function _M.is_encrypted_login_packet(tvb, isserver)
    if isserver then
        local len = _M.length(tvb)
        local payload = _M.payload_tvbr(tvb):bytes()
        local opcode = _M.opcode(payload, _M.opcode_len(payload, isserver))
        return not (len == 11 and opcode == LOGIN_SERVER_OPCODE.Init)
    else
        return true
    end
end

---@param tvb Tvb Packet
---@param isserver boolean
---@return boolean
function _M.is_encrypted_game_packet(tvb, isserver)
    local len = _M.length(tvb)
    local payload = _M.payload_tvbr(tvb):bytes()
    local opcode = _M.opcode(payload, _M.opcode_len(payload, isserver))
    if isserver then
        return not (len == 16 and opcode == GAME_SERVER_OPCODE.KeyInit)
    else
        return not (len == 263 and opcode == GAME_CLIENT_OPCODE.ProtocolVersion)
    end
end

return _M