--[[
    License: GPL3
    Author: Eldar Khayrullin
    Email: eldar.khayrullin@mail.ru
    Date: 2024
    Description: packet
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

---@param tvb Tvb packet
---@return TvbRange
function _M.length_tvbr(tvb)
    return tvb(LENGTH_OFFSET, LENGTH_LEN)
end

---@param tvb Tvb packet
---@return number
function _M.length(tvb)
    return _M.length_tvbr(tvb):le_uint()
end

---@param tvb Tvb packet
---@param pinfo Pinfo
---@param offset number
function _M.get_len(tvb, pinfo, offset)
    return _M.length(tvb(offset))
end

---@param tvb Tvb packet
---@return TvbRange payload packet payload without header length
function _M.payload_tvbr(tvb)
    return tvb(_M.HEADER_LEN)
end

---@param tvb Tvb packet
---@return string payload packet payload without header length
function _M.payload(tvb)
    return _M.payload_tvbr(tvb):raw()
end

---@param tvbr TvbRange payload
---@param isserver boolean
---@return TvbRange
function _M.opcode_tvbr(tvbr, isserver)
    local len = 1
    local opcode1 = tvbr:range(OPCODE_PAYLOAD_OFFSET, len):uint()
    -- TODO generate extended opcode1 list from *_OPCODE table
    if isserver then
        if opcode1 == 0xFE then
            len = 2
        end
    elseif opcode1 == 0x39 or opcode1 == 0xD0 then
        len = 2
    end
    return tvbr:range(OPCODE_PAYLOAD_OFFSET, len)
end

-- TODO use ByteArray
---@param tvbr TvbRange payload
---@param isserver boolean
---@return number
function _M.opcode(tvbr, isserver)
    return _M.opcode_tvbr(tvbr, isserver):uint()
end

-- FIXME process long opcodes
---@param tvb Tvb
---@return TvbRange
function _M.data_tvbr(tvb)
    return tvb(3)
end

---@param data Tvb
---@return TvbRange
function _M.xor_key_tvbr(data)
    return data(XOR_KEY_DATA_OFFSET, XOR_KEY_LEN)
end

---@param data ByteArray
---@return string
function _M.xor_key(data)
    return data:raw(XOR_KEY_DATA_OFFSET, XOR_KEY_LEN)
end

---@param tvb Tvb packet
---@param isserver boolean
---@return boolean
function _M.is_encrypted_login_packet(tvb, isserver)
    if isserver then
        local len = _M.length(tvb)
        local opcode = _M.opcode(_M.payload_tvbr(tvb), isserver)
        return not (len == 11 and opcode == LOGIN_SERVER_OPCODE.Init)
    else
        return true
    end
end

---@param tvb Tvb packet
---@param isserver boolean
---@return boolean
function _M.is_encrypted_game_packet(tvb, isserver)
    local len = _M.length(tvb)
    local opcode = _M.opcode(_M.payload_tvbr(tvb), isserver)
    -- TODO check current *_xor_key for empty
    if isserver then
        return not (len == 16 and opcode == GAME_SERVER_OPCODE.KeyInit)
    else
        return not (len == 263 and opcode == GAME_CLIENT_OPCODE.ProtocolVersion)
    end
end

return _M