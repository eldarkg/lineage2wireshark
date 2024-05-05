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

---@param tvb Tvb
---@return TvbRange
function _M.length_tvbr(tvb)
    return tvb(0, _M.HEADER_LEN)
end

---@param tvb Tvb
---@return number
function _M.length(tvb)
    return _M.length_tvbr(tvb):le_uint()
end

---@param tvb Tvb
---@param pinfo Pinfo
---@param offset number
function _M.get_len(tvb, pinfo, offset)
    return _M.length(tvb(offset))
end

---@param tvb Tvb
---@return TvbRange
function _M.opcode_tvbr(tvb)
    return tvb(_M.HEADER_LEN, 1)
end

---@param tvb Tvb
---@return number
function _M.opcode(tvb)
    return _M.opcode_tvbr(tvb):le_uint()
end

-- FIXME process long opcodes
---@param tvb Tvb
---@return TvbRange
function _M.data_tvbr(tvb)
    return tvb(3)
end

---@param tvb Tvb
---@return string
function _M.encrypted_block(tvb)
    return tvb(2):bytes():raw()
end

---@param data Tvb
---@return TvbRange
function _M.xor_key_tvbr(data)
    return data(1, 4)
end

---@param data Tvb
---@return string
function _M.xor_key(data)
    return _M.xor_key_tvbr(data):bytes():raw()
end

---@param tvb Tvb
---@param isserver boolean
---@return TvbRange
function _M.decrypted_opcode_tvbr(tvb, isserver)
    local opcode1 = tvb(0, 1):uint()
    local len = 1
    -- TODO generate extended opcode1 list from *_OPCODE table
    if isserver then
        if opcode1 == 0xFE then
            len = 2
        end
    elseif opcode1 == 0x39 or opcode1 == 0xD0 then
        len = 2
    else
        len = 1 end
    return tvb(0, len)
end

---@param tvb Tvb
---@param isserver boolean
---@return number
function _M.decrypted_opcode(tvb, isserver)
    return _M.decrypted_opcode_tvbr(tvb, isserver):uint()
end

---@param tvb Tvb
---@param isserver boolean
---@return boolean
function _M.is_encrypted_login_packet(tvb, isserver)
    if isserver then
        local len = _M.length(tvb)
        local opcode = _M.opcode(tvb)
        return not (len == 11 and opcode == LOGIN_SERVER_OPCODE.Init)
    else
        return true
    end
end

---@param tvb Tvb
---@param isserver boolean
---@return boolean
function _M.is_encrypted_game_packet(tvb, isserver)
    local len = _M.length(tvb)
    local opcode = _M.opcode(tvb)
    -- TODO check current *_xor_key for empty
    if isserver then
        return not (len == 16 and opcode == GAME_SERVER_OPCODE.KeyInit)
    else
        return not (len == 263 and opcode == GAME_CLIENT_OPCODE.ProtocolVersion)
    end
end

return _M