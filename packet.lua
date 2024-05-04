--[[
    License: GPL3
    Author: Eldar Khayrullin
    Email: eldar.khayrullin@mail.ru
    Date: 2024
    Description: packet
]]--

local _M = {}

_M.HEADER_LEN = 2

---@param tvb Tvb
---@return Tvb
function _M.length_tvb(tvb)
    return tvb(0, _M.HEADER_LEN)
end

---@param tvb Tvb
---@return number
function _M.length(tvb)
    return _M.length_tvb(tvb):le_uint()
end

---@param tvb Tvb
---@param pinfo Pinfo
---@param offset number
function _M.get_len(tvb, pinfo, offset)
    return _M.length(tvb(offset))
end

---@param tvb Tvb
---@return Tvb
function _M.opcode_tvb(tvb)
    return tvb(2, 1)
end

---@param tvb Tvb
---@return number
function _M.opcode(tvb)
    return _M.opcode_tvb(tvb):le_uint()
end

---@param tvb Tvb
---@return Tvb
function _M.data_tvb(tvb)
    return tvb(3)
end

---@param tvb Tvb
---@return string
function _M.encrypted_block(tvb)
    return tvb(2):bytes():raw()
end

---@param data Tvb
---@return Tvb
function _M.xor_key_tvb(data)
    return data(1, 4)
end

---@param data Tvb
---@return string
function _M.xor_key(data)
    return _M.xor_key_tvb(data):bytes():raw()
end

---@param tvb Tvb
---@param isserver boolean
---@return TvbRange
function _M.decrypted_opcode_tvb(tvb, isserver)
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
    return _M.decrypted_opcode_tvb(tvb, isserver):uint()
end

return _M