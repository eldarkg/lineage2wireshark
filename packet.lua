--[[
    License: GPL3
    Author: Eldar Khayrullin
    Email: eldar.khayrullin@mail.ru
    Date: 2024
    Description: packet
]]--

local _M = {}

---@param buffer ByteArray
---@return ByteArray
function _M.length_buffer(buffer)
    return buffer(0, 2)
end

---@param buffer ByteArray
---@return number
function _M.length(buffer)
    return _M.length_buffer(buffer):le_uint()
end

---@param buffer ByteArray
---@return ByteArray
function _M.opcode_buffer(buffer)
    return buffer(2, 1)
end

---@param buffer ByteArray
---@return number
function _M.opcode(buffer)
    return _M.opcode_buffer(buffer):le_uint()
end

---@param buffer ByteArray
---@return ByteArray
function _M.data_buffer(buffer)
    return buffer(3)
end

---@param buffer ByteArray
---@return string
function _M.encrypted_block(buffer)
    return buffer(2):bytes():raw()
end

---@param data ByteArray
---@return ByteArray
function _M.xor_key_buffer(data)
    return data(1, 4)
end

---@param data ByteArray
---@return string
function _M.xor_key(data)
    return _M.xor_key_buffer(data):bytes():raw()
end

---@param buffer TvbRange
---@param isserver boolean
---@return TvbRange
function _M.decrypted_opcode_buffer(buffer, isserver)
    local opcode1 = buffer(0, 1):uint()
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
    return buffer(0, len)
end

---@param buffer TvbRange
---@param isserver boolean
---@return number
function _M.decrypted_opcode(buffer, isserver)
    return _M.decrypted_opcode_buffer(buffer, isserver):uint()
end

return _M