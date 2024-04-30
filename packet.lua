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
---@return TvbRange
function _M.decrypted_opcode_buffer(buffer)
    local opcode1 = buffer(0, 1):uint()
    local len = (opcode1 == 0xD0 or opcode1 == 0xFE) and 2 or 1
    return buffer(0, len)
end

---@param buffer TvbRange
---@return number
function _M.decrypted_opcode(buffer)
    return _M.decrypted_opcode_buffer(buffer):uint()
end

return _M