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

return _M