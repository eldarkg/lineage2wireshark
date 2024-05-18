--[[
    License: GPL3
    Author: Eldar Khayrullin
    Email: eldar.khayrullin@mail.ru
    Date: 2024
    Description: XOR crypto
    Protocol: 709
]]--

local _M = {}

local DYNAMIC_KEY_LEN = 4

---@param server_key ByteArray Server XOR key
---@param static_key ByteArray Static XOR key
---@return ByteArray
function _M.create_key(server_key, static_key)
    return server_key .. static_key
end

---@param key ByteArray
---@param plen integer Previous crypt data length
---@return ByteArray
function _M.next_key(key, plen)
    local dkey = key:le_uint(0, DYNAMIC_KEY_LEN)
    dkey = dkey + plen
    local fmt = "<I" .. tostring(DYNAMIC_KEY_LEN)
    local dkey_b = ByteArray.new(Struct.pack(fmt, dkey), true)
    return dkey_b .. key(DYNAMIC_KEY_LEN, key:len() - DYNAMIC_KEY_LEN)
end

---@param data ByteArray
---@param key ByteArray
---@param isenc boolean
---@return ByteArray
local function crypt(data, key, isenc)
    local dec = ByteArray.new()
    dec:set_size(data:len())

    local btmp = 0
    for i = 0, data:len() - 1 do
        local benc = data:get_index(i)
        local bkey = key:get_index(i % key:len())
        local bxor = bit32.bxor(benc, bkey, btmp)
        dec:set_index(i, bxor)

        btmp = isenc and bxor or benc
    end

    return dec
end

---@param enc ByteArray
---@param key ByteArray
---@return ByteArray
function _M.decrypt(enc, key)
    return crypt(enc, key, false)
end

---@param dec ByteArray
---@param key ByteArray
---@return ByteArray
function _M.encrypt(dec, key)
    return crypt(dec, key, true)
end

return _M