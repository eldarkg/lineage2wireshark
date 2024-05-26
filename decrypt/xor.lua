--[[
    License: GPL3
    Author: Eldar Khayrullin
    Email: eldar.khayrullin@mail.ru
    Date: 2024
    Description: XOR crypto
]]--

local _M = {}

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
    local DYNAMIC_KEY_LEN = 4
    local pos
    if key:len() == 8 then
        pos = 0
    elseif key:len() == 16 then
        pos = 8
    else
        return nil
    end

    local dkey = key:le_uint(pos, DYNAMIC_KEY_LEN)
    dkey = dkey + plen
    local fmt = "<I" .. tostring(DYNAMIC_KEY_LEN)
    local dkey_b = ByteArray.new(Struct.pack(fmt, dkey), true)

    local res = dkey_b
    if pos ~= 0 then
        local pre = key(0, pos)
        res = pre .. res
    end
    local post_pos = pos + DYNAMIC_KEY_LEN
    if post_pos < key:len() then
        local post = key(post_pos, key:len() - post_pos)
        res = res .. post
    end
    return res
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