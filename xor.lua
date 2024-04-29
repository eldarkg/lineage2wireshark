--[[
    License: GPL3
    Author: Eldar Khayrullin
    Email: eldar.khayrullin@mail.ru
    Date: 2024
    Description: XOR crypto
    Protocol: 709
]]--

local _M = {}

---@param server_key string Server XOR key
---@param static_key string Static XOR key
---@return string
function _M.init_key(server_key, static_key)
    return server_key .. static_key
end

---@param key  string
---@param plen number Previous crypt data length
---@return string
function _M.next_key(key, plen)
    local nb = 4
    local fmt = "<I" .. tostring(nb)
    local dkey = Struct.unpack(fmt, key:sub(1, nb))
    dkey = dkey + plen
    return Struct.pack(fmt, dkey) .. key:sub(nb + 1)
end

---@param data string
---@param key  string
---@param enc  boolean
---@return string
local function crypt(data, key, enc)
    local dec = ""
    local temp = 0
    for i = 1, #data do
        local benc = data:byte(i)
        local bkey = key:byte((i - 1) % #key + 1)
        local bxor = bit32.bxor(benc, bkey, temp)
        dec = dec .. string.char(bxor)

        temp = enc and bxor or benc
    end

    return dec
end

---@param enc string
---@param key string
---@return string
function _M.decrypt(enc, key)
    return crypt(enc, key, false)
end

---@param dec string
---@param key string
---@return string
function _M.encrypt(dec, key)
    return crypt(dec, key, true)
end

return _M