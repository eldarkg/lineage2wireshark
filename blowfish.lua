--[[
    License: GPL3
    Author: Eldar Khayrullin
    Email: eldar.khayrullin@mail.ru
    Date: 2024
    Description: Blowfish ECB crypto
]]--

local crypto = require("crypto")

local _M = {}

---@param data ByteArray
---@param bs number
---@return ByteArray
local function align_size(data, bs)
    local alen = (bs - data:len() % bs) % bs
    data:set_size(data:len() + alen)
    return data
end

---@param data ByteArray
---@param bs number
---@return ByteArray
local function swap_endian(data, bs)
    local swapped = ByteArray.new()
    swapped:set_size(data:len())

    for i = 0, data:len() - 1, bs do
        for j = i + bs - 1, i, -1 do
            local b = (j < data:len()) and data:get_index(j) or 0
            swapped:set_index(2 * i + bs - 1 - j, b)
        end
    end

    return swapped
end

---@param enc ByteArray
---@param pk string
---@return ByteArray
function _M.decrypt(enc, pk)
    local bf_bs = 8
    enc = align_size(enc, bf_bs)

    local bs = 4
    local enc_be = swap_endian(enc, bs)

    local cipher = crypto.decrypt.new("bf-ecb", pk)
    local dec_be_raw = cipher:update(enc_be:raw())
    local dec_be_next_raw = cipher:final() and cipher:final() or ""
    local dec_be = ByteArray.new(dec_be_raw .. dec_be_next_raw, true)

    -- FIXME not work?
    -- local dec_be = ByteArray.new(crypto.decrypt("bf-ecb", enc_be:raw(), pk), true)

    local dec = swap_endian(dec_be, bs)
    return dec
end

return _M