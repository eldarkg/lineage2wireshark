--[[
    License: GPL3
    Author: Eldar Khayrullin
    Email: eldar.khayrullin@mail.ru
    Date: 2024
    Description: Blowfish ECB crypto
]]--

local crypto = require("crypto")

local _M = {}

local function align_size(data, bs)
    local alen = (bs - #data % bs) % bs
    for i = 1, alen do
        data = data .. "\x00"
    end

    return data
end

local function swap_endian(data, bs)
    local swapped = ""
    for i = 1, #data, bs do
        for j = i + bs - 1, i, -1 do
            local b = (j <= #data) and string.char(data:byte(j)) or "\x00"
            swapped = swapped .. b
        end
    end

    return swapped
end

function _M.decrypt(enc, pk)
    local bf_bs = 8
    enc = align_size(enc, bf_bs)

    local bs = 4
    local enc_be = swap_endian(enc, bs)

    local cipher =
        crypto.decrypt.new("bf-ecb", pk)

    local dec_be = cipher:update(enc_be)
    local dec_be_next = cipher:final()
    dec_be = dec_be .. (dec_be_next and dec_be_next or "")

    -- FIXME not work?
    -- local dec_be = crypto.decrypt("bf-ecb", enc_be, pk)

    local dec = swap_endian(dec_be, bs)
    return dec
end

return _M