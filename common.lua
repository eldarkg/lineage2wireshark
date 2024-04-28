--[[
    License: GPL3
    Author: Eldar Khayrullin
    Email: eldar.khayrullin@mail.ru
    Date: 2024
    Description: Wireshark Dissector for "Lineage2 common"
    Protocol: 785a
]]--

local crypto = require("crypto")

local _M = {}

local BLOWFISH_PK = Struct.fromhex(
    "64 10 30 10 AE 06 31 10 16 95 30 10 32 65 30 10 71 44 30 10 00",
    " ")

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

function _M.decrypt(enc)
    local bf_bs = 8
    enc = align_size(enc, bf_bs)

    local bs = 4
    local enc_be = swap_endian(enc, bs)

    local cipher =
        crypto.decrypt.new("bf-ecb", BLOWFISH_PK)

    local dec_be = cipher:update(enc_be)
    local dec_be_next = cipher:final()
    dec_be = dec_be .. (dec_be_next and dec_be_next or "")

    -- FIXME not work?
    -- local dec_be = crypto.decrypt("bf-ecb", enc_be, BLOWFISH_PK)

    local dec = swap_endian(dec_be, bs)
    return dec
end

function _M.generated(obj, isgen)
    return isgen and obj:set_generated() or obj
end

local function add_generic(add, obj, protofield, tvbrange, label, isgen)
    obj = _M.generated(add(obj, protofield, tvbrange), isgen)
    obj = label and obj:prepend_text(label) or obj
end

function _M.add_le(obj, protofield, tvbrange, label, isgen)
    add_generic(obj.add_le, obj, protofield, tvbrange, label, isgen)
end

function _M.add_be(obj, protofield, tvbrange, label, isgen)
    add_generic(obj.add, obj, protofield, tvbrange, label, isgen)
end

function _M.set_info_field(isserver, isgen, opcode_str, pinfo)
    local src_role = isserver and "Server" or "Client"
    if not opcode_str then opcode_str = "" end
    pinfo.cols.info =
        tostring(pinfo.src_port) .. " → " .. tostring(pinfo.dst_port) ..
        " " ..  src_role .. ": " ..
        (isgen and ("[" .. opcode_str .. "]") or opcode_str)
end

return _M