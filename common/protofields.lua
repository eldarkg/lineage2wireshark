--[[
    License: GPL3
    Author: Eldar Khayrullin
    Email: eldar.khayrullin@mail.ru
    Date: 2024
    Description: Proto Fields
]]--

---Workaround: skip 1st pass without root path
if not package.searchpath("common.protofields", package.path) then
    return
end

local _M = {}

---@param name string Protocol name
---@return table
function _M.init(name)
    return {
        bytes = ProtoField.bytes(name .. ".bytes", " ", base.NONE),
        bool = ProtoField.bool(name .. ".bool", " "),
        u8 = ProtoField.uint8(name .. ".u8", " ", base.DEC),
        u16 = ProtoField.uint16(name .. ".u16", " ", base.DEC),
        r32 = ProtoField.uint32(name .. ".r32", " ", base.HEX),
        i32 = ProtoField.int32(name .. ".i32", " ", base.DEC),
        i64 = ProtoField.int64(name .. ".i64", " ", base.DEC),
        double = ProtoField.double(name .. ".double", " "),
        utf16z = ProtoField.string(name .. ".utf16z", " ", base.ASCII),
        asciiz = ProtoField.stringz(name .. ".asciiz", " ", base.ASCII),
        ipv4 = ProtoField.ipv4(name .. ".ipv4", " "),
    }
end

return _M