--[[
    License: GPL3
    Author: Eldar Khayrullin
    Email: eldar.khayrullin@mail.ru
    Date: 2024
    Description: Game Proto Fields
]]--

---Workaround: skip 1st pass without root path
if not package.searchpath("game.protofield", package.path) then
    return
end

local _M = {}

_M.bytes = ProtoField.bytes("lineage2game.bytes", " ", base.NONE)
_M.bool = ProtoField.bool("lineage2game.bool", " ")
_M.u8 = ProtoField.uint8("lineage2game.u8", " ", base.DEC)
_M.u16 = ProtoField.uint16("lineage2game.u16", " ", base.DEC)
_M.r32 = ProtoField.uint32("lineage2game.r32", " ", base.HEX)
_M.i32 = ProtoField.int32("lineage2game.i32", " ", base.DEC)
_M.i64 = ProtoField.int64("lineage2game.i64", " ", base.DEC)
_M.double = ProtoField.double("lineage2game.double", " ")
_M.string = ProtoField.string("lineage2game.string", " ", base.ASCII)
_M.stringz = ProtoField.stringz("lineage2game.stringz", " ", base.ASCII)
_M.ipv4 = ProtoField.ipv4("lineage2game.ipv4", " ")

---@return table
function _M.init()
    return {
        _M.bytes,
        _M.u8,
        _M.u16,
        _M.i32,
        _M.r32,
        _M.i64,
        _M.double,
        _M.string,
    }
end

return _M