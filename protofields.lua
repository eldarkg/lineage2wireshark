--[[
    License: GPL3
    Author: Eldar Khayrullin
    Email: eldar.khayrullin@mail.ru
    Date: 2024
    Description: proto fields
]]--

local _M = {}

-- TODO clean
_M.Length = ProtoField.uint16("lineage2.Length", "Length", base.DEC)
_M.Data = ProtoField.bytes("lineage2.Data", "Data", base.NONE)
_M.Bool = ProtoField.bool("lineage2.Bool", " ")
_M.Uint8 = ProtoField.uint8("lineage2.Uint8", " ", base.DEC)
_M.Uint16 = ProtoField.uint16("lineage2.Uint16", " ", base.DEC)
_M.Uint32 = ProtoField.uint32("lineage2.Uint32", " ", base.DEC)
_M.Dword = ProtoField.uint32("lineage2.Dword", " ", base.HEX)
_M.String = ProtoField.string("lineage2.String", " ", base.ASCII)
_M.Stringz = ProtoField.stringz("lineage2.Stringz", " ", base.ASCII)
_M.IPv4 = ProtoField.ipv4("lineage2.IPv4", " ")

return _M