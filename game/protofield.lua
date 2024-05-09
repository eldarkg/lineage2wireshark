--[[
    License: GPL3
    Author: Eldar Khayrullin
    Email: eldar.khayrullin@mail.ru
    Date: 2024
    Description: Game Proto Fields
    Protocol: 709?
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
_M.u32 = ProtoField.uint32("lineage2game.u32", " ", base.DEC)
_M.b32 = ProtoField.uint32("lineage2game.b32", " ", base.HEX)
_M.double = ProtoField.double("lineage2game.double", " ")
_M.string = ProtoField.string("lineage2game.string", " ", base.ASCII)
_M.stringz = ProtoField.stringz("lineage2game.stringz", " ", base.ASCII)
_M.wstring = ProtoField.string("lineage2game.wstring", " ", base.UNICODE)
_M.wstringz = ProtoField.stringz("lineage2game.wstringz", " ", base.UNICODE)
_M.ipv4 = ProtoField.ipv4("lineage2game.ipv4", " ")

---@param opcode_name table
function _M.init(opcode_name)
    _M.server_opcode = ProtoField.uint8("lineage2game.server_opcode", "Opcode",
                                        base.HEX, opcode_name.server)
    _M.client_opcode = ProtoField.uint8("lineage2game.client_opcode", "Opcode",
                                        base.HEX, opcode_name.client)
end

return _M