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

local SERVER_OPCODE_TXT = require("game.opcode.server").SERVER_OPCODE_TXT
local CLIENT_OPCODE_TXT = require("game.opcode.client").CLIENT_OPCODE_TXT

local _M = {}

_M.bytes = ProtoField.bytes("lineage2game.bytes", " ", base.NONE)
_M.bool = ProtoField.bool("lineage2game.bool", " ")
_M.uint8 = ProtoField.uint8("lineage2game.uint8", " ", base.DEC)
_M.uint16 = ProtoField.uint16("lineage2game.uint16", " ", base.DEC)
_M.uint32 = ProtoField.uint32("lineage2game.uint32", " ", base.DEC)
_M.bin32 = ProtoField.uint32("lineage2game.bin32", " ", base.HEX)
_M.string = ProtoField.string("lineage2game.string", " ", base.ASCII)
_M.stringz = ProtoField.stringz("lineage2game.stringz", " ", base.ASCII)
_M.ipv4 = ProtoField.ipv4("lineage2game.ipv4", " ")
_M.server_opcode = ProtoField.uint8("lineage2game.server_opcode", "Opcode",
                                    base.HEX, SERVER_OPCODE_TXT)
_M.client_opcode = ProtoField.uint8("lineage2game.client_opcode", "Opcode",
                                    base.HEX, CLIENT_OPCODE_TXT)

return _M