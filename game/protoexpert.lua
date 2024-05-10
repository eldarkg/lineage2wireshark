--[[
    License: GPL3
    Author: Eldar Khayrullin
    Email: eldar.khayrullin@mail.ru
    Date: 2024
    Description: Game Proto Experts
]]--

---Workaround: skip 1st pass without root path
if not package.searchpath("game.protoexpert", package.path) then
    return
end

local _M = {}

_M.undecoded = ProtoExpert.new("undecoded", "Decode error",
                               expert.group.UNDECODED, expert.severity.ERROR)
_M.unk_opcode = ProtoExpert.new("unknown_opcode", "Unknown Opcode",
                                expert.group.UNDECODED, expert.severity.ERROR)

return _M