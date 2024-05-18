--[[
    License: GPL3
    Author: Eldar Khayrullin
    Email: eldar.khayrullin@mail.ru
    Date: 2024
    Description: Login Client Opcodes
    Protocol: 785a?
]]--

---Workaround: skip 1st pass without root path
if not package.searchpath("common.utils", package.path) then
    return
end

local cmn = require("common.utils")

local _M = {}

_M.CLIENT_OPCODE = {
    RequestAuthLogin = 0x00,
    RequestServerLogin = 0x02,
    RequestServerList = 0x05,
    RequestGGAuth = 0x07,
}

_M.CLIENT_OPCODE_TXT = cmn.invert(_M.CLIENT_OPCODE)

return _M