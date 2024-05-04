--[[
    License: GPL3
    Author: Eldar Khayrullin
    Email: eldar.khayrullin@mail.ru
    Date: 2024
    Description: Login Client Opcodes
    Protocol: 785a?
]]--

local CLIENT_OPCODE = {
    RequestAuthLogin = 0x00,
    RequestServerLogin = 0x02,
    RequestServerList = 0x05,
    RequestGGAuth = 0x07,
}

return CLIENT_OPCODE