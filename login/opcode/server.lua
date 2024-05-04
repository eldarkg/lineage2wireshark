--[[
    License: GPL3
    Author: Eldar Khayrullin
    Email: eldar.khayrullin@mail.ru
    Date: 2024
    Description: Login Server Opcodes
    Protocol: 785a?
]]--

local SERVER_OPCODE = {
    Init = 0x00,
    LoginFail = 0x01,
    AccountKicked = 0x02,
    LoginOk = 0x03,
    ServerList = 0x04,
    PlayFail = 0x06,
    PlayOk = 0x07,
    GGAuth = 0x0B,
}

return SERVER_OPCODE