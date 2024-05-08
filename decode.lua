--[[
    License: GPL3
    Author: Eldar Khayrullin
    Email: eldar.khayrullin@mail.ru
    Date: 2024
    Description: Decode data
]]--

---Workaround: skip 1st pass without root path
if not package.searchpath("decode", package.path) then
    return
end

local data = require("data")

local _M = {}

---@param path string
function _M.load(path)
    data.load(path)
    _M.OPCODE_NAME = {}
    _M.OPCODE_FMT = {}
    _M.OPCODE_NAME.SERVER, _M.OPCODE_FMT.SERVER = data.opcode_name_format(true)
    _M.OPCODE_NAME.CLIENT, _M.OPCODE_FMT.CLIENT = data.opcode_name_format(false)
end

---@param opcode number
---@param isserver boolean
function _M.decode(opcode, isserver)

end

return _M