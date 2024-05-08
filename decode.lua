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
local OPCODE_FMT = {}

---@param path string
function _M.load(path)
    data.load(path)
    _M.OPCODE_NAME = {}
    _M.OPCODE_NAME.server, OPCODE_FMT.server = data.opcode_name_format(true)
    _M.OPCODE_NAME.client, OPCODE_FMT.client = data.opcode_name_format(false)
end

---@param tree TreeItem
---@param data TvbRange
---@param opcode number
---@param isencrypted boolean
---@param isserver boolean
function _M.decode(tree, data, opcode, isencrypted, isserver)
    -- local field = OPCODE_FMT.
end

return _M