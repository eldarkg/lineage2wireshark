--[[
    License: GPL3
    Author: Eldar Khayrullin
    Email: eldar.khayrullin@mail.ru
    Date: 2024
    Description: Decode Game Client Packet Data
    Protocol: 709?
]]--

---Workaround: skip 1st pass without root path
if not package.searchpath("game.decode.client", package.path) then
    return
end

local cmn = require("common")
local pf = require("game.protofield")

local CLIENT_OPCODE = require("game.opcode.client").CLIENT_OPCODE

local _M = {}

---@param tree        TreeItem
---@param opcode      number
---@param data        Tvb
---@param isencrypted boolean
function _M.decode_client_data(tree, opcode, data, isencrypted)
    if opcode == CLIENT_OPCODE.ProtocolVersion then
        cmn.add_le(tree, pf.uint32, data(0, 4), "Protocol version", isencrypted)
    end
    -- TODO
end

return _M