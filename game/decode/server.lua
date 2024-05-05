--[[
    License: GPL3
    Author: Eldar Khayrullin
    Email: eldar.khayrullin@mail.ru
    Date: 2024
    Description: Decode Game Server Packet Data
    Protocol: 709?
]]--

---Workaround: skip 1st pass without root path
if not package.searchpath("game.decode.server", package.path) then
    return
end

local cmn = require("common")
local packet = require("packet")
local pf = require("game.protofield")

local SERVER_OPCODE = require("game.opcode.server").SERVER_OPCODE

local _M = {}

---@param tree        TreeItem
---@param opcode      number
---@param data        TvbRange
---@param isencrypted boolean
function _M.decode_server_data(tree, opcode, data, isencrypted)
    if opcode == SERVER_OPCODE.KeyInit then
        cmn.add_le(tree, pf.bytes, packet.xor_key_tvbr(data), "XOR key",
                   isencrypted)
    end
    -- TODO
end

return _M