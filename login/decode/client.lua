--[[
    License: GPL3
    Author: Eldar Khayrullin
    Email: eldar.khayrullin@mail.ru
    Date: 2024
    Description: Decode Login Client Packet Data
    Protocol: 785a?
]]--

---Workaround: skip 1st pass without root path
if not package.searchpath("login.decode.client", package.path) then
    return
end

local cmn = require("common")
local pf = require("login.protofield")

local CLIENT_OPCODE = require("login.opcode.client").CLIENT_OPCODE

local _M = {}

---@param tree TreeItem
---@param opcode number
---@param data TvbRange
---@param isencrypted boolean
function _M.decode_client_data(tree, opcode, data, isencrypted)
    if opcode == CLIENT_OPCODE.RequestAuthLogin then
        cmn.add_le(tree, pf.string, data(0, 14), "Login", isencrypted)
        cmn.add_le(tree, pf.string, data(14, 16), "Password", isencrypted)
    elseif opcode == CLIENT_OPCODE.RequestServerLogin then
        cmn.add_le(tree, pf.r32, data(0, 4), "Session Key 1.1", isencrypted)
        cmn.add_le(tree, pf.r32, data(4, 4), "Session Key 1.2", isencrypted)
        cmn.add_le(tree, pf.u8, data(8, 1), "Server ID", isencrypted)
    elseif opcode == CLIENT_OPCODE.RequestServerList then
        cmn.add_le(tree, pf.r32, data(0, 4), "Session Key 1.1", isencrypted)
        cmn.add_le(tree, pf.r32, data(4, 4), "Session Key 1.2", isencrypted)
    elseif opcode == CLIENT_OPCODE.RequestGGAuth then
        cmn.add_le(tree, pf.r32, data(0, 4), "Session ID", isencrypted)
    end
end

return _M