--[[
    License: GPL3
    Author: Eldar Khayrullin
    Email: eldar.khayrullin@mail.ru
    Date: 2024
    Description: Decode Login Server Packet Data
    Protocol: 785a?
]]--

---Workaround: skip 1st pass without root path
if not package.searchpath("login.decode.server", package.path) then
    return
end

local cmn = require("common.utils")
local pf = require("login.protofield")

local SERVER_OPCODE = require("login.opcode.server").SERVER_OPCODE

local _M = {}

---@param tree TreeItem
---@param opcode number
---@param data TvbRange
---@param isencrypted boolean
function _M.decode_server_data(tree, opcode, data, isencrypted)
    if opcode == SERVER_OPCODE.Init then
        cmn.add_le(tree, pf.r32, data(0, 4), "Session ID", isencrypted)
        cmn.add_le(tree, pf.r32, data(4, 4), "Protocol version", isencrypted)
    elseif opcode == SERVER_OPCODE.LoginFail then
        cmn.add_le(tree, pf.login_fail_reason, data(0, 4), nil, isencrypted)
    elseif opcode == SERVER_OPCODE.AccountKicked then
        cmn.add_le(tree, pf.account_kicked_reason, data(0, 4), nil, isencrypted)
    elseif opcode == SERVER_OPCODE.LoginOk then
        cmn.add_le(tree, pf.r32, data(0, 4), "Session Key 1.1", isencrypted)
        cmn.add_le(tree, pf.r32, data(4, 4), "Session Key 1.2", isencrypted)
    elseif opcode == SERVER_OPCODE.ServerList then
        cmn.add_le(tree, pf.u8, data(0, 1), "Count", isencrypted)
        local blk_sz = 21
        for i = 0, cmn.le(data(0, 1)) - 1 do
            local b = blk_sz * i
            local serv_st = cmn.generated(tree:add(data(b + 2, blk_sz),
                                          "Server " .. (i + 1)), isencrypted)
            cmn.add_le(serv_st, pf.u8, data(b + 2, 1), "Server ID", isencrypted)
            cmn.add_be(serv_st, pf.ipv4, data(b + 3, 4), "Game Server IP", isencrypted)
            cmn.add_le(serv_st, pf.i32, data(b + 7, 4), "Port", isencrypted)
            cmn.add_le(serv_st, pf.u8, data(b + 11, 1), "Age limit", isencrypted)
            cmn.add_le(serv_st, pf.bool, data(b + 12, 1), "PVP server", isencrypted)
            cmn.add_le(serv_st, pf.u16, data(b + 13, 2), "Online", isencrypted)
            cmn.add_le(serv_st, pf.u16, data(b + 15, 2), "Max", isencrypted)
            cmn.add_le(serv_st, pf.bool, data(b + 17, 1), "Test server", isencrypted)
        end
    elseif opcode == SERVER_OPCODE.PlayFail then
        cmn.add_le(tree, pf.play_fail_reason, data(0, 4), nil, isencrypted)
    elseif opcode == SERVER_OPCODE.PlayOk then
        cmn.add_le(tree, pf.r32, data(0, 4), "Session Key 2.1", isencrypted)
        cmn.add_le(tree, pf.r32, data(4, 4), "Session Key 2.2", isencrypted)
    elseif opcode == SERVER_OPCODE.GGAuth then
        cmn.add_le(tree, pf.gg_auth_response, data(0, 4), nil, isencrypted)
    end
end

return _M