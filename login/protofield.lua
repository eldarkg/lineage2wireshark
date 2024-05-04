--[[
    License: GPL3
    Author: Eldar Khayrullin
    Email: eldar.khayrullin@mail.ru
    Date: 2024
    Description: Login Proto Fields
    Protocol: 785a
]]--

---Workaround: skip 1st pass without root path
if not package.searchpath("login.protofield", package.path) then
    return
end

local msg = require("login.message.server")

local SERVER_OPCODE_TXT = require("login.opcode.server").SERVER_OPCODE_TXT
local CLIENT_OPCODE_TXT = require("login.opcode.client").CLIENT_OPCODE_TXT

local _M = {}

_M.bytes = ProtoField.bytes("lineage2game.bytes", " ", base.NONE)
_M.bool = ProtoField.bool("lineage2login.bool", " ")
_M.uint8 = ProtoField.uint8("lineage2login.uint8", " ", base.DEC)
_M.uint16 = ProtoField.uint16("lineage2login.uint16", " ", base.DEC)
_M.uint32 = ProtoField.uint32("lineage2login.uint32", " ", base.DEC)
_M.bin32 = ProtoField.uint32("lineage2login.bin32", " ", base.HEX)
_M.string = ProtoField.string("lineage2login.string", " ", base.ASCII)
_M.ipv4 = ProtoField.ipv4("lineage2login.ipv4", " ")

_M.server_opcode = ProtoField.uint8("lineage2login.server_opcode",
                                    "Opcode", base.HEX, SERVER_OPCODE_TXT)
_M.client_opcode = ProtoField.uint8("lineage2login.client_opcode",
                                    "Opcode", base.HEX, CLIENT_OPCODE_TXT)

_M.login_fail_reason = ProtoField.uint32("lineage2login.login_fail_reason",
                                         "Reason", base.HEX,
                                         msg.LOGIN_FAIL_REASON)
_M.account_kicked_reason = ProtoField.uint32("lineage2login.account_kicked_reason",
                                             "Reason", base.HEX,
                                             msg.ACCOUNT_KICKED_REASON)
_M.play_fail_reason = ProtoField.uint32("lineage2login.play_fail_reason",
                                        "Reason", base.HEX,
                                        msg.PLAY_FAIL_REASON)
_M.gg_auth_response = ProtoField.uint32("lineage2login.gg_auth_response",
                                        "Response", base.HEX,
                                        msg.GG_AUTH_RESPONSE)

return _M