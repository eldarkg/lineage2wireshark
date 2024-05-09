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
-- TODO set from load
local pf = require("game.protofield")

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
    local data_fmt = OPCODE_FMT[isserver and "server" or "client"][opcode]
    local offset = 0
    for index, field_fmt in ipairs(data_fmt) do
        -- local len = 0 -- FIXME TEST
        local f
        local len
        local val
        local typ = field_fmt.type
        if typ == "b" then
            -- TODO check (bitmap)
            f = pf.bytes
            len = -1
        elseif typ == "c" then
            -- TODO sign?
            f = pf.uint8
            len = 1
        elseif typ == "d" then
            -- TODO sign?
            f = pf.uint32
            len = 4
        elseif typ == "f" then
            f = pf.double
            len = 8
        elseif typ == "h" then
            -- TODO sign?
            f = pf.uint16
            len = 2
        elseif typ == "q" then
            -- TODO check
            f = pf.bytes
            len = 4
        elseif typ == "s" then
            f = pf.string
            val, len = data(offset):le_ustringz()
        elseif typ == "z" then
            f = pf.bytes
            -- TODO check
            len = -1 -- TODO take remains len
        elseif typ == "-" then
            -- TODO check (script)
            print("-")
            f = pf.string
            len = -1
        else
            break -- TODO error
        end

        -- TODO select endian
        local item = val and tree:add_le(f, data(offset, len), val)
                         or tree:add_le(f, data(offset, len))
        item:prepend_text(field_fmt.name)
        if isencrypted then
            item:set_generated()
        end

        offset = offset + len
    end
end

return _M