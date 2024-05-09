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
local pf = require("game.protofield")

local _M = {}
local OPCODE_FMT = {}

---@param path string
function _M.init(path)
    data.load(path)
    _M.OPCODE_NAME = {}
    _M.OPCODE_NAME.server, OPCODE_FMT.server = data.opcode_name_format(true)
    _M.OPCODE_NAME.client, OPCODE_FMT.client = data.opcode_name_format(false)

    pf.init(_M.OPCODE_NAME)
    _M.PF = {
        pf.bytes,
        pf.u8,
        pf.u16,
        pf.u32,
        pf.double,
        pf.string,
        pf.server_opcode,
        pf.client_opcode,
    }
end

---@param tree TreeItem
---@param tvbr TvbRange Length
function _M.length(tree, tvbr)
    tree:add_le(pf.u16, tvbr):prepend_text("Length")
end

---@param tree TreeItem
---@param data ByteArray
---@param label string
function _M.bytes(tree, data, label)
    local data_tvb = data:tvb(label)
    tree:add_le(pf.bytes, data_tvb()):prepend_text(label):set_generated()
end

---@param tree TreeItem
---@param tvbr TvbRange Opcode
---@param isencrypted boolean
---@param isserver boolean
function _M.opcode(tree, tvbr, isencrypted, isserver)
    local f = isserver and pf.server_opcode or pf.client_opcode
    local item = tree:add(f, tvbr(offset, len))
    if isencrypted then
        item:set_generated()
    end
end

---@param tree TreeItem
---@param tvbr TvbRange Data
---@param opcode number
---@param isencrypted boolean
---@param isserver boolean
function _M.data(tree, tvbr, opcode, isencrypted, isserver)
    local subtree = tree:add(tvbr, "Data")
    if isencrypted then
        subtree:set_generated()
    end

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
            f = pf.u8
            len = 1
        elseif typ == "d" then
            -- TODO sign?
            f = pf.u32
            len = 4
        elseif typ == "f" then
            f = pf.double
            len = 8
        elseif typ == "h" then
            -- TODO sign?
            f = pf.u16
            len = 2
        elseif typ == "q" then
            -- TODO check
            f = pf.bytes
            len = 4
        elseif typ == "s" then
            f = pf.string
            val, len = tvbr(offset):le_ustringz()
        elseif typ == "z" then
            f = pf.bytes
            -- TODO check
            len = -1 -- TODO take remains len
        elseif typ == "-" then
            -- TODO check (script)
            f = pf.string
            len = -1
        else
            break -- TODO error
        end

        -- TODO select endian
        local item = val and subtree:add_le(f, tvbr(offset, len), val)
                         or subtree:add_le(f, tvbr(offset, len))
        item:prepend_text(field_fmt.name)
        if isencrypted then
            item:set_generated()
        end

        offset = offset + len
    end
end

return _M