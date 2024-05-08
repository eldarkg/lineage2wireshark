--[[
    License: GPL3
    Author: Eldar Khayrullin
    Email: eldar.khayrullin@mail.ru
    Date: 2024
    Description: Data
]]--

---Workaround: skip 1st pass without root path
if not package.searchpath("data", package.path) then
    return
end

local ini = require("thirdparty.ini")

local _M = {}

---@param path string
function _M.load(path)
    _M.packets = ini.parse(path)
end

---@param isserver boolean
---@return table opcode2name Key: opcode, Value: name
function _M.opcode_names(isserver)
    local tbl = {}
    for opcode, desc in pairs(_M.packets[isserver and "server" or "client"]) do
        local opname = desc:match("^(%w+):")
        tbl[opcode] = opname
    end
    return tbl
end

---@param opcode number
---@param isserver boolean
---@return table
function _M.data_format(opcode, isserver)
    local desc = _M.packets[isserver and "server" or "client"][opcode]
    local opname = desc:match("^(%w+):")
    local fmt = desc:sub(#opname + 2)

    local data = {}
    for typ, name, func in fmt:gmatch("(%a)%((%w+):?(%g-)%)") do
        local field = {}
        field.type = typ
        field.name = name
        field.func = func
        table.insert(data, field)
    end

    return data
end

-- TODO TEST
-- _M.load("content/packetsc5.ini")
-- for key, value in pairs(_M.opcode_names(false)) do
--     print(key, value)
-- end
-- local fmt = _M.data_format(0x0C, true)
-- for index, value in ipairs(fmt) do
--     print(index, value.type, value.name, value.func)
-- end
return _M