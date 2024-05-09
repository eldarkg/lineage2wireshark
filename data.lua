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
---@return table names Opcode to name
---@return table fmts Opcode to data format
function _M.opcode_name_format(isserver)
    local names = {}
    local fmts = {}

    for opcode, desc in pairs(_M.packets[isserver and "server" or "client"]) do
        local opname = desc:match("^([%w_]+):")
        names[opcode] = opname

        local fmt_str = desc:sub(#opname + 2)
        local data_fmt = {}
        for typ, name, func in fmt_str:gmatch("([%a-])%(([%w_]+):?(%g-)%)") do
            local field_fmt = {}
            field_fmt.type = typ
            field_fmt.name = name
            field_fmt.func = func
            table.insert(data_fmt, field_fmt)
        end

        fmts[opcode] = data_fmt
    end

    return names, fmts
end

return _M