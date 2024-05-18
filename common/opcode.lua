--[[
    License: GPL3
    Author: Eldar Khayrullin
    Email: eldar.khayrullin@mail.ru
    Date: 2024
    Description: Opcodes
]]--

---Workaround: skip 1st pass without root path
if not package.searchpath("common.opcode", package.path) then
    return
end

local ini = require("thirdparty.ini")

local _M = {}

---@param self table
---@param isserver boolean
---@return table names Opcode to name
---@return table fmts Opcode to data format
local function opcode_name_format(self, isserver)
    local names = {}
    local fmts = {}

    for opcode_s, desc
        in pairs(self.packets[isserver and "server" or "client"]) do

        local opcode = tonumber(opcode_s, 16)
        local opname = desc:match("^([^:]+):")
        names[opcode] = opname

        local fmt_str = desc:sub(#opname + 2)
        local data_fmt = {}
        for typ, name, action, param
            in fmt_str:gmatch("([^(]+)%(([^:)]+):?([^.)]-)%.?([^.]-)%)") do

            local field_fmt = {}
            field_fmt.type = typ
            field_fmt.name = name
            field_fmt.action = action:lower()
            field_fmt.param = param
            table.insert(data_fmt, field_fmt)
        end

        fmts[opcode] = data_fmt
    end

    return names, fmts
end

---@param path string
function _M.load(path)
    return {
        packets = ini.parse(path),
        opcode_name_format = opcode_name_format
    }
end

return _M