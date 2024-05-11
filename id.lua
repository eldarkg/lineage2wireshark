--[[
    License: GPL3
    Author: Eldar Khayrullin
    Email: eldar.khayrullin@mail.ru
    Date: 2024
    Description: ID
]]--

---Workaround: skip 1st pass without root path
if not package.searchpath("id", package.path) then
    return
end

local ini = require("thirdparty.ini")

local _M = {}

---@param path string
function _M.load(path)
    local tbl = ini.parse(path)
    local id_desc = {}
    for id, desc in pairs(tbl) do
        id_desc[tonumber(id, 10)] = desc
    end
    return id_desc
end

return _M