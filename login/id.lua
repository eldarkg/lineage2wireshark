--[[
    License: GPL3
    Author: Eldar Khayrullin
    Email: eldar.khayrullin@mail.ru
    Date: 2024
    Description: Login ID
]]--

---Workaround: skip 1st pass without root path
if not package.searchpath("login.id", package.path) then
    return
end

local _M = {}

---@param path string
---@param lang string Language: see content/login (en, ru)
function _M.init(lang)
    local cmn = require("common.utils")
    local content_abs_path = cmn.abs_path("content/login/" .. lang .. "/")

    local id = require("common.id")
    local ID = {}
    ID["AccountKicked"] = id.load(content_abs_path .. "AccountKickedReason.ini", 0)
    ID["GGAuth"] = id.load(content_abs_path .. "GGAuthResponse.ini", 0)
    ID["LoginFail"] = id.load(content_abs_path .. "LoginFailReason.ini", 0)
    ID["PlayFail"] = id.load(content_abs_path .. "PlayFailReason.ini", 0)

    return ID
end

return _M