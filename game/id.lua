--[[
    License: GPL3
    Author: Eldar Khayrullin
    Email: eldar.khayrullin@mail.ru
    Date: 2024
    Description: Game ID
]]--

---Workaround: skip 1st pass without root path
if not package.searchpath("game.id", package.path) then
    return
end

local _M = {}

---@param path string
---@param lang string Language: see content/game (en, ru)
function _M.init(lang)
    local cmn = require("common.utils")
    local content_abs_path = cmn.abs_path("content/game/" .. lang .. "/")

    local id = require("common.id")
    local ID = {}
    ID["Block"] = id.load(content_abs_path .. "Blocks.ini", 0)
    ID["ClassID"] = id.load(content_abs_path .. "ClassId.ini", 0)
    ID["FSup"] = id.load(content_abs_path .. "AttributesId.ini", 0)
    ID["Func01"] = id.load(content_abs_path .. "ItemsId.ini", 0)
    ID["Func02"] = id.load(content_abs_path .. "TextType.ini", 0)
    ID["GMCmd"] = id.load(content_abs_path .. "GMCmds.ini", 0)
    ID["Location"] = id.load(content_abs_path .. "Location.ini", 0)
    ID["Macro"] = id.load(content_abs_path .. "MacroTypes.ini", 0)
    ID["MsgID"] = id.load(content_abs_path .. "SysMsgId.ini", 0)
    -- TODO offset from protocol version
    ID["NpcId"] = id.load(content_abs_path .. "NpcsId.ini", 1000000) -- From C4
    ID["Race"] = id.load(content_abs_path .. "Races.ini", 0)
    ID["RestartPoint"] = id.load(content_abs_path .. "RestartPoints.ini", 0)
    ID["Sex"] = id.load(content_abs_path .. "Sex.ini", 0)
    ID["Shortcut"] = id.load(content_abs_path .. "ShortcutTypes.ini", 0)
    ID["Skill"] = id.load(content_abs_path .. "SkillsId.ini", 0)
    ID["SocialAction"] = id.load(content_abs_path .. "SocialActions.ini", 0)
    ID["SocialClass"] = id.load(content_abs_path .. "SocialClasses.ini", 0)
    ID["SSQ"] = id.load(content_abs_path .. "SSQInfos.ini", 256)

    return ID
end

return _M