--[[
    License: GPL3
    Author: Eldar Khayrullin
    Email: eldar.khayrullin@mail.ru
    Date: 2024
    Description: Game Server Opcodes
    Protocol: 709?
]]--

---Workaround: skip 1st pass without root path
if not package.searchpath("common", package.path) then
    return
end

local cmn = require("common")

local _M = {}

_M.SERVER_OPCODE = {
    KeyInit = 0x00,
    MoveToLocation = 0x01,
    UserInfo = 0x04,
    StatusUpdate = 0x0E,
    CharSelectInfo = 0x13,
    AuthLoginFail = 0x14,
    CharSelected = 0x15,
    CharCreateOk = 0x19,
    CharCreateFail = 0x1A,
    CharDeleteOk = 0x23,
    CharDeleteFail = 0x24,
    ActionFailed = 0x25,
    SocialAction = 0x2D,
    ChangeWaitType = 0x2F,
    TeleportToLocation = 0x38,
    ChangeMoveType = 0x3E,
    DoorInfo = 0x4C,
    SkillList = 0x58,
    MagicSkillLaunched = 0x76,
    LogOutOk = 0x7E,
    MagicEffectIcons = 0x7F,
    QuestList = 0x80,
    PrivateStoreMsg = 0x9C,
    AllianceCrest = 0xAE,
    ServerSocketClose = 0xAF,
    RelationChanged = 0xCE,
    NetPing = 0xD3,
    ChairSit = 0xE1,
    HennaInfo = 0xE4,
    SendMacroList = 0xE7,
    EtcStatusUpdate = 0xF3,
    AgitDecoInfo = 0xF7,
    SSQInfo = 0xF8,
    FriendList = 0xFA,
    ExSendManorList = 0xFE1B,
    ExStorageMaxCount = 0xFE2E,
}

_M.SERVER_OPCODE_TXT = cmn.invert(_M.SERVER_OPCODE)

return _M