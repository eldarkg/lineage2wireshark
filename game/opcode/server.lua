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
    NpcSay = 0x02,
    CharInfo = 0x03,
    UserInfo = 0x04,
    Attack = 0x05,
    Die = 0x06,
    Revive = 0x07,
    AttackOutOfRange = 0x08,
    AttackinCoolTime = 0x09,
    AttackDeadTarget = 0x0A,
    SpawnItem = 0x0B,
    DropItem = 0x0C,
    GetItem = 0x0D,
    StatusUpdate = 0x0E,
    NpcHtmlMessage = 0x0F,
    SellList = 0x10,
    BuyList = 0x11,
    DeleteObject = 0x12,
    CharSelectInfo = 0x13,
    LoginFail = 0x14,
    CharSelected = 0x15,
    NpcInfo = 0x16,
    CharTemplates = 0x17,
    NewCharFail = 0x18,
    CharCreateSuccess = 0x19,
    CharCreateFail = 0x1A,
    ItemListPacket = 0x1B,
    SunRise = 0x1C,
    SunSet = 0x1D,
    TradeStart = 0x1E,
    TradeStartOk = 0x1F,
    TradeOwnAdd = 0x20,
    TradeOtherAdd = 0x21,
    TradeDone = 0x22,
    CharDeleteSuccess = 0x23,
    CharDeleteFail = 0x24,
    ActionFail = 0x25,
    SeverClose = 0x26,
    InventoryUpdate = 0x27,
    TeleportToLocation = 0x28,
    TargetSelected = 0x29,
    TargetUnselected = 0x2A,
    AutoAttackStart = 0x2B,
    AutoAttackStop = 0x2C,
    SocialAction = 0x2D,
    ChangeMoveType = 0x2E,
    ChangeWaitType = 0x2F,
    -- TODO
    SetDismissPledge = 0x38,
    DismissParty = 0x3E,
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