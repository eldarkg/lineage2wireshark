--[[
    License: GPL3
    Author: Eldar Khayrullin
    Email: eldar.khayrullin@mail.ru
    Date: 2024
    Description: Wireshark Dissector for Lineage2Game
    Protocol: 709
]]--

local cmn = require("common")
local packet = require("packet")
local xor = require("xor")

local GAME_PORT = 7777
local STATIC_XOR_KEY = "\xA1\x6C\x54\x87"

local lineage2game = Proto("lineage2game", "Lineage2 Game Protocol")

local SERVER_OPCODE = {
    CryptInit = 0x00,
    MoveToLocation = 0x01,
    UserInfo = 0x04,
    StatusUpdate = 0x0E,
    CharList = 0x13,
    AuthLoginFail = 0x14,
    CharCreateOk = 0x19,
    CharCreateFail = 0x1A,
    CharDeleteOk = 0x23,
    CharDeleteFail = 0x24,
    ActionFailed = 0x25,
    ChangeWaitType = 0x2F,
    TeleportToLocation = 0x38,
    ChangeMoveType = 0x3E,
    LogoutOK = 0x7E,
    QuestList = 0x80,
    NetPingRequest = 0xD3,
    ServerSocketClose = 0xAF,
    ChairSit = 0xE1,
    ExSendManorList = 0xFE1B,
}
local SERVER_OPCODE_TXT = cmn.invert(SERVER_OPCODE)

local CLIENT_OPCODE = {
    ProtocolVersion = 0x00,
    MoveBackwardToLocation = 0x01,
    Say = 0x02,
    EnterWorld = 0x03,
    Action = 0x04,
    AuthRequest = 0x08,
    Logout = 0x09,
    AttackRequest = 0x0A,
    CharacterCreate = 0x0B,
    CharacterDelete = 0x0C,
    CharacterSelected = 0x0D,
    RequestItemList = 0x0F,
    RequestUnEquipItem = 0x11,
    RequestDropItem = 0x12,
    UseItem = 0x14,
    TradeRequest = 0x15,
    AddTradeItem = 0x16,
    TradeDone = 0x17,
    RequestSocialAction = 0x1B,
    ChangeMoveType = 0x1C,
    ChangeWaitType = 0x1D,
    RequestSellItem = 0x1E,
    RequestBuyItem = 0x1F,
    RequestBypassToServer = 0x21,
    RequestJoinPledge = 0x24,
    RequestAnswerJoinPledge = 0x25,
    RequestWithdrawalPledge = 0x26,
    RequestOustPledgeMember = 0x27,
    RequestJoinParty = 0x29,
    RequestAnswerJoinParty = 0x2A,
    RequestWithDrawalParty = 0x2B,
    RequestOustPartyMember = 0x2C,
    RequestMagicSkillUse = 0x2F,
    Appearing = 0x30,
    RequestShortCutReg = 0x33,
    RequestShortCutDel = 0x35,
    RequestTargetCanceld = 0x37,
    Say2 = 0x38,
    RequestPledgeMemberList = 0x3C,
    RequestSkillList = 0x3F,
    AnswerTradeRequest = 0x40,
    RequestActionUse = 0x45,
    RequestRestart = 0x46,
    ValidatePosition = 0x48,
    StartRotating = 0x4A,
    FinishRotating = 0x4B,
    RequestStartPledgeWar = 0x4D,
    RequestStopPledgeWar = 0x4F,
    RequestGiveNickName = 0x55,
    RequestEnchantItem = 0x58,
    RequestDestroyItem = 0x59,
    RequestFriendInvite = 0x5E,
    RequestAnswerFriendInvite = 0x5F,
    RequestFriendList = 0x60,
    RequestFriendDel = 0x61,
    CharacterRestore = 0x62,
    RequestQuestList = 0x63,
    RequestQuestAbort = 0x64,
    RequestPledgeInfo = 0x66,
    RequestPledgeCrest = 0x68,
    RequestRide = 0x6A,
    RequestAquireSkillInfo = 0x6B,
    RequestAquireSkill = 0x6C,
    RequestRestartPoint = 0x6D,
    RequestGMCommand = 0x6E,
    RequestPartyMatchConfig = 0x6F,
    RequestPartyMatchList = 0x70,
    RequestPartyMatchDetail = 0x71,
    RequestCrystallizeItem = 0x72,
    SetPrivateStoreMsgSell = 0x77,
    RequestGmList = 0x81,
    RequestJoinAlly = 0x82,
    RequestAnswerJoinAlly = 0x83,
    AllyLeave = 0x84,
    AllyDismiss = 0x85,
    RequestAllyCrest = 0x88,
    RequestChangePetName = 0x89,
    RequestPetUseItem = 0x8A,
    RequestGiveItemToPet = 0x8B,
    RequestGetItemFromPet = 0x8C,
    RequestAllyInfo = 0x8E,
    RequestPetGetItem = 0x8F,
    SetPrivateStoreMsgBuy = 0x94,
    RequestStartAllianceWar = 0x98,
    RequestStopAllianceWar = 0x9A,
    RequestBlock = 0xA0,
    RequestSiegeAttackerList = 0xA2,
    RequestJoinSiege = 0xA4,
    NetPing = 0xA8,
    RequestRecipeBookOpen = 0xAC,
    RequestEvaluate = 0xB9,
    RequestHennaList = 0xBA,
    RequestHennaItemInfo = 0xBB,
    RequestHennaEquip = 0xBC,
    RequestMakeMacro = 0xC1,
    RequestDeleteMacro = 0xC2,
    RequestAutoSoulShot = 0xCF,
    RequestExEnchantSkillInfo = 0xD006,
    RequestExEnchantSkill = 0xD007,
    RequestExManorList = 0xD008,
    RequestExPledgeCrestLarge = 0xD010,
    RequestExSetPledgeCrestLarge = 0xD011,
    RequestChangePartyLeader = 0xEE,
}
local CLIENT_OPCODE_TXT = cmn.invert(CLIENT_OPCODE)

local pf_bytes = ProtoField.bytes("lineage2game.bytes", " ", base.NONE)
local pf_bool = ProtoField.bool("lineage2game.bool", " ")
local pf_uint8 = ProtoField.uint8("lineage2game.uint8", " ", base.DEC)
local pf_uint16 = ProtoField.uint16("lineage2game.uint16", " ", base.DEC)
local pf_uint32 = ProtoField.uint32("lineage2game.uint32", " ", base.DEC)
local pf_bin32 = ProtoField.uint32("lineage2game.bin32", " ", base.HEX)
local pf_string = ProtoField.string("lineage2game.string", " ", base.ASCII)
local pf_stringz = ProtoField.stringz("lineage2game.stringz", " ", base.ASCII)
local pf_ipv4 = ProtoField.ipv4("lineage2game.ipv4", " ")
local pf_server_opcode = ProtoField.uint8("lineage2game.server_opcode",
                                          "Opcode", base.HEX, SERVER_OPCODE_TXT)
local pf_client_opcode = ProtoField.uint8("lineage2game.client_opcode",
                                          "Opcode", base.HEX, CLIENT_OPCODE_TXT)

lineage2game.fields = {
    pf_bytes,
    pf_uint16,
    pf_uint32,
    pf_server_opcode,
    pf_client_opcode,
}

-- TODO save only dynamic part
local xor_key_cache = {}
local server_xor_key = ""
local client_xor_key = ""

---@param buffer ByteArray
---@param isserver boolean
---@return boolean
local function is_encrypted_packet(buffer, isserver)
    local len = packet.length(buffer)
    local opcode = packet.opcode(buffer)
    if isserver then
        return not (len == 16 and opcode == SERVER_OPCODE.CryptInit)
    else
        return not (len == 263 and opcode == CLIENT_OPCODE.ProtocolVersion)
    end
end

local function decode_server_data(tree, opcode, data, isencrypted)
    if opcode == SERVER_OPCODE.CryptInit then
        cmn.add_le(tree, pf_bytes, packet.xor_key_buffer(data), "XOR key",
                   isencrypted)
    end
    -- TODO
end

local function decode_client_data(tree, opcode, data, isencrypted)
    if opcode == CLIENT_OPCODE.ProtocolVersion then
        cmn.add_le(tree, pf_uint32, data(0, 4), "Protocol version", isencrypted)
    end
    -- TODO
end

function lineage2game.dissector(buffer, pinfo, tree)
    pinfo.cols.protocol = lineage2game.name
    -- TODO check pinfo.visited
    -- TODO check pinfo.conversation
    -- TODO if pinfo.visited then return end

    if buffer:len() == 0 then return end

    local isserver = (pinfo.src_port == GAME_PORT)
    local pf_opcode = isserver and pf_server_opcode or pf_client_opcode
    local opcode_txt_tbl = isserver and SERVER_OPCODE_TXT or CLIENT_OPCODE_TXT
    local isencrypted = is_encrypted_packet(buffer, isserver)

    if not xor_key_cache[pinfo.number] then
        xor_key_cache[pinfo.number] =
            isserver and server_xor_key or client_xor_key
    end
    local xor_key = xor_key_cache[pinfo.number]

    local subtree = tree:add(lineage2game, buffer(), "Lineage2 Game Protocol")
    cmn.add_le(subtree, pf_uint16, packet.length_buffer(buffer), "Length", false)

    if isencrypted then
        local label = "XOR key"
        local xor_key_tvb = ByteArray.tvb(ByteArray.new(xor_key, true), label)
        cmn.add_le(subtree, pf_bytes, xor_key_tvb(), label, isencrypted)
    end

    local opcode_p = nil
    local data_p = nil
    if isencrypted then
        -- TODO empty encrypted_block ?
        local dec = xor.decrypt(packet.encrypted_block(buffer), xor_key)
        -- TODO only not in cache (flag)
        if isserver then
            server_xor_key = xor.next_key(xor_key, #dec)
        else
            client_xor_key = xor.next_key(xor_key, #dec)
        end

        local dec_tvb = ByteArray.tvb(ByteArray.new(dec, true), "Decrypted")

        opcode_p = packet.decrypted_opcode_buffer(dec_tvb(), isserver)
        data_p = dec_tvb(opcode_p:len())
    else
        opcode_p = packet.opcode_buffer(buffer)
        data_p = packet.data_buffer(buffer)
    end

    cmn.add_be(subtree, pf_opcode, opcode_p, nil, isencrypted)

    local data_st = cmn.generated(tree:add(lineage2game, data_p, "Data"),
                                  isencrypted)

    local opcode = cmn.be(opcode_p)
    -- TODO move up
    if isserver and opcode == SERVER_OPCODE.CryptInit then
        server_xor_key = xor.create_key(packet.xor_key(data_p), STATIC_XOR_KEY)
        client_xor_key = server_xor_key
    end
    local decode_data = isserver and decode_server_data or decode_client_data
    decode_data(data_st, opcode, data_p, isencrypted)

    cmn.set_info_field(pinfo, isserver, isencrypted, opcode_txt_tbl[opcode])
end

local tcp_port = DissectorTable.get("tcp.port")
tcp_port:add(GAME_PORT, lineage2game)