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

-- TODO move to protocol preferences
local GAME_PORT = 7777
local STATIC_XOR_KEY = "\xA1\x6C\x54\x87"

local lineage2game = Proto("lineage2game", "Lineage2 Game Protocol")

-- TODO set protocol info

local SERVER_OPCODE = {
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
    ChangeWaitType = 0x2F,
    TeleportToLocation = 0x38,
    ChangeMoveType = 0x3E,
    SkillList = 0x58,
    LogOutOk = 0x7E,
    MagicEffectIcons = 0x7F,
    QuestList = 0x80,
    NetPing = 0xD3,
    ServerSocketClose = 0xAF,
    ChairSit = 0xE1,
    HennaInfo = 0xE4,
    SendMacroList = 0xE7,
    EtcStatusUpdate = 0xF3,
    SSQInfo = 0xF8,
    ExSendManorList = 0xFE1B,
}
local SERVER_OPCODE_TXT = cmn.invert(SERVER_OPCODE)

local CLIENT_OPCODE = {
    ProtocolVersion = 0x00,
    MoveBackwardToLocation = 0x01,
    Say = 0x02,
    EnterWorld = 0x03,
    Action = 0x04,
    RequestAuthLogin = 0x08,
    Logout = 0x09,
    AttackRequest = 0x0A,
    CharCreate = 0x0B,
    CharDelete = 0x0C,
    CharSelected = 0x0D,
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
    RequestSkillCoolTime = 0x9D,
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
    RequestManorList = 0xD008,
    RequestExPledgeCrestLarge = 0xD010,
    RequestExSetPledgeCrestLarge = 0xD011,
    RequestChangePartyLeader = 0xEE,
}
local CLIENT_OPCODE_TXT = cmn.invert(CLIENT_OPCODE)

local f_bytes = ProtoField.bytes("lineage2game.bytes", " ", base.NONE)
local f_bool = ProtoField.bool("lineage2game.bool", " ")
local f_uint8 = ProtoField.uint8("lineage2game.uint8", " ", base.DEC)
local f_uint16 = ProtoField.uint16("lineage2game.uint16", " ", base.DEC)
local f_uint32 = ProtoField.uint32("lineage2game.uint32", " ", base.DEC)
local f_bin32 = ProtoField.uint32("lineage2game.bin32", " ", base.HEX)
local f_string = ProtoField.string("lineage2game.string", " ", base.ASCII)
local f_stringz = ProtoField.stringz("lineage2game.stringz", " ", base.ASCII)
local f_ipv4 = ProtoField.ipv4("lineage2game.ipv4", " ")
local f_server_opcode = ProtoField.uint8("lineage2game.server_opcode",
                                         "Opcode", base.HEX, SERVER_OPCODE_TXT)
local f_client_opcode = ProtoField.uint8("lineage2game.client_opcode",
                                         "Opcode", base.HEX, CLIENT_OPCODE_TXT)

lineage2game.fields = {
    f_bytes,
    f_uint16,
    f_uint32,
    f_server_opcode,
    f_client_opcode,
}

-- TODO implement module cache. Methods: new, set(number, val), last, get(number)

---Init by lineage2game.init
---Last packet pinfo.number
local last_packet_number
---Accumulator XOR decrypt length in current pinfo.number
local xor_accum_len

---Last sub packet number
local last_subpacket_number
---Key: pinfo.number. Value: sub packet count
local packet_count_cache

local server_xor_key
local client_xor_key
-- TODO save only dynamic part
---Key: pinfo.number. Value: XOR key
local xor_key_cache

---Opcode stat in last packet
---Key: opcode. Value: sub packet count
local last_opcode_stat

---@param tvb Tvb
---@param isserver boolean
---@return boolean
local function is_encrypted_packet(tvb, isserver)
    local len = packet.length(tvb)
    local opcode = packet.opcode(tvb)
    -- TODO check current *_xor_key for empty
    if isserver then
        return not (len == 16 and opcode == SERVER_OPCODE.KeyInit)
    else
        return not (len == 263 and opcode == CLIENT_OPCODE.ProtocolVersion)
    end
end

---@param tree        TreeItem
---@param opcode      number
---@param data        Tvb
---@param isencrypted boolean
local function decode_server_data(tree, opcode, data, isencrypted)
    if opcode == SERVER_OPCODE.KeyInit then
        cmn.add_le(tree, f_bytes, packet.xor_key_tvb(data), "XOR key",
                   isencrypted)
    end
    -- TODO
end

---@param tree        TreeItem
---@param opcode      number
---@param data        Tvb
---@param isencrypted boolean
local function decode_client_data(tree, opcode, data, isencrypted)
    if opcode == CLIENT_OPCODE.ProtocolVersion then
        cmn.add_le(tree, f_uint32, data(0, 4), "Protocol version", isencrypted)
    end
    -- TODO
end

---@param opcode number
---@param isserver boolean
---@return string
local function opcode_str(opcode, isserver)
    local str = isserver and SERVER_OPCODE_TXT[opcode] or CLIENT_OPCODE_TXT[opcode]
    return str and str or ""
end

---@param pnum     number pinfo.number
---@param isserver boolean
local function process_xor_key_cache(pnum, isserver)
    if xor_key_cache[pnum] then
        local xor_key = xor.next_key(xor_key_cache[pnum], xor_accum_len)
        if isserver then
            server_xor_key = xor_key
        else
            client_xor_key = xor_key
        end
    else
        xor_key_cache[pnum] = isserver and server_xor_key or client_xor_key
    end
end

---@param key string Server XOR key
local function init_xor_key(key)
    server_xor_key = xor.create_key(key, STATIC_XOR_KEY)
    client_xor_key = server_xor_key
end

---@param plen number Previous decrypted data length
---@param isserver boolean
local function update_xor_key(plen, isserver)
    xor_accum_len = xor_accum_len + plen

    if isserver then
        server_xor_key = xor.next_key(server_xor_key, plen)
    else
        client_xor_key = xor.next_key(client_xor_key, plen)
    end
end

---@param opcode number
local function update_last_opcode_stat(opcode)
    local n = last_opcode_stat[opcode]
    last_opcode_stat[opcode] = n and n + 1 or 1
end

---@return boolean false on 1 dissection pass
local function is_last_subpacket()
    return packet_count_cache[last_packet_number] and
           last_subpacket_number == packet_count_cache[last_packet_number]
end

---@param tvb Tvb
---@param pinfo Pinfo
---@param offset number
local function get_len(tvb, pinfo, offset)
    return packet.length(tvb(offset))
end

---@param tvb Tvb
---@param pinfo Pinfo
---@param tree TreeItem
local function dissect(tvb, pinfo, tree)
    pinfo.cols.protocol = lineage2game.name

    if tvb:len() == 0 then
        return 0
    end

    last_subpacket_number = last_subpacket_number + 1

    local isserver = (pinfo.src_port == GAME_PORT)
    local isencrypted = is_encrypted_packet(tvb, isserver)
    -- TODO check isencrypted and *_xor_key is empty then not process. Ret false. Print no XOR key

    if isencrypted then
        -- TODO use last_packet_number
        process_xor_key_cache(pinfo.number, isserver)
    end

    local xor_key = isserver and server_xor_key or client_xor_key

    local opcode_tvb = nil
    local data_tvb = nil
    if isencrypted then
        -- TODO empty encrypted_block ?
        local dec = xor.decrypt(packet.encrypted_block(tvb), xor_key)
        -- TODO move down
        -- TODO show Opcode name instead Decrypted
        local dec_tvb = ByteArray.tvb(ByteArray.new(dec, true), "Decrypted")

        opcode_tvb = packet.decrypted_opcode_tvb(dec_tvb(), isserver)
        data_tvb = dec_tvb(opcode_tvb:len())
    else
        opcode_tvb = packet.opcode_tvb(tvb)
        data_tvb = packet.data_tvb(tvb)
    end

    local opcode = cmn.be(opcode_tvb)
    update_last_opcode_stat(opcode)

    -- TODO only not in cache (flag). Check is isencrypted?
    if isserver and opcode == SERVER_OPCODE.KeyInit then
        init_xor_key(packet.xor_key(data_tvb))
    end

    -- TODO before Decrypted in representation
    -- TODO add packet id in sequence, example: 1. Opcode name
    local subtree = tree:add(lineage2game, tvb(), opcode_str(opcode, isserver))
    cmn.add_le(subtree, f_uint16, packet.length_tvb(tvb), "Length", false)
    if isencrypted then
        local label = "XOR key"
        -- TODO make hidden
        local xor_key_tvb = ByteArray.tvb(ByteArray.new(xor_key, true), label)
        cmn.add_le(subtree, f_bytes, xor_key_tvb(), label, isencrypted)
    end

    local f_opcode = isserver and f_server_opcode or f_client_opcode
    cmn.add_be(subtree, f_opcode, opcode_tvb, nil, isencrypted)

    -- TODO move dec_tvb here
    local data_st = cmn.generated(subtree:add(lineage2game, data_tvb, "Data"),
                                  isencrypted)
    -- TODO decode_data call server or client by isserver
    local decode_data = isserver and decode_server_data or decode_client_data
    decode_data(data_st, opcode, data_tvb, isencrypted)

    if isencrypted then
        update_xor_key(packet.encrypted_block(tvb):len(), isserver)
    end

    if is_last_subpacket() then
        -- TODO move to common
        local str = ""
        for op, count in pairs(last_opcode_stat) do
            if #str ~= 0 then
                str = str .. ", "
            end
            str = str .. opcode_str(op, isserver)
            if 1 < count then
                str = str .. "(" .. count .. ")"
            end
        end
        cmn.set_info_field(pinfo, isserver, isencrypted, str)
    end

    return tvb:len()
end

function lineage2game.init()
    last_packet_number = nil
    xor_accum_len = 0

    last_subpacket_number = 0
    packet_count_cache = {}

    server_xor_key = ""
    client_xor_key = ""
    xor_key_cache = {}

    last_opcode_stat = {}
end

---@param tvb Tvb
---@param pinfo Pinfo
---@param tree TreeItem
function lineage2game.dissector(tvb, pinfo, tree)
    pinfo.cols.info = ""

    if pinfo.number == last_packet_number then
        if packet_count_cache[last_packet_number] and
           packet_count_cache[last_packet_number] <= last_subpacket_number then
            xor_accum_len = 0
            last_subpacket_number = 0
        end
    else
        if last_packet_number and
           packet_count_cache[last_packet_number] == nil then
            packet_count_cache[last_packet_number] = last_subpacket_number
        end

        last_packet_number = pinfo.number
        xor_accum_len = 0
        last_subpacket_number = 0
        last_opcode_stat = {}
    end

    local subtree = tree:add(lineage2game, tvb(), "Lineage2 Game Protocol")
    dissect_tcp_pdus(tvb, subtree, packet.HEADER_LEN, get_len, dissect)
end

local tcp_port = DissectorTable.get("tcp.port")
tcp_port:add(GAME_PORT, lineage2game)
-- TODO use treeitem:add_tvb_expert_info