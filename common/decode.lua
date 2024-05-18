--[[
    License: GPL3
    Author: Eldar Khayrullin
    Email: eldar.khayrullin@mail.ru
    Date: 2024
    Description: Decode data
]]--

---Workaround: skip 1st pass without root path
if not package.searchpath("common.decode", package.path) then
    return
end

-- TODO create instance

local pe = require("game.protoexpert")
local pf

local ICON_SIZE_LEN = 4

local _M = {}
local OPCODE_FMT = {}
local ID = {}

---@param _pf table
---@param path string
---@param lang string Language: see content/game (en, ru)
function _M.init(_pf, path, lang)
    -- FIXME
    pf = _pf
    local op = require("common.opcode").load(path)
    _M.OPCODE_NAME = {}
    _M.OPCODE_NAME.server, OPCODE_FMT.server = op:opcode_name_format(true)
    _M.OPCODE_NAME.client, OPCODE_FMT.client = op:opcode_name_format(false)

    -- TODO move to file
    local cmn = require("common.utils")
    local content_abs_path = cmn.abs_path("content/game/" .. lang .. "/")
    local id = require("common.id")
    ID["Block"] = id.load(content_abs_path .. "Blocks.ini", 0)
    ID["ClassID"] = id.load(content_abs_path .. "ClassId.ini", 0)
    ID["FSup"] = id.load(content_abs_path .. "AttributesId.ini", 0)
    ID["Func01"] = id.load(content_abs_path .. "ItemsId.ini", 0)
    ID["Func02"] = id.load(content_abs_path .. "TextType.ini", 0)
    ID["GMCmd"] = id.load(content_abs_path .. "GMCmds.ini", 0)
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
end

---@param tree TreeItem
---@param tvbr TvbRange Length
function _M.length(tree, tvbr)
    tree:add_le(pf.u16, tvbr):prepend_text("Length")
end

---@param tree TreeItem
---@param data ByteArray
---@param label string
function _M.bytes(tree, data, label)
    local data_tvb = data:tvb(label)
    tree:add_le(pf.bytes, data_tvb()):prepend_text(label):set_generated()
end

---@param tree TreeItem
---@param tvbr TvbRange Opcode
---@param isencrypted boolean
---@return TreeItem item
function _M.opcode(tree, tvbr, isencrypted)
    local item = tree:add(pf.bytes, tvbr(offset, len)):prepend_text("Opcode")
    if isencrypted then
        item:set_generated()
    end
    return item
end

-- TODO use capital case for Big endian or HEX values or field_fmt.action: Len.{n}?

---@param tvbr TvbRange Field data
---@param type string Field type
---@param len integer
---@return any val
---@return integer len Refined length
local function get_value_len(tvbr, type, len)
    local val
    if type == "b" then
        len = tvbr(0, len):le_uint()
    elseif type == "c" then
        val = tvbr(0, len):le_uint()
    elseif type == "d" then
        val = tvbr(0, len):le_int()
    elseif type == "h" then
        val = tvbr(0, len):le_uint()
    elseif type == "q" then
        val = tvbr(0, len):le_int64()
    elseif type == "s" then
        val, len = tvbr:le_ustringz()
    end
    return val, len
end

---@param tvbr TvbRange Field data
---@param fmt table Field format
---@return ProtoField f
---@return integer|nil len Length. nil - memory range is out of bounds
---@return any val
local function parse_field(tvbr, fmt)
    local f
    local len
    local val

    local type = fmt.type
    if type == "b" then
        f = pf.bytes
        len = ICON_SIZE_LEN
    elseif type == "c" then
        f = pf.u8
        len = 1
    elseif type == "d" then
        if fmt.param == "FCol" then
            f = pf.r32
        else
            f = pf.i32
        end
        len = 4
    elseif type == "f" then
        f = pf.double
        len = 8
    elseif type == "h" then
        f = pf.u16
        len = 2
    elseif type == "q" then
        f = pf.i64
        len = 8
    elseif type == "s" then
        f = pf.string
        len = 2 -- min length of empty unicode string
    elseif type == "z" then
        f = pf.bytes
        local s = fmt.name:match("(%d+)")
        len = tonumber(s, 10)
    elseif type == "-" then
        -- TODO decode Script:
        -- implement to ini operator Switch, Case.{scope}[.{n}]
        -- implement to ini For.{scope}[.{count_field}]
        f = pf.bytes
        len = -1
    else
        len = tonumber(type, 10)
        if len then
            f = pf.bytes
        end
    end

    if len then
        if len <= tvbr:len() then
            val, len = get_value_len(tvbr, type, len)
        else
            len = nil
        end
    end

    return f, len, val
end

---@param tree TreeItem
---@param tvbr TvbRange Data
---@param data_fmt table Data format
---@param isencrypted boolean
---@return integer|nil len Decode length. nil - memory range is out of bounds
local function decode_data(tree, tvbr, data_fmt, isencrypted)
    local offset = 0
    local i = 1
    while i <= #data_fmt do
        local field_fmt = data_fmt[i]

        if tvbr:len() <= offset then
            tree:add_proto_expert_info(pe.undecoded, "not found field \"" ..
                                       field_fmt.name .. "\"")
            return nil
        end

        local f
        local len
        local val
        f, len, val = parse_field(tvbr(offset), field_fmt)
        if not len then
            tree:add_proto_expert_info(pe.undecoded, "parse field \"" ..
                                       field_fmt.name ..
                                       "(" .. field_fmt.type .. ")\"")
            return nil
        end

        if field_fmt.type == "b" then
            local item = tree:add_le(pf.i32, tvbr(offset, ICON_SIZE_LEN))
            item:prepend_text("Icon size")
            if isencrypted then
                item:set_generated()
            end
            offset = offset + ICON_SIZE_LEN

            if tvbr:len() < offset + len then
                tree:add_proto_expert_info(pe.undecoded, "incomplete icon \"" ..
                                           field_fmt.name .. "\"")
                return nil
            end
        end

        -- TODO select endian
        local item = val and tree:add_le(f, tvbr(offset, len), val)
                         or tree:add_le(f, tvbr(offset, len))
        item:prepend_text(field_fmt.name)

        local act = field_fmt.action
        if act == "get" then
            local id = ID[field_fmt.param]
            if id then
                local desc = id[val]
                item:append_text(" (" .. tostring(desc) .. ")")
            end
        end

        -- TODO show hex for number types too
        if isencrypted then
            item:set_generated()
        end

        offset = offset + len

        if act == "for" then
            local iend = i + tonumber(field_fmt.param, 10)
            for j = 1, val, 1 do
                if tvbr:len() <= offset then
                    tree:add_proto_expert_info(pe.undecoded,
                                        "not found repeat #" .. tostring(j) ..
                                        " of group " .. field_fmt.name)
                    return nil
                end

                local subtree = tree:add(tvbr(offset), tostring(j))
                if isencrypted then
                    subtree:set_generated()
                end

                len = decode_data(subtree, tvbr(offset),
                                  {table.unpack(data_fmt, i + 1, iend)},
                                  isencrypted)
                if len then
                    subtree:set_len(len)
                    offset = offset + len
                else
                    return nil
                end
            end

            i = iend
        end

        i = i + 1
    end

    return offset
end

-- TODO save ID from CharInfo, NpcInfo and etc for later link ID by packet number

---@param tree TreeItem
---@param tvbr TvbRange Data
---@param opcode integer
---@param isencrypted boolean
---@param isserver boolean
---@return integer|nil len Decode length. nil - error
function _M.data(tree, tvbr, opcode, isencrypted, isserver)
    local subtree = tree:add(tvbr, "Data")
    if isencrypted then
        subtree:set_generated()
    end

    local data_fmt = OPCODE_FMT[isserver and "server" or "client"][opcode]
    if data_fmt then
        return decode_data(subtree, tvbr, data_fmt, isencrypted)
    else
        tree:add_proto_expert_info(pe.unk_opcode, "unknown opcode \"" ..
                                   string.format("0x%X", opcode) .. "\"")
        return nil
    end
end

return _M