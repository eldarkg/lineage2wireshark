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

local uniconv = require("unistring.uniconv")

local ICON_SIZE_LEN = 4
local ASCII_CHAR_SIZE = 1
local UTF16_CHAR_SIZE = 2

local _M = {}

---@param str string List string
---@param sep string Separator
---@param isnum boolean Is decimal number or string
---@return table set
local function parse_list(str, sep, isnum)
    local set = {}
    for match in str:gmatch("([^" .. sep .. "%s]+)") do
        local val = isnum and tonumber(match, 10) or match
        -- table.insert(list, val)
        set[val] = true
    end
    return set
end

---@param self table
---@param tree TreeItem
---@param tvbr TvbRange Length
local function length(self, tree, tvbr)
    tree:add_le(self.pf.u16, tvbr):prepend_text("Length")
end

---@param self table
---@param tree TreeItem
---@param data ByteArray
---@param label string
local function bytes(self, tree, data, label)
    local data_tvb = data:tvb(label)
    tree:add_le(self.pf.bytes, data_tvb()):prepend_text(label):set_generated()
end

---@param self table
---@param tree TreeItem
---@param tvbr TvbRange Opcode
---@param isencrypted boolean
---@return TreeItem item
local function opcode(self, tree, tvbr, isencrypted)
    local item = tree:add(self.pf.bytes, tvbr(offset, len)):prepend_text("Opcode")
    if isencrypted then
        item:set_generated()
    end
    return item
end

---@param data ByteArray
---@param char_sz integer
---@return integer len
local function strlen(data, char_sz)
    local len = 0
    for i = 0, data:len() - 1, char_sz do
        if data:le_uint(i, char_sz) == 0 then
            break
        end
        len = len + char_sz
    end
    return len
end

-- TODO use capital case for Big endian or HEX values or field_fmt.action: Len.{n}?

---@param data ByteArray Field data
---@param typ string Field type
---@param len integer
---@return any val
---@return integer len Refined length
local function get_value_refine_len(data, typ, len)
    local val
    if typ == "b" then
        len = data(0, len):le_uint()
    elseif typ == "c" then
        val = data(0, len):le_uint()
    elseif typ == "d" then
        val = data(0, len):le_int()
    elseif typ == "h" then
        val = data(0, len):le_uint()
    elseif typ == "q" then
        val = data(0, len):le_int64()
    elseif typ == "s" then
        len = strlen(data, UTF16_CHAR_SIZE)
        val = len == 0 and ""
                       or uniconv.from_encoding("UTF16", nil, data(0, len):raw())
        len = len + UTF16_CHAR_SIZE
    elseif tonumber(typ, 10) then
        val = data(0, len)
    end
    return val, len
end

---@param self table
---@param data ByteArray Field data
---@param fmt table Field format
---@return ProtoField f
---@return integer|nil len Length. nil - memory range is out of bounds
---@return any val
---@return boolean le Is Little Endian else Big Endian
local function parse_field(self, data, fmt)
    local f
    local len
    local val
    local le = true

    -- TODO use Param: Hex
    local typ = fmt.type
    if typ == "b" then
        f = self.pf.bytes
        len = ICON_SIZE_LEN
    elseif typ == "c" then
        f = self.pf.u8
        len = 1
    elseif typ == "d" then
        if fmt.action == "hex" or fmt.param == "FCol" then
            f = self.pf.r32
        else
            f = self.pf.i32
        end
        len = 4
    elseif typ == "f" then
        f = self.pf.double
        len = 8
    elseif typ == "h" then
        f = self.pf.u16
        len = 2
    elseif typ == "i" then
        f = self.pf.ipv4
        len = 4
        le = false
    elseif typ == "q" then
        f = self.pf.i64
        len = 8
    elseif typ == "s" then
        f = self.pf.utf16z
        len = UTF16_CHAR_SIZE -- min length of zero-terminated UTF16 string
    elseif typ == "S" then
        if fmt.action == "len" then
            len = tonumber(fmt.param, 10)
            f = strlen(data(0, len), ASCII_CHAR_SIZE) < len
                and self.pf.asciiz or self.pf.ascii
        else
            f = self.pf.asciiz
            len = ASCII_CHAR_SIZE -- min length of zero-terminated ASCII string
        end
    elseif typ == "z" then
        f = self.pf.bytes
        local s = fmt.name:match("(%d+)")
        len = tonumber(s, 10)
    elseif typ == "-" then
        -- TODO decode Script:
        -- implement to ini operator Switch, Case.{scope}[.{n}]
        -- implement to ini For.{scope}[.{count_field}]
        f = self.pf.bytes
        len = -1
    else
        len = tonumber(typ, 10)
        if len then
            f = self.pf.bytes
        end
    end

    if len then
        if len <= data:len() then
            val, len = get_value_refine_len(data, typ, len)
        else
            len = nil
        end
    end

    return f, len, val, le
end

---@param self table
---@param data ByteArray Data
---@param opcode integer
---@param isserver boolean
---@return table|nil values
local function get_values(self, data, opcode, isserver)
    local data_fmt = self.OPCODE_FMT[isserver and "server" or "client"][opcode]
    if data_fmt and 0 < data:len() then
        local values = {}
        for i = 1, #data_fmt, 1 do
            local field_fmt = data_fmt[i]
            if field_fmt.type == "?" or field_fmt.type == "*" then
                goto continue
            end

            local len
            local val
            _, len, val = parse_field(self, data, field_fmt)
            if not len then
                break
            end

            values[field_fmt.name] = val

            if data:len() <= len then
                break
            end
            data = data(len, data:len() - len)
            ::continue::
        end
        return values
    else
        return nil
    end
end

---@param self table
---@param tree TreeItem
---@param tvbr TvbRange Data
---@param data_fmt table Data format
---@param isencrypted boolean
---@return integer|nil len Decode length. nil - memory range is out of bounds
local function decode_data(self, tree, tvbr, data_fmt, isencrypted)
    local offset = 0
    local i = 1
    local ismandatory = true
    local switch_beg
    local switch_val
    while i <= #data_fmt do
        local field_fmt = data_fmt[i]

        if field_fmt.type == "?" then
            ismandatory = false
        elseif field_fmt.type == "*" then
            if field_fmt.action == "struct" then
                local iend = i + tonumber(field_fmt.param, 10)
                local subtree = tree:add(tvbr(offset), field_fmt.name)
                if isencrypted then
                    subtree:set_generated()
                end

                local len = decode_data(self, subtree, tvbr(offset),
                                        {table.unpack(data_fmt, i + 1, iend)},
                                        isencrypted)
                if len then
                    subtree:set_len(len)
                    offset = offset + len
                else
                    return nil
                end

                i = iend
            elseif field_fmt.action == "switch" then
                switch_beg = true
            elseif field_fmt.action == "case" then
                if switch_val == nil then
                    -- TODO syntax error
                    return nil
                end

                local iend = i + tonumber(field_fmt.param, 10)

                local set = parse_list(field_fmt.name, ",", true)
                if set[switch_val] or
                   field_fmt.name == "default" and switch_beg ~= nil then

                    local len = decode_data(self, tree, tvbr(offset),
                        {table.unpack(data_fmt, i + 1, iend)},
                        isencrypted)
                    if len then
                        offset = offset + len
                    else
                        return nil
                    end

                    switch_beg = nil
                    switch_val = nil
                end

                i = iend
            end
        else
            if tvbr:len() <= offset then
                if ismandatory then
                    tree:add_proto_expert_info(self.pe.undecoded,
                        "not found field \"" .. field_fmt.name .. "\"")
                    return nil
                else
                    break
                end
            end

            local f
            local len
            local val
            local le
            f, len, val, le = parse_field(self, tvbr(offset):bytes(), field_fmt)
            if not len then
                tree:add_proto_expert_info(self.pe.undecoded, "parse field \"" ..
                    field_fmt.name .. "(" .. field_fmt.type .. ")\"")
                return nil
            end

            if switch_beg == true then
                switch_beg = false
                switch_val = val
            end

            if field_fmt.type == "b" then
                local item = tree:add_le(self.pf.i32, tvbr(offset, ICON_SIZE_LEN))
                item:prepend_text("Icon size")
                if isencrypted then
                    item:set_generated()
                end
                offset = offset + ICON_SIZE_LEN

                if tvbr:len() < offset + len then
                    tree:add_proto_expert_info(self.pe.undecoded,
                                            "incomplete icon \"" ..
                                            field_fmt.name .. "\"")
                    return nil
                end
            end

            local field_tvbr = tvbr(offset, len)
            local add = le and TreeItem.add_le or TreeItem.add
            local item = val and f ~= self.pf.bytes
                             and add(tree, f, field_tvbr, val)
                             or add(tree, f, field_tvbr)
            item:prepend_text(field_fmt.name)

            -- TODO warn if action not found
            if field_fmt.action == "get" and field_fmt.param ~= "FCol" then
                local id = self.ID[field_fmt.param]
                local desc = id and id[val] or nil
                item:append_text(" (" .. tostring(desc) .. ")")
            end

            if isencrypted then
                item:set_generated()
            end

            if field_fmt.action == "unscramble" then
                local unscr = require("rsa").unscramble_mod(field_tvbr:bytes())
                self:bytes(tree, unscr, "Unscrambled " .. field_fmt.name)
            end

            offset = offset + len

            if field_fmt.action == "for" then
                local iend = i + tonumber(field_fmt.param, 10)
                for j = 1, val, 1 do
                    if tvbr:len() <= offset then
                        if ismandatory then
                            tree:add_proto_expert_info(self.pe.undecoded,
                                "not found repeat #" .. tostring(j) ..
                                " of group " .. field_fmt.name)
                            return nil
                        else
                            break
                        end
                    end

                    local subtree = tree:add(tvbr(offset), tostring(j))
                    if isencrypted then
                        subtree:set_generated()
                    end

                    len = decode_data(self, subtree, tvbr(offset),
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
        end

        i = i + 1
    end

    return offset
end

-- TODO save ID from CharInfo, NpcInfo and etc for later link ID by packet number

---@param self table
---@param tree TreeItem
---@param tvbr TvbRange Data
---@param opcode integer
---@param isencrypted boolean
---@param isserver boolean
---@return integer|nil len Decode length. nil - error
local function data(self, tree, tvbr, opcode, isencrypted, isserver)
    local subtree = tree:add(tvbr, "Data")
    if isencrypted then
        subtree:set_generated()
    end

    local data_fmt = self.OPCODE_FMT[isserver and "server" or "client"][opcode]
    if data_fmt then
        return decode_data(self, subtree, tvbr, data_fmt, isencrypted)
    else
        tree:add_proto_expert_info(self.pe.unk_opcode, "unknown opcode \"" ..
                                   string.format("0x%X", opcode) .. "\"")
        return nil
    end
end

---@param pf table Proto fields
---@param pe table Proto experts
---@param isgame boolean False - Login
---@param ver string
---@param lang string Language: see content/game (en, ru)
function _M.init(pf, pe, isgame, ver, lang)
    local name = isgame and "game" or "login"
    local utils = require("common.utils")
    local op = require("common.opcode").load(
        utils.abs_path("content/" .. name .. "/packets/" .. ver .. ".ini"))

    local OPCODE_NAME = {}
    local OPCODE_FMT = {}
    OPCODE_NAME.server, OPCODE_FMT.server = op:opcode_name_format(true)
    OPCODE_NAME.client, OPCODE_FMT.client = op:opcode_name_format(false)
    return {
        pf = pf,
        pe = pe,
        OPCODE_NAME = OPCODE_NAME,
        OPCODE_FMT = OPCODE_FMT,
        ID = require(name .. ".id").init(lang),

        get_values = get_values,
        length = length,
        bytes = bytes,
        opcode = opcode,
        data = data,
    }
end

return _M