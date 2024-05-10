--[[
    License: GPL3
    Author: Eldar Khayrullin
    Email: eldar.khayrullin@mail.ru
    Date: 2024
    Description: Decode data
]]--

---Workaround: skip 1st pass without root path
if not package.searchpath("decode", package.path) then
    return
end

local data = require("data")
-- TODO instead init input Proto to set fields and experts
local pe = require("game.protoexpert")
local pf = require("game.protofield")

local _M = {}
local OPCODE_FMT = {}

-- TODO input Proto to set fields and experts
---@param path string
function _M.init(path)
    data.load(path)
    _M.OPCODE_NAME = {}
    _M.OPCODE_NAME.server, OPCODE_FMT.server = data.opcode_name_format(true)
    _M.OPCODE_NAME.client, OPCODE_FMT.client = data.opcode_name_format(false)

    pf.init(_M.OPCODE_NAME)
    _M.PF = {
        pf.bytes,
        pf.u8,
        pf.u16,
        pf.i32,
        pf.i64,
        pf.double,
        pf.string,
        pf.server_opcode,
        pf.client_opcode,
    }

    _M.PE = {
        pe.undecoded,
        pe.unk_opcode,
    }
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
---@param isserver boolean
---@return TreeItem item
function _M.opcode(tree, tvbr, isencrypted, isserver)
    local f = isserver and pf.server_opcode or pf.client_opcode
    local item = tree:add(f, tvbr(offset, len))
    if isencrypted then
        item:set_generated()
    end
    return item
end

-- TODO process field_fmt.action:
-- for.{n} - repeat next n fields Count times (nocase)
-- get.{term} - get description? (nocase)
-- TODO use capital case for Hex values or field_fmt.action: Len.{n}?

-- FIXME !!! number replace with integer (every place)

---@param tvbr TvbRange Field data
---@param type string Field type
---@param len integer
---@return any val
---@return integer len Refined length
local function get_value(tvbr, type, len)
    local val
    if type == "c" then
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
        -- TODO check (bitmap)
        f = pf.bytes
        len = -1
    elseif type == "c" then
        f = pf.u8
        len = 1
    elseif type == "d" then
        f = pf.i32
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
        len = 2 -- min len of empty unicode string
    elseif type == "z" then
        f = pf.bytes
        local s = fmt.name:match("(%d+)")
        len = tonumber(s, 10)
    elseif type == "-" then
        -- TODO check (script)
        f = pf.string
        len = -1
    else
        len = tonumber(type, 10)
        if len then
            f = pf.bytes
        else
            -- TODO error
            print("Unknown type")
        end
    end

    if len <= tvbr:len() then
        val, len = get_value(tvbr, type, len)
    else
        len = nil
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
                                       field_fmt.name .. "\"")
            return nil
        end

        local act = field_fmt.action
        if act == "get" then
            -- print("Not implemented: get")
        end

        -- TODO select endian
        local item = val and tree:add_le(f, tvbr(offset, len), val)
                         or tree:add_le(f, tvbr(offset, len))
        item:prepend_text(field_fmt.name)
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
                if not len then
                    return nil
                end
                offset = offset + len
            end

            i = iend
        end

        i = i + 1
    end

    return offset
end

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
        tree:add_proto_expert_info(pe.unk_opcode, "not found field \"" ..
                                    field_fmt.name .. "\"")
        return nil
    end
end

return _M