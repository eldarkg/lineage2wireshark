--[[
    License: GPL3
    Author: Eldar Khayrullin
    Email: eldar.khayrullin@mail.ru
    Date: 2024
    Description: common
]]--

local _M = {}

---@param buf ByteArray|TvbRange
---@return number
function _M.le(buf)
    return buf:le_uint()
end

---@param buf ByteArray|TvbRange
---@return number
function _M.be(buf)
    return buf:uint()
end

---Invert table key and value between themselves
---@param tbl table
---@return table
function _M.invert(tbl)
    local itbl = {}
    for key, value in pairs(tbl) do
        itbl[value] = key
    end
    return itbl
end

function _M.generated(item, isgen)
    return isgen and item:set_generated() or item
end

local function add_generic(add, item, protofield, tvbrange, label, isgen)
    item = _M.generated(add(item, protofield, tvbrange), isgen)
    item = label and item:prepend_text(label) or item
end

function _M.add_le(item, protofield, tvbrange, label, isgen)
    add_generic(item.add_le, item, protofield, tvbrange, label, isgen)
end

function _M.add_be(item, protofield, tvbrange, label, isgen)
    add_generic(item.add, item, protofield, tvbrange, label, isgen)
end

-- FIXME deprecated
function _M.set_info_field(pinfo, isserver, isgen, str)
    local src_role = isserver and "Server" or "Client"
    pinfo.cols.info =
        tostring(pinfo.src_port) .. " → " .. tostring(pinfo.dst_port) ..
        " " .. src_role .. ": " .. (isgen and ("[" .. str .. "]") or str)
end

---@param pinfo Pinfo
---@param isserver boolean
---@param isgen boolean
---@param opcode_stat table
---@param opcode_str function
function _M.set_info_field_stat(pinfo, isserver, isgen, opcode_stat, opcode_str)
    local str = ""
    for op, count in pairs(opcode_stat) do
        if #str ~= 0 then
            str = str .. ", "
        end
        str = str .. opcode_str(op, isserver)
        if 1 < count then
            str = str .. "(" .. count .. ")"
        end
    end
    _M.set_info_field(pinfo, isserver, isgen, str)
end

return _M