--[[
    License: GPL3
    Author: Eldar Khayrullin
    Email: eldar.khayrullin@mail.ru
    Date: 2024
    Description: common
]]--

local _M = {}

---@param buffer Tvb
---@return Tvb
function _M.le(buffer)
    return buffer:le_uint()
end

---@param buffer Tvb
---@return Tvb
function _M.be(buffer)
    return buffer:uint()
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

function _M.set_info_field(pinfo, isserver, isgen, opcode_str)
    local src_role = isserver and "Server" or "Client"
    if not opcode_str then opcode_str = "" end
    pinfo.cols.info =
        tostring(pinfo.src_port) .. " → " .. tostring(pinfo.dst_port) ..
        " " ..  src_role .. ": " ..
        (isgen and ("[" .. opcode_str .. "]") or opcode_str)
end

return _M