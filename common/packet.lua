--[[
    License: GPL3
    Author: Eldar Khayrullin
    Email: eldar.khayrullin@mail.ru
    Date: 2024
    Description: Packet
]]--

---Workaround: skip 1st pass without root path
if not package.searchpath("common.packet", package.path) then
    return
end

local _M = {}

_M.HEADER_LEN = 2

local LENGTH_LEN = _M.HEADER_LEN
local XOR_KEY_LEN = 4

local LENGTH_OFFSET = 0

local OPCODE_PAYLOAD_OFFSET = 0

local XOR_KEY_DATA_OFFSET = 1

---@param tvb Tvb Packet
---@return TvbRange
function _M.length_tvbr(tvb)
    return tvb(LENGTH_OFFSET, LENGTH_LEN)
end

---@param tvb Tvb Packet
---@return integer
function _M.length(tvb)
    return _M.length_tvbr(tvb):le_uint()
end

---@param tvb Tvb Packet
---@param pinfo Pinfo
---@param offset integer
function _M.get_len(tvb, pinfo, offset)
    return _M.length(tvb(offset))
end

---@param tvb Tvb Packet
---@return TvbRange payload Packet payload without header length
function _M.payload_tvbr(tvb)
    return tvb(_M.HEADER_LEN)
end

---@param tvb Tvb Packet
---@return ByteArray payload Packet payload without header length
function _M.payload(tvb)
    return _M.payload_tvbr(tvb):bytes()
end

---@param payload ByteArray Payload
---@param isserver boolean
---@return integer
function _M.opcode_len(payload, isserver)
    local len = 1
    local opcode1 = payload:uint(OPCODE_PAYLOAD_OFFSET, len)
    -- TODO generate extended opcode1 list from *_OPCODE table
    if isserver then
        if opcode1 == 0xFE then
            len = 2
        end
    elseif opcode1 == 0x39 or opcode1 == 0xD0 then
        len = 2
    end
    return len
end

---@param tvbr TvbRange Payload
---@param op_len integer Opcode length
---@return TvbRange
function _M.opcode_tvbr(tvbr, op_len)
    return tvbr(OPCODE_PAYLOAD_OFFSET, op_len)
end

---@param payload ByteArray Payload
---@param op_len integer Opcode length
---@return integer
function _M.opcode(payload, op_len)
    return payload:uint(OPCODE_PAYLOAD_OFFSET, op_len)
end

---@param tvbr TvbRange Payload
---@param op_len integer Opcode length
---@return TvbRange|nil
function _M.data_tvbr(tvbr, op_len)
    return op_len < tvbr:len() and tvbr(op_len) or nil
end

---@param payload ByteArray Payload
---@param op_len integer Opcode length
---@return ByteArray
function _M.data(payload, op_len)
    return op_len < payload:len()
            and payload(op_len, payload:len() - op_len)
            or ByteArray.new()
end

---@param data TvbRange Data
---@return TvbRange
function _M.xor_key_tvbr(data)
    return data(XOR_KEY_DATA_OFFSET, XOR_KEY_LEN)
end

---@param data ByteArray Data
---@return ByteArray
function _M.xor_key(data)
    return data(XOR_KEY_DATA_OFFSET, XOR_KEY_LEN)
end

return _M