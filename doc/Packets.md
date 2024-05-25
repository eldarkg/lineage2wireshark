# Packets Description File Format
```ini
; Comment
[client] ; client packets section
Packet
...
Packet

[server] ; server packets section
Packet
...
Packet
```

## Packet
```ini
OpcodeHex=OpcodeName:[Field[...Field]]
```

### Field
```ini
Type(Name[:Action[.Param]])
```

#### Type
| Type     | Description |
|:--------:|-------------|
| -        | script decoded |
| `number` | bytes array with size equal `number` |
| b        | bitmap: icon size (4 bytes) + data |
| c        | u8 |
| d        | i32 (Exception: `FCol` - r32) |
| f        | double |
| h        | u16 |
| i        | IPv4 |
| q        | i64 |
| s        | zero terminated string UTF-16 |
| S        | zero terminated string ASCII |
| z        | bytes array with size equal `Name` number (like 256fixed or 32) |

#### Action
| Action | Description |
|:------:|-------------|
| For    | Repeat field `value` times next `Param` fields |
| Get    | Get description by `value` index from accordance content file to `Param` |
| Hex    | Show `value` as hex |
| Len    | Limit length `Param` for string |
| Unscramble | Unscramble `value` |

* Action is case insensetive.
