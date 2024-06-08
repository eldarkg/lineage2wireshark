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
| ?        | Next fields are not mandatory |
| *        | action without data |
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

#### Action with data
| Action | Description |
|:------:|-------------|
| AddObjID | Add object ID to objects cache. Use first of next found `string` or `Get.` as info |
| For    | Repeat field `value` times next `Param` fields |
| Get    | Get description by `value` index from accordance content file to `Param` |
| Hex    | Show `value` as hex |
| Len    | Limit length `Param` for string |
| ObjID  | Get object from objects cache |
| Switch | Begin switch block (`Name` - any) of next field `value` |
| Case   | Case `Name` values list (comma separated) of previous switch next `Param` size block. `Name` == `default` - default case |
| Unscramble | Unscramble `value` |

#### Action without data
| Action | Description |
|:------:|-------------|
| Struct | Struct next `Param` fields |

* Action is case insensetive.
