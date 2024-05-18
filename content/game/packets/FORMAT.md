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
Type(Name[:Func.FuncParam])
```

#### Type
| Type | Description |
|:----:|-------------|
| -        | script decoded |
| `number` | bytes array with size equal `number` |
| b        | bitmap: icon size (4 bytes) + data |
| c        | u8 |
| d        | i32 (Exception: `FCol` - r32) |
| f        | double |
| h        | u16 |
| q        | i64 |
| s        | string UTF-16 |
| z        | bytes array with size equal `Name` number (like 256fixed or 32) |

#### Func
| Func | Description |
|:----:|-------------|
| For  | Repeat field `value` times next `FuncParam` fields |
| Get  | Get description by `value` index from accordance content file to `FuncParam` |

* Func is case insensetive.
