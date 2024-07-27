# lineage2wireshark

## Limitations
* manual protocol select
* one client-server connection protocol decode at the same time

## Support Protocols
* Login server: 785a, c621
* Game server: 660, 709, 746

## Wireshark Filters
* Login server: lineage2login (tcp.srcport == 2106 || tcp.dstport == 2106)
* Game server: lineage2game (tcp.srcport == 7777 || tcp.dstport == 7777)
* Show only packets: && tcp.len != 0

## Wireshark Preferences
### Protocols
![Preferences](doc/wireshark_pref_prot.png)
### Protocols -> TCP
* Validate the TCP checksum if possible (?)
* Allow subdissector to reassemble TCP streams
* Reassemble out-of-order segments
* Analyze TCP sequence numbers
* Do not call subdissectors for error packets (?)
![Preferences](doc/wireshark_pref_tcp.png)

## Wireshark cautions
* After `Reload Lua Plugins` need to `Reload this file` (otherwise invalid sequence)
* ?Switch between LINEAGE packet and TCP error packet break sequence crypt
(to restore switch to LINEAGE packet)

## Decrypt
### Find client (C4, C5 with ProtocolVersion 785a) static BlowFish private key
```
system/engine.dll -> Ghidra -> Search call InitializeBlowfish -> Arg 2 -> Key
```
* Try all found keys and find one valid.
### XOR Key
Found by selection based on known data of the first crypted packet
(for example packet `RequestAuthLogin`).

## Utility
Convert binary to image
```sh
convert -depth 8 -size 16x16+0 gray:in.bin out.png
```

## Dependency
* Wireshark 4.2.5 (last tested)
* Lua 5.2
* luarocks
* luacrypto2
* lua-unistring

## Thirdparty
* lua-ini (modified)

```shell
sudo luarocks install luacrypto2

sudo apt install libunistring-dev
sudo luarocks install --server=https://luarocks.org/dev unistring
```

INFO: http://mkottman.github.io/luacrypto/manual.html#reference