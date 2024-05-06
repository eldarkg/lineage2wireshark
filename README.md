# lineage2wireshark

## Support Protocols
* Login server: 785a
* Game server: 709

## Wireshark Filters
* Login server: (tcp.srcport == 2106 || tcp.dstport == 2106)
* Game server: (tcp.srcport == 7777 || tcp.dstport == 7777)
* Show only packets: && tcp.len != 0

## Wireshark Preferences
### Protocols -> TCP
* Validate the TCP checksum if possible (?)
* Allow subdissector to reassemble TCP streams
* Reassemble out-of-order segments
* Analyze TCP sequence numbers
* Do not call subdissectors for error packets (?)
![Preferences](doc/wireshark_pref.png)

## Dependency
* Wireshark 4.2.2 (other not tested)
* Lua 5.2
* luarocks
* luacrypto2

## Thirdparty
* lua-ini (modified)

```shell
sudo luarocks install luacrypto2
```

INFO: http://mkottman.github.io/luacrypto/manual.html#reference