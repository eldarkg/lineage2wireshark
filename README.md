Wireshark Filters
* All: (tcp.srcport == 2106 || tcp.dstport == 2106 || tcp.srcport == 7777 || tcp.dstport == 7777)
* Login server: (tcp.srcport == 2106 || tcp.dstport == 2106)
* Game server: (tcp.srcport == 7777 || tcp.dstport == 7777)
* Show only lineage packets: && tcp.len != 0
* Show only tcp push: && tcp.flags.push == 1 (NO USE!!!)

Dependency
* Wireshark 4.2.2 (other not tested)
* Lua 5.2
* luarocks
* luacrypto2

```shell
sudo luarocks install luacrypto2
```

INFO: http://mkottman.github.io/luacrypto/manual.html#reference