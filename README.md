Wireshark Filters
* All: (tcp.srcport == 2106 || tcp.dstport == 2106 || tcp.srcport == 7777 || tcp.dstport == 7777) && tcp.flags.push == 1
* Login server: (tcp.srcport == 2106 || tcp.dstport == 2106) && tcp.flags.push == 1
* Game server: (tcp.srcport == 7777 || tcp.dstport == 7777) && tcp.flags.push == 1

Dependency
```shell
sudo luarocks install luacrypto2
```

INFO: http://mkottman.github.io/luacrypto/manual.html#reference