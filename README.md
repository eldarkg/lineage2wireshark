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
### Find client (C1-C5 with ProtocolVersion 785a) static BlowFish private key
```
system/engine.dll -> Ghidra -> Search call InitializeBlowfish -> Arg 2 -> Key
```
* For C1: need move last 8 bytes (without last 0x00) of private key to begin.
* Try all found keys and find one valid.

### XOR Key
Found by selection based on known data of the first crypted packet
(for example packet `RequestAuthLogin`).

## Utility
Convert binary to image (FIXME: not tested)
```sh
convert -depth 8 -size 16x16+0 gray:in.bin out.png
```

## Dependencies
* Wireshark 4.4.8 (last tested)
* Lua 5.4
* luarocks
* lua-iconv
* luaossl

### Install dependencies
```sh
sudo apt install wireshark

sudo apt install lua5.4

# Build and install luarocks
git clone https://github.com/luarocks/luarocks
cd luarocks
./configure
make
sudo checkinstall

sudo luarocks install lua-iconv
sudo luarocks --dev install luaossl
```

## Thirdparty (builtin)
* lua-ini (modified)

## FAQ
### Fix Error 0308010C Digital Envelope Routines Unsupported
```sh
openssl version -d  # dir
# Edit $(dir)/openssl.cnf
# Under [provider_sect] add the following line:
# legacy = legacy_sect
# [default_sect]
# activate = 1
# [legacy_sect]
# activate = 1
openssl list -providers # check legacy exist
```
INFO: https://www.iclarified.com/92617/how-to-fix-error-0308010c-digital-envelope-routines-unsupported

