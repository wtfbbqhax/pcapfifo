# pcapfifo
Spool pcaps through a pipe

## Whats it good for?

Tools that support readback via `pcap_open_offline()` etc.. will stop processing
packets once EOF occurs, by feeding pcap's through a pipe this can be avoided.

### Like what? 
 - [Snort](https://www.snort.org)
 - [tcpdump](http://www.tcpdump.org)
 - etc.. 

## Compile
```bash
~ ❯❯❯ c++ -std=c++11 -lpcap -o pcapfifo pcapfifo.cc
```
## Run
```bash
~ ❯❯❯ mkfifo pcap.fifo
~ ❯❯❯ ./pcapfifo in.pcap <in2...N.pcap> pcap.fifo
~ ❯❯❯ snort -c snort.lua -Acmg -r pcap.fifo
```

