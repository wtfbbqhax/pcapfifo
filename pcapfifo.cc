#include <pcap.h>

#include <vector>

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/time.h>
#include <time.h>

pcap_dumper_t *put;

void write_packet(uint8_t*, pcap_pkthdr *hdr, uint8_t *data) 
{
    pcap_dump((uint8_t*)put, hdr, data);
    return;
}

int main(int argc, char *argv[])
{
    std::vector<const char*> inputs;

    if( argc <= 2 ) {
        fprintf(stderr, "Not enough arguments\n");
        exit(1);
    }

    for (int i = 1; i < argc-1; ++i )
    {
        inputs.emplace_back(argv[i]);
        printf("%s\n", argv[i]);
    }

    pcap_t *_cap = pcap_open_dead(DLT_EN10MB, 65535);
    put = pcap_dump_open(_cap, argv[argc-1]);
    if( !put )
    {
        fprintf(stderr, "Failed to open output %s\n", argv[argc-1]);
        exit(1);
    }

    for ( auto &fn : inputs )
    {
        char errbuf[PCAP_ERRBUF_SIZE];
        pcap_t* pin = pcap_open_offline(fn, errbuf);
        if( !pin ) {
            fprintf(stderr, "fatal: %s: %s\n", argv[1], errbuf);
            continue;
        }

        int err = pcap_loop(pin, -1, (pcap_handler)write_packet, NULL); 
        if( err == -1 ) {
            fprintf(stderr, "fatal: %s:%s\n", fn, pcap_geterr(pin));
            continue;
        }

        pcap_close(pin);
    }

    pcap_dump_close(put);
    pcap_close(_cap); // Move this as early as possible

    return 0;
}
