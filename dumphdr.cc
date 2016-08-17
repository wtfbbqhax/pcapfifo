#include <pcap.h>

#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>

int main(int argc, char *argv[])
{
    if( argc <= 1 )
    {
        fprintf(stderr, "Not enough arguments\n");
        exit(1);
    }

    int pin = open(argv[1], O_RDONLY);
    if ( pin == -1 )
    {
        fprintf(stderr, "Cannot open %s: %s\n", argv[1], strerror(errno));
        exit(1);
    }

    pcap_file_header global;
    int bytes = read(pin, &global, sizeof(global));
    if ( bytes != sizeof(global) )
    {
        fprintf(stderr, "Failed to read pcap_file_header_t\n");
        close(pin);
        exit(1);
    }
    
    printf("global.magic         = 0x%X;\n"
           "global.version_major = %d;\n"
           "global.version_minor = %d;\n"
           "global.thiszone      = %d;\n"
           "global.sigfigs       = %d;\n"
           "global.snaplen       = %d;\n"
           "global.linktype      = %d;\n",
           global.magic,
           global.version_major,
           global.version_minor,
           global.thiszone,
           global.sigfigs,
           global.snaplen,
           global.linktype);

    pcap_pkthdr pkthdr;
#ifdef __APPLE__
    bytes = read(pin, &pkthdr, sizeof(pkthdr) - sizeof(pkthdr.comment));
    if ( bytes != sizeof(pkthdr) - sizeof(pkthdr.comment) )
#else
    bytes = read(pin, &pkthdr, sizeof(pkthdr) - sizeof(pkthdr.comment));
    if ( bytes != sizeof(pkthdr) )
#endif
    {
        fprintf(stderr, "Failed to read pcap_pkthdr: %s\n", strerror(errno));
        close(pin);
        exit(1);
    }
    
    printf("pkthdr.ts_sec        = %ld;\n"
           "pkthdr.ts_usec       = %d;\n"
           "pkthdr.incl_len      = %u;\n"
           "pkthdr.orig_len      = %u;\n",
           pkthdr.ts.tv_sec,
           pkthdr.ts.tv_usec,
           pkthdr.caplen,
           pkthdr.len);

    close(pin);
    return 0;
}
