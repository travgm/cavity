#ifndef _CAVITY_H
#define _CAVITY_H 1

#define FRACTION_LEN 1024
#define BUFFER_SIZE  16384
#define MAX_FRACTIONS 1000

#define MMAP_PARAMS PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS

typedef struct
{ 
  unsigned char magic;
  unsigned char hash[EVP_MAX_MD_SIZE];
  unsigned int hash_len;
  unsigned int position;
  size_t fraction_len;
} FRACT_HEADER;

typedef struct {
    char filename[256];
    unsigned int position;
} FractionInfo;


#endif
