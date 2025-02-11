Cavity
===============

The first implementation to implement the improvements on the Fractioned Cavity Loader in VXUG vol 1

A big thanks to vrzh and elfmaster for all their input and guidance.

Improvements Implemented:
- Hashing of the executable file and we store the original hash in the fraction #0 header.
- Salt is computed from header
- Encrypting each fraction with AES-256
- Validating that each file is actually a fraction
- You can put it to any directory (builder) and it verifies files and puts them in the right order by qsort
- We are currently writing the fractions to a buffer and mmap() them to RWX memory to execute. **WORK IN PROGRESS**

Written by Travis Montoya "travgm" (hexproof.sh)

### Implementation

A big shoutout to smelly_vx for the writeup on a nice implementation of the fractioned cavity
technique in the vxug vol1 zine. While the original was written for windows I decided to write this 
for Linux and implement a few of the suggested improvements. I didn't add the loader, which I may at 
a later point as I have some neat ideas for that. 

**Preface**

Make note that we want to avoid using dependencies in scenarios other than PoC types. So this just shows
the process where we could write our own encryption/obfuscation and utilize this same process. The
route I chose for this is by nowhere perfect, but documented my initial thoughts through the process. As
I make improvements and updates I will update the process as we go along.

**How it works**

It works pretty simply, it takes an input file and a directory (its created if not found) and breaks
the file up into 1024 byte (1KB) "fractions" to keep track of the data needed for re-assembly we create
a FRACT_HEADER which holds some information we need and the builder reassembles it with that data:


**The Breaker**

```
typedef struct
{ 
  unsigned char magic;
  unsigned char hash[EVP_MAX_MD_SIZE];
  unsigned int hash_len;
  unsigned int position;
  size_t fraction_len;
} FRACT_HEADER;
```

We set a magic byte in our case we use 0x69 that will let us verify that this is a fractioned file and
we store the hash of the ENTIRE executable in Fraction #0 and the hash length (which should be 32) and
the position allows us during reassembly to know where to add it in the reassembly process, lastly the
fraction_len holds the length of the fraction so we know how many bytes are meant to be read and should
match during reassembly.

During the break process we read the input file in the 1024 byte chunks and we then encrypt it utilizing
the hash created from the entire file. If you read the code can you take a guess how we compute the salt
for encryption/decryption? We then write the header first and then the encrypted data to the file. The
last fraction is not always 1024 bytes.

This by default creates output files called `fraction_*.bin` numbered 0 to xxx numbering the order, but
we could rename these as the fract header holds the information we need and the builder looks at that to
reassemble the file. They can also be thrown into any directory. This would allow for the fractioned files
to be hidden amongst thousands of files if wanted.

**The Builder**

The builder does alot more checking and work to reassemble the files, remember we need th EXACT information
that we encrypted the fractions with to be able to decrypt them. If the header is tampered with in any way
with at least the hash or hash_len even fraction_len it will fail. We use FRACT_HEADER in the builder and we
also use FractionInfo

```
typedef struct {
    char filename[256];
    unsigned int position;
} FractionInfo;
```

When the builder is executed and we begin to process a directory we read size of FRACT_HEADER to read the
header of the file in and check for the magic byte 0x69, if it's not we close the file and continue searching.
If we find a fractioned file we add it to our FractionInfo array and we set the position of the FractionInfo
structure to the position in the FRACT_HEADER that we read in. This becomes useful later. Once we are done reading
all the files of the directory in and have all fractions (hopefully). This could be an improvement would be to verify
we have all the fractions. Next we use `qsort` to sort our fractions based on the position so we have 0-xxx.

Then we start processing each fraction by reading in the header and checking if it is the first fraction so we can
get our hash and hash_len to generate our salt and pass to `aes_init` and begin reading the data in and decrypting
each fraction. As each fraction is decrypted we update or digest to compute our `calculated_hash` at the end of 
processing all fractions. We compare the `original_hash` that was read from fraction #0 and the `calculated_hash` that
was calculated during decryption.

We end by closing closing the file and we now have a reassembled file that was fractioned.

**The Loader**

The breaker/builder hold the techniques used for hashing/encryption so you could still utilize the original method of
how the loader worked by downloading the fractions and then decrypting them. Depending on the use case you still could
potentionally map them to the RWX memory and make it memory resident. 

I started writing an assembly based loader that can load a static pie compiled elf binary. The loader combines the builder
to rebuild the fractions. It will first decrypt each fraction and append it to the buffer the same way the builder does, but
instead of writing it to a file to be executed it loads it into memory to be executed. The stloader.asm code will be released
later this month once it's been completed.

**Closing**

If you see an errors/improvements or have suggestions feel free to send me an e-mail at trav@hexproof.sh or send me a
message on discord.

