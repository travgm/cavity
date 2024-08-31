/**
 * breaker.c
 * This code is based on smelly_vx fractioned cavity loader published in
 * vxug vol 1 zine.
 *
 * Breaks a file into 1024 byte chunks, the first fraction contains a
 * hash of the original file. When we put it back together we can verify
 * the hashes to make sure it was reassembled properly.
 *
 * We also encrypt each fraction (not including the header) with AES-256
 * encryption. The Encryption/Decryption used here is the sample code
 * found:
 * https://github.com/saju/misc/blob/master/misc/openssl_aes.c
 *
 * Travis M. <trav@hexproof.sh>
 * Website: hexproof.sh
 *
 * Use the Makefile to compile.. It makes it easy.
 *
**/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <sys/stat.h>
#include <errno.h>
#include <openssl/evp.h>
#include <openssl/aes.h>

#include "cavity.h"

int aes_init (unsigned char *key_data, int key_data_len, unsigned char *salt, EVP_CIPHER_CTX * e_ctx);
unsigned char *aes_encrypt_frac(EVP_CIPHER_CTX * e, unsigned char *plaintext, int *len);

void
create_fraction (const char *file_name, const char *output_directory)
{
  EVP_MD_CTX *md_ctx;
  const EVP_MD *md;
  unsigned char md_value_hash[EVP_MAX_MD_SIZE];
  unsigned int md_len;
  FILE *in_file = NULL;
  unsigned int fraction_count = 0;
  char fraction_name[256];
  size_t ret;

  printf ("Creating fractions of %s\n", file_name);

  if ((in_file = fopen (file_name, "rb")) == NULL)
    {
      perror ("Error opening input file");
      exit (errno);
    }

  struct stat st = { 0 };
  if (stat (output_directory, &st) == -1)
    {
      if (mkdir (output_directory, 0700) == -1)
	{
	  perror ("Error creating output directory");
	  exit (errno);
	}
    }

  unsigned int salt[8];
  unsigned char buffer[BUFFER_SIZE];
  md = EVP_sha256 ();
  md_ctx = EVP_MD_CTX_new ();
  EVP_DigestInit_ex (md_ctx, md, NULL);
  while ((ret = fread (buffer, 1, BUFFER_SIZE, in_file)) > 0)
    {
      EVP_DigestUpdate (md_ctx, buffer, ret);
    }
  EVP_DigestFinal_ex (md_ctx, md_value_hash, &md_len);
  EVP_MD_CTX_free (md_ctx);

  memcpy (salt, md_value_hash, 4);
  memcpy (salt + 4, md_value_hash + md_len - 4, 4);

  rewind (in_file);

  unsigned char frac_buffer[FRACTION_LEN];
  while ((ret = fread (frac_buffer, 1, FRACTION_LEN, in_file)) > 0)
    {
      FILE *out_file;
      FRACT_HEADER fhdr = { 0 };
      EVP_CIPHER_CTX *en = EVP_CIPHER_CTX_new ();

      aes_init (md_value_hash, md_len, (unsigned char *)&salt, en);

      fhdr.magic = 0x69;
      fhdr.position = fraction_count;
      fhdr.fraction_len = ret;
      if (fraction_count == 0)
	{
	  memcpy (fhdr.hash, md_value_hash, md_len);
	}

      snprintf (fraction_name, sizeof (fraction_name), "%s/frac_%u.bin",
		output_directory, fraction_count);
      printf ("Fraction #%u %s\n", fraction_count, fraction_name);
      if ((out_file = fopen (fraction_name, "wb")) == NULL)
	{
	  perror ("Error creating fraction file");
	  exit (errno);
	}

      if (fwrite (&fhdr, sizeof (FRACT_HEADER), 1, out_file) != 1)
	{
	  perror ("Error writing fraction header");
	  exit (errno);
	}

      unsigned char *en_buffer;
      int len = strlen((char *)frac_buffer);
      en_buffer = aes_encrypt_frac (en, frac_buffer, &len);
      if (fwrite (en_buffer, 1, ret, out_file) != ret)
	{
	  perror ("Error writing fraction data");
	  exit (errno);
	}

      EVP_CIPHER_CTX_free(en);
      fclose (out_file);
      fraction_count++;
    }

  fclose (in_file);
  printf ("Created %u fractions\n", fraction_count);
}

int
aes_init (unsigned char *key_data, int key_data_len, unsigned char *salt,
	  EVP_CIPHER_CTX * e_ctx)
{
  int i, nrounds = 5;
  unsigned char key[32], iv[32];

  i =
    EVP_BytesToKey (EVP_aes_256_cbc (), EVP_sha1 (), salt, key_data,
		    key_data_len, nrounds, key, iv);
  if (i != 32)
    {
      printf ("Key size is %d bits - should be 256 bits\n", i);
      return -1;
    }

  EVP_CIPHER_CTX_init (e_ctx);
  EVP_EncryptInit_ex (e_ctx, EVP_aes_256_cbc (), NULL, key, iv);

  return 0;
}

unsigned char *
aes_encrypt_frac(EVP_CIPHER_CTX * e, unsigned char *plaintext, int *len)
{
  int c_len = *len + AES_BLOCK_SIZE, f_len = 0;
  unsigned char *ciphertext = malloc (c_len);

  EVP_EncryptInit_ex (e, NULL, NULL, NULL, NULL);
  EVP_EncryptUpdate (e, ciphertext, &c_len, plaintext, *len);
  EVP_EncryptFinal_ex (e, ciphertext + c_len, &f_len);

  *len = c_len + f_len;

  return ciphertext;
}

int
main (int argc, char *argv[])
{
  if (argc < 2)
    {
      printf ("nope!\n");
      return 1;
    }

  create_fraction (argv[1], argv[2]);

  return 0;
}
