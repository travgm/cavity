/**
 * builder.c
 * This code is based on smelly_vx fractioned cavity loader published in
 * vxug vol 1 zine.
 *
 * This file takes an output name and a directory and reassembles a file
 * that was broken up by breaker.c. We decrypt, verify hash and write the
 * file to the current directory.
 *
 * We also decrypt each fraction (not including the header) with AES-256
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
#include <errno.h>
#include <openssl/evp.h>

#include "cavity.h"

int
aes_init (unsigned char *key_data, int key_data_len, unsigned char *salt,
          EVP_CIPHER_CTX * d_ctx);

unsigned char *
aes_decrypt (EVP_CIPHER_CTX * e, unsigned char *ciphertext, int *len);

int
compare_fractions (const void *a, const void *b)
{
  return ((FractionInfo *) a)->position - ((FractionInfo *) b)->position;
}

void
process_files (const char *out_name, const char *directory)
{
  FILE *out_file = NULL;
  DIR *dir;
  struct dirent *entry;
  EVP_MD_CTX *md_ctx;
  const EVP_MD *md;
  unsigned char calculated_hash[EVP_MAX_MD_SIZE];
  unsigned int md_len;
  unsigned char original_hash[EVP_MAX_MD_SIZE];
  int hash_set = 0;
  FractionInfo fractions[MAX_FRACTIONS];
  int fraction_count = 0;

  dir = opendir (directory);
  if (dir == NULL)
    {
      perror ("Invalid directory");
      exit (1);
    }

  // First, read all fraction files and store their information
  while ((entry = readdir (dir)) != NULL)
    {
      if (entry->d_type == DT_REG)
	{
	  char path[1024];
	  snprintf (path, sizeof (path), "%s/%s", directory, entry->d_name);

	  FILE *frac_file = fopen (path, "rb");
	  if (frac_file == NULL)
	    {
	      perror ("Error opening fraction file");
	      continue;
	    }

	  FRACT_HEADER fhdr;
	  if (fread (&fhdr, sizeof (FRACT_HEADER), 1, frac_file) != 1)
	    {
	      perror ("Error reading fraction header");
	      fclose (frac_file);
	      continue;
	    }

	  if (fhdr.magic != 0x69)
	    {
	      printf ("Not a fractioned file: %s\n", path);
	      fclose (frac_file);
	      continue;
	    }

	  strcpy (fractions[fraction_count].filename, path);
	  fractions[fraction_count].position = fhdr.position;
	  fraction_count++;

	  fclose (frac_file);
	}
    }

  // Sort fractions by position
  qsort (fractions, fraction_count, sizeof (FractionInfo), compare_fractions);

  // Now process fractions in order
  out_file = fopen (out_name, "wb");
  if (out_file == NULL)
    {
      perror ("Error creating out file");
      exit (1);
    }

  md = EVP_sha256 ();
  md_ctx = EVP_MD_CTX_new ();
  EVP_DigestInit_ex (md_ctx, md, NULL);
  unsigned char salt[8];

  for (int i = 0; i < fraction_count; i++)
    {
      EVP_CIPHER_CTX *de = EVP_CIPHER_CTX_new ();

      FILE *frac_file = fopen (fractions[i].filename, "rb");
      if (frac_file == NULL)
	{
	  perror ("Error opening fraction file");
	  continue;
	}

      FRACT_HEADER fhdr;
      if (fread (&fhdr, sizeof (FRACT_HEADER), 1, frac_file) != 1)
	{
	  perror ("Error reading fraction header");
	  fclose (frac_file);
	  continue;
	}

      if (i == 0)
	{
	  memcpy (original_hash, fhdr.hash, EVP_MAX_MD_SIZE);
	  // We need our salt for decryption
	  memcpy (salt, fhdr.hash, 4);
	  memcpy (salt + 4, fhdr.hash + strlen ((char *)fhdr.hash) - 4, 4);
	  hash_set = 1;
	}

      aes_init (original_hash, strlen ((char *)original_hash),
		(unsigned char *) &salt, de);

      char frac_buffer[FRACTION_LEN];
      size_t bytes_read =
	fread (frac_buffer, 1, fhdr.fraction_len, frac_file);
      if (bytes_read != fhdr.fraction_len)
	{
	  perror ("Error reading fraction data");
	  fclose (frac_file);
	  continue;
	}
      char *de_frac_buffer;
      int len = strlen ((char *) frac_buffer);
      de_frac_buffer = (char *)aes_decrypt (de, (unsigned char *)frac_buffer, &len);
      if (fwrite (de_frac_buffer, 1, bytes_read, out_file) != bytes_read)
	{
	  perror ("Error writing to output file");
	  fclose (frac_file);
	  exit (1);
	}

      EVP_DigestUpdate (md_ctx, frac_buffer, bytes_read);
      EVP_CIPHER_CTX_free(de);
      fclose (frac_file);
    }

  fclose (out_file);
  closedir (dir);

  EVP_DigestFinal_ex (md_ctx, calculated_hash, &md_len);
  EVP_MD_CTX_free (md_ctx);

  if (!hash_set)
    {
      printf ("Error: No fractions found or unable to read original hash.\n");
      exit (1);
    }

  if (memcmp (original_hash, calculated_hash, md_len) == 0)
    {
      printf ("Hash verification successful. File reassembled correctly.\n");
    }
  else
    {
      printf
	("Hash verification failed. Reassembled file may be corrupted.\n");
      exit (1);
    }
}

int
aes_init (unsigned char *key_data, int key_data_len, unsigned char *salt,
	  EVP_CIPHER_CTX * d_ctx)
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

  EVP_CIPHER_CTX_init (d_ctx);
  EVP_EncryptInit_ex (d_ctx, EVP_aes_256_cbc (), NULL, key, iv);

  return 0;
}

unsigned char *
aes_decrypt (EVP_CIPHER_CTX * e, unsigned char *ciphertext, int *len)
{
  int p_len = *len, f_len = 0;
  unsigned char *plaintext = malloc (p_len);

  EVP_DecryptInit_ex (e, NULL, NULL, NULL, NULL);
  EVP_DecryptUpdate (e, plaintext, &p_len, ciphertext, *len);
  EVP_DecryptFinal_ex (e, plaintext + p_len, &f_len);

  *len = p_len + f_len;
  return plaintext;
}

int
main (int argc, char *argv[])
{
  process_files (argv[1], argv[2]);

  return 0;
}
