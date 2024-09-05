/** ulexec.c
 *  Travis Montoya <trav@hexproof.sh>
 *
 *  This is part of the fractioned cavity loader project. This file
 *  handles executing an ELF64 executable from memory.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <elf.h>

#define STACK_SIZE 1024 * 32
#define MEMORY_MAP "/proc/self/maps"
#define MEMORY_LINE "%lx-%lx"

typedef struct {
	int argc;
	char **argv;
	char **envp;
} ULEXEC_ENV;

typedef struct {
	char *buffer;
	size_t buffer_len;
	int use_interp;
	int argc;
	ULEXEC_ENV *args;
} ULEXEC_INFO;

int
ulexec_verify_elf64(ULEXEC_INFO *info) {
	Elf64_Ehdr ehdr = NULL;
	if (info == NULL) {
		return -1;
	}

	memcpy(&ehdr, info->buffer, sizeof(ehdr));
        if ((strncmp (ehdr.e_ident, ELFMAG, 4) != 0)
      		|| ehdr.e_ident[EI_CLASS] != ELFCLASS64) {
			return -1;
		}
	}
	return 0;
}

int 
ulexec_check_interp_required(char *buffer) {

}

int
ulexec_setup_memory() {
	FILE *fd = fopen(MEMORY_MAP, "r");
	if (fd == NULL) {
		return -1;
	}

	unsigned long addr_start;
	unsigned long addr_end;
	char map_line[256];
	int cnt = 0;
	while(fgets(map_line, sizeof(map_line), fd) && cnt < 3) {
		if (sscanf(map_line, MEMORY_LINE, &addr_start, &addr_end) == 2) {
			size_t addr_len = addr_end - addr_start;
			memset((void *)addr_start, 0, addr_len);
		}	
	}
	return 0;
}

int 
ulexec(ULEXEC_INFO *info, ULEXEC_ENV *env) {
	Elf64_Ehdr *ehdr;
	Elf64_Phdr *phdr;

	int use_interp = check_interp_required(&info);


	/**
	 * Step 1. Preserve arguments
	 */
	void *arg_table = mmap(NULL, 4096, PROT_READ | PORT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (arg_table == MAP_FAILED) {
		return -1;
	}
	info>args->argc = env->argc;
	// preserve addresses of argv and envp (so we know where to restore them later)
	info->args->argv = (char **)((char *)arg_table + sizeof(ULEXEC_ENV));
	info->args->envp = (char **)((char *)info->args->envp + env->argc * sizeof(char *));

	// Copy actual command line arguments
	for(int i = 0; i < env->argc; ++) {
		info->args->argv[i] = strdup(env->argv[i]);
	}
	for(int i = 0; env->envp[i] != NULL; ++i) {
		info->args->envp[i] = strdup(env->envp[i]);
	}

	/**
	 * Step 2. Clean memory of calling process (text, data, heap)
	 */
	int ret = ulexec_setup_memory();
	if (ret != 0) {
		return -1;
	}

         
}

ULEXEC_INFO *
ulexec_init_info(char *buffer, size_t buffer_len) {
	ULEXEC_INFO *ul_info = (ULEXEC_INFO *)malloc(sizeof(ULEXEC_INFO));
		
	memcpy(ul_info->buffer, buffer, buffer_len);
	ul_info->buffer_len = buffer_len;

	return ul_info;	
}

int 
ulexec_free_info(ULEXEC_INFO *info) {
	if ( == NULL) {
		return -1;
	}

	free(info);
}

