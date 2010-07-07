#include "elfreader.h"
#include <sys/mman.h>
#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>

struct lib_desc_t
{
		int		lib_fd;
		char	*lib_base;
		size_t	lib_len;
		struct lop_info lib_info;
};


static int
map_parser_init_lib_hooker(struct lib_desc_t *lib, char *filename)
{
		int ret;
	    struct stat _stat;
		
		ret = stat(filename, &_stat);
		if(ret)
				goto map_parser_init_lib_hooker_stat_error;

		lib->lib_fd = open(filename, O_RDONLY, 0644);
		if(lib->lib_fd < 0)
				goto map_parser_init_lib_hooker_open_error;

		lib->lib_base = mmap(0, _stat.st_size, PROT_READ, MAP_PRIVATE, lib->lib_fd, 0);
		if(lib->lib_base == MAP_FAILED)
				goto map_parser_init_lib_hooker_mmap_failed;

		lib->lib_len = _stat.st_size;
		lop_init_info(&lib->lib_info, lib->lib_base);
		return 0;

map_parser_init_lib_hooker_mmap_failed:
		close(lib->lib_fd);
map_parser_init_lib_hooker_open_error:
map_parser_init_lib_hooker_stat_error:
		perror("initlib : ");
		return -1;
}

static void
map_parser_exit_lib_hooker(struct lib_desc_t *lib)
{
		close(lib->lib_fd);
	    munmap(lib->lib_base, lib->lib_len);
}


int main()
{
	struct lib_desc_t lib;
	unsigned system_offset = 0;
	unsigned binsh_offset  = 0;
	printf("search system offset\n");
	printf("search /bin/sh string offset\n");
	if(map_parser_init_lib_hooker(&lib, "/lib/libc.so.6")){
			return 0;
	}
	
	printf("%d\n", lib.lib_info.lop_dynsym_count);
	lop_display(&lib.lib_info);

	Elf32_Shdr *rodata = lop_get_section_by_name(lib.lib_base, ".rodata");
	if(rodata){
			char *start = lib.lib_base + rodata->sh_offset;
			char *end   = start + rodata->sh_size;
			char *walk = start;
			while(start){
				printf("%d : %s\n", (start - lib.lib_base) , start);
				start = strchr(start, '\0');
				if(start < end) start++;
			}

	}
	
	map_parser_exit_lib_hooker(&lib);

	return 0;

}



