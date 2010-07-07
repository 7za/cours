#ifndef LINUX_OBJ_PARSER
#define LINUX_OBJ_PARSER

#include <libelf.h>


struct lop_dynsym
{
  Elf32_Sym  *lop_sym;
  Elf32_Rel  *lop_rel;
  char       *lop_symname;
};

#define LOP_MAX_DYNSYM 1024*4

struct lop_info
{
  Elf32_Ehdr *lop_ehdr;
  Elf32_Phdr *lop_phdr;
  Elf32_Shdr *lop_shdr;
  Elf32_Addr  lop_textvaddr;
  Elf32_Addr  lop_datavaddr;
  Elf32_Addr  lop_gotoffset;

  struct   lop_dynsym lop_plt[LOP_MAX_DYNSYM];
  uint32_t lop_dynsym_count;  
};

int
lop_init_info(struct lop_info *ptr, char *base);

void
lop_display(struct lop_info *ptr);


Elf32_Shdr*
lop_get_section_by_name(char *base, char *name);


#endif

