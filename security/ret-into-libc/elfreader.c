#include "elfreader.h"

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define die_now(str) do{fprintf(stderr, "%s : %s\n", __func__, str); exit(1); }while(0)

void
lop_display(struct lop_info *ptr)
{
  uint32_t i;
  printf("headers_addr[ehdr = %p, shdr = %p, phdr = %p]\n", ptr->lop_ehdr,
                                                            ptr->lop_shdr,
                                                            ptr->lop_phdr);

  printf("segment_addr[text = %x, data = %x]\n", ptr->lop_textvaddr,
                                                 ptr->lop_datavaddr);

  printf("%d\n", ptr->lop_dynsym_count);
  for(i = 0; i < ptr->lop_dynsym_count; ++i){
    printf("plt_info[name = %s, symbol[type=%d, value=%x, visibility=%d], rel=[offset=%x]\n",
           ptr->lop_plt[i].lop_symname ? ptr->lop_plt[i].lop_symname : "",
           ptr->lop_plt[i].lop_sym->st_info,
		   ptr->lop_plt[i].lop_sym->st_value,
           ptr->lop_plt[i].lop_sym->st_other,
           ptr->lop_plt[i].lop_rel ? ptr->lop_plt[i].lop_rel->r_offset
                                        : 0x00);
           
  }                                                                                                       
}


static int
lop_read_segment_info(struct lop_info *ptr)
{
  int nb_affect = 0;
  uint8_t i;
  Elf32_Phdr *current;
  current = ptr->lop_phdr;
 
  for( i = 0; i <  ptr->lop_ehdr->e_phnum && nb_affect < 2; ++i, ++current){
    if(current->p_type == PT_LOAD){
      if(current->p_flags & PF_X){
        ++nb_affect;
        ptr->lop_textvaddr = current->p_vaddr;
      }
      else if(current->p_flags & PF_W){
        ++nb_affect;
        ptr->lop_datavaddr = current->p_vaddr;
      }
    }
  }
  return !(nb_affect == 2); 
}


static Elf32_Shdr*
lop_get_section_by_type(char *base, uint32_t type)
{
  Elf32_Ehdr *ehdr    = (Elf32_Ehdr *)base;
  Elf32_Shdr *current = (Elf32_Shdr*)((char*)base + ehdr->e_shoff);
  uint16_t i;

  for(i = 0; i < ehdr->e_shnum; ++i, ++current){
    if( type == current->sh_type){
      return current;
    }
  }
  return NULL;
}

Elf32_Shdr*
lop_get_section_by_name(char *base, char *name)
{
		Elf32_Shdr *ret = NULL;
		uint16_t i = 0;
		uint16_t nbsec = 0;
		Elf32_Ehdr *ehdr    = (Elf32_Ehdr *)base;
		Elf32_Shdr *current = (Elf32_Shdr*)((char*)base + ehdr->e_shoff);
		char *sectionnamelist = base + current[ehdr->e_shstrndx].sh_offset;


		nbsec = ehdr->e_shnum;

		for (i = 0; ret == NULL && i < nbsec; ++i, ++current) {
				char *currstr = sectionnamelist + current->sh_name;
				if (!strcmp(name, currstr)) {
						ret = current;
				}
		}
		return ret;
}


static Elf32_Shdr*
lop_get_section_dynstr_tab(char *base, Elf32_Shdr *dyn)
{
  Elf32_Shdr *current = (Elf32_Shdr*)((char*)base + ((Elf32_Ehdr*)base)->e_shoff);
  return current + dyn->sh_link;
}


static Elf32_Rel*
lop_find_rel_by_sym(struct lop_info *ptr, int sind, int ind)
{
  Elf32_Rel  *current;
  Elf32_Shdr *iter = ptr->lop_shdr;
  uint16_t numsec  = ptr->lop_ehdr->e_shnum;
  uint16_t i;

  for( i = 0; i < numsec; ++i, ++iter){
    if(iter->sh_type == SHT_REL && (unsigned)sind == iter->sh_link){
      unsigned int numrel = iter->sh_offset / sizeof(Elf32_Rel);
      unsigned int j;
      current =  (Elf32_Rel*)((char*)ptr->lop_ehdr + iter->sh_offset);
      for( j = 0; j < numrel; ++j, ++current){
        if(ELF32_R_SYM(current->r_info) == (unsigned)ind){
          return current; 
        }
      }
    }
  }
  return NULL;
}


static int
lop_build_plt_table(struct lop_info *ptr,
                    Elf32_Shdr *dyn,
                    Elf32_Shdr *str)
{
  Elf32_Sym *symbol   = 0;
  char      *name     = 0;
  unsigned int num_sym;
  unsigned int i;
  unsigned int sind = dyn - ptr->lop_shdr; 

  num_sym  = dyn->sh_size / sizeof(Elf32_Sym);

  symbol   = (Elf32_Sym*)((char*)ptr->lop_ehdr + dyn->sh_offset);
  name     = (char*)ptr->lop_ehdr + str->sh_offset;

  
  for(i = 0; i < num_sym && i < LOP_MAX_DYNSYM; ++i, ++symbol){
    ptr->lop_plt[i].lop_sym     = symbol;
    ptr->lop_plt[i].lop_symname = name + symbol->st_name;
    ptr->lop_plt[i].lop_rel     = lop_find_rel_by_sym(ptr, sind, i);
  }
  ptr->lop_dynsym_count = i;
  return !i;
}



static int
lop_read_dynsym_section(struct lop_info *ptr)
{
  Elf32_Shdr *dyn = NULL, *str = NULL;
  int ret = 0;
  
  dyn = lop_get_section_by_type((char*)ptr->lop_ehdr, SHT_DYNSYM);
  if(!dyn)
    goto lop_process_dynsym_section_no_dynsym_error;

  str = lop_get_section_dynstr_tab((char*)ptr->lop_ehdr, dyn);
  if(!str)
    goto lop_process_dynsym_section_no_dynstrtab_error;

  ret = lop_build_plt_table(ptr, dyn, str);

  return ret;
    
lop_process_dynsym_section_no_dynsym_error:
  die_now("no dynamic symbol section found");
lop_process_dynsym_section_no_dynstrtab_error:
  die_now("no string table for symbol found");
}


int
lop_init_info(struct lop_info *ptr, char *base)
{
  
  int ret;
  memset(ptr, 0, sizeof(*ptr));

  ptr->lop_ehdr = (Elf32_Ehdr*)base;
  ptr->lop_phdr = (Elf32_Phdr*)(base + ptr->lop_ehdr->e_phoff);
  ptr->lop_shdr = (Elf32_Shdr*)(base + ptr->lop_ehdr->e_shoff);
  
  ret = lop_read_segment_info(ptr);
  if(ret){
    die_now("unable to read process segment");
  }
  ret = lop_read_dynsym_section(ptr);
  if(ret){
    die_now("unable to read plt information");
  }
  return 0;
}


Elf32_Sym*
lop_get_dynsym_by_name(char *base, char *name)
{
  Elf32_Shdr  *dyn = NULL,
			  *str = NULL;
  Elf32_Sym   *currsym  = NULL;
  char        *currname = NULL;
  unsigned int nbsym    = 0, i;

  dyn = lop_get_section_by_type(base, SHT_DYNSYM);
  if(!dyn)
    return NULL;

  str =  lop_get_section_dynstr_tab(base, dyn);
  if(!str)
	return NULL;

  currsym = (Elf32_Sym*) base + dyn->sh_offset;

  nbsym   = dyn->sh_size/sizeof(Elf32_Sym);
  for( i = 0; i< nbsym; ++i, ++currsym){
    currname = base + str->sh_offset + currsym->st_name;
	if(strcmp(name, currname) == 0){
		return currsym;
	}
  }
  return NULL;
}
