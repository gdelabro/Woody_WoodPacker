#include "../woody.h"

char		*payload2 = "\x53\x51\x52\x57\x56\x41\x50\x41\x51\x41\x52\x41\x53\x41\x54\x41\x55\x41\x56\x41\x57\x4c\x8d\x05\xe4\xff\xff\xff\x48\xb8\x11\x11\x11\x11\x11\x11\x11\x11\x49\x29\xc0\xbf\x01\x00\x00\x00\x48\xbe\x59\x2e\x2e\x2e\x2e\x0a\x00\x00\x56\x48\xbe\x2e\x2e\x2e\x2e\x57\x4f\x4f\x44\x56\x48\x89\xe6\xba\x0e\x00\x00\x00\xb8\x01\x00\x00\x00\x0f\x05\x48\x83\xc4\x10\x4c\x89\xc0\x41\x5f\x41\x5e\x41\x5d\x41\x5c\x41\x5b\x41\x5a\x41\x59\x41\x58\x5e\x5f\x5a\x59\x5b\xff\xe0";
char		*payload_end2 = "";
uint32_t	payload_size;
uint32_t	payload_mem_size;

void	show_section(Elf64_Shdr *shdr, char *sct_names, int nb)
{
	ft_printf("section %lld:\n\tname %lld: %s\n\ttype: %lld\n\tflags: %.8llb\n\taddr: %.8llp\n\toffset: %.8llp\n\tsize: %llx\n\tlink: %lld\n\tinfo: %lld\n\taddralign: %lld\n\tentsize: %lld\n",
	nb, shdr->sh_name, sct_names + shdr->sh_name, shdr->sh_type, shdr->sh_flags, shdr->sh_addr,
	shdr->sh_offset, shdr->sh_size, shdr->sh_link, shdr->sh_info, shdr->sh_addralign, shdr->sh_entsize);
}

int		align(uint64_t nb, int alignement)
{
	uint64_t	res;

	res = (alignement - nb % alignement) % alignement;
	return (res);
}

void	modify_sections(void *ptr, Elf64_Shdr *shdr_base, int shnum, uint32_t index, elf_info *info)
{
	int 		i;
	int 		i2;
	Elf64_Shdr	*shdr;
	char		*sct_names;
	char		*name;
	uint32_t	nb;

	shdr = shdr_base + index;
	check_address(shdr + 1);
	check_address(shdr_base + shnum);
	sct_names = ptr + shdr->sh_offset;
	check_address(sct_names);
	info->text = NULL;
	i = -1;
	while (++i < shnum)
	{
		shdr = shdr_base + i;
		check_address((void*)shdr + sizeof(*shdr));
		name = sct_names + shdr->sh_name;
		check_address(name);
	ft_printf("{red}\n");
		show_section(shdr, sct_names, i);
		if (shdr->sh_offset >= info->seg->p_offset + info->seg->p_filesz && ft_strcmp(".bss", name))
		{
			shdr->sh_addr ? shdr->sh_addr += info->bits_added : 0;
			shdr->sh_offset += info->bits_added;
		}
		if (!ft_strcmp(".bss", name))
		{
			//shdr->sh_flags = SHF_EXECINSTR & SHF_ALLOC & SHF_WRITE;
			//shdr->sh_type = SHT_PROGBITS;
			//shdr->sh_size += payload_mem_size + align(shdr->sh_size, 16);
		}
	}
}

void	modify_program_header(void *ptr, elf_info *info)
{
	Elf64_Ehdr	*ehdr;
	Elf64_Phdr	*phdr;
	int			i;
	int			filled;

	ehdr = ptr;
	phdr = ptr + ehdr->e_phoff;
	check_address(phdr + 1);
	check_address(phdr + ehdr->e_phnum);
	ft_printf("PROGRAM HEADERS:\n");
	i = -1;
	filled = 0;
	info->seg = NULL;
	while (++i < ehdr->e_phnum)
	{
		ft_printf("header %d:\n\ttype: %x\n\tflags: %x\n\toffset: %x\n\tvaddr: %x\n\tpaddr: %x\n\tfilesz: %x\n\tmemsz: %x\n\talign: %x\n",
		i, phdr->p_type, phdr->p_flags, phdr->p_offset, phdr->p_vaddr, phdr->p_paddr, phdr->p_filesz, phdr->p_memsz, phdr->p_align);
		if (phdr->p_type == 1)
			filled++;
		if (phdr->p_type == 1 && filled == 1)
			phdr->p_flags = PF_R | PF_W | PF_X;
		else if (phdr->p_type == 1 && filled == 2)
		{
			phdr->p_flags = PF_R | PF_W | PF_X;
			info->seg = phdr;
			info->new_entry = phdr->p_vaddr + phdr->p_memsz;
			info->bss_size = phdr->p_memsz - phdr->p_filesz;
			info->new_code_offset = phdr->p_offset + phdr->p_filesz;
		}
		else if (info->seg && phdr->p_offset > info->seg->p_offset + info->seg->p_filesz)
		{
			phdr->p_offset += info->bits_added;// + payload_mem_size
			phdr->p_paddr ? phdr->p_paddr += info->bits_added : 0;// + payload_mem_size
			phdr->p_vaddr ? phdr->p_vaddr += info->bits_added : 0;// + payload_mem_size
		}
		phdr += 1;
	}
	if (!info->seg)
		ft_quit("coudn't find the data segement");
}

void	write_binary(void *ptr, Elf64_Ehdr 	*ehdr, elf_info	*info)
{
	int		fd;
	char	alignement[16] = "\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90";
	int		size_begining;
	void	*end_file;
	int		i;

	fd = open("woody", O_WRONLY | O_CREAT | O_TRUNC, S_IRWXU | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH);
	if (fd < 0)
		ft_quit("can't open new file woody");
	ehdr->e_shoff += info->bits_added;
	ehdr->e_entry = info->new_entry;
	info->seg->p_filesz += info->bits_added;
	info->seg->p_memsz = info->seg->p_filesz;
	size_begining = info->new_code_offset;
	write(fd, ptr, size_begining);
	i = -1;
	while (++i < info->bss_size)
		write(fd, "\0", 1);
	write(fd, payload2, payload_size);
	write(fd, alignement, align(payload_size, 16));
	end_file = ptr + size_begining;
	write(fd, end_file, (size_t)(get_ptr_end() - end_file));
	close(fd);
}

void	rebuild_binary(void *ptr)
{
	Elf64_Ehdr	*ehdr;
	elf_info	info;
	char		*payload_to_modify;

	if (!is_in_address(ptr + sizeof(*ehdr)))
		ft_quit("file too small");
	ehdr = ptr;
	if (ft_strncmp(ehdr->e_ident, ELFMAG, 4))
		ft_quit("ELF signature not found");
	if (ehdr->e_ident[EI_CLASS] != ELFCLASS64)
		ft_quit("ELF file is not 64bits");
	if (ehdr->e_type != ET_EXEC && ehdr->e_type != ET_DYN)
		ft_quit("ELF file is not executable or dynamicaly linked");
	info.old_entry = ehdr->e_entry;
	payload_size = (uint64_t)payload_end2 - (uint64_t)payload2 - 1;
	payload_mem_size = payload_size + align(payload_size, 16);
	payload_to_modify = malloc(payload_size);
	ft_memcpy(payload_to_modify, payload2, payload_size);
	payload2 = payload_to_modify;

	modify_program_header(ptr, &info);
	info.bits_added = info.bss_size + payload_mem_size;
	modify_sections(ptr, ptr + ehdr->e_shoff, ehdr->e_shnum, ehdr->e_shstrndx, &info);

	info.old_entry_offset = info.new_entry - info.old_entry;
	modify_payload(payload2, payload_size, (void*)info.old_entry_offset);

	write_binary(ptr, ehdr, &info);
	ft_printf("entry: %x\n", ehdr->e_entry);
	free(payload2);
}