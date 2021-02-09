#include "../woody.h"

char		*payload2 = "\xbf\x01\x00\x00\x00\x48\xbe\x59\x2e\x2e\x2e\x2e\x0a\x00\x00\x56\x48\xbe\x2e\x2e\x2e\x2e\x57\x4f\x4f\x44\x56\x48\x89\xe6\xba\x0e\x00\x00\x00\xb8\x01\x00\x00\x00\x0f\x05\x41\x58\x41\x58\x48\xb8\x11\x11\x11\x11\x11\x11\x11\x11\xff\xe0\xbf\x00\x00\x00\x00\xb8\x3c\x00\x00\x00\x0f\x05";
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
	Elf64_Shdr	*shdr;
	char		*sct_names;
	char		*name;

	shdr = shdr_base + index;
	check_address(shdr + 1);
	check_address(shdr_base + shnum);
	sct_names = ptr + shdr->sh_offset;
	check_address(sct_names);
	info->text_offset = 0;
	i = -1;
	while (++i < shnum)
	{
		shdr = shdr_base + i;
		check_address((void*)shdr + sizeof(*shdr));
		name = sct_names + shdr->sh_name;
		check_address(name);
		if (!ft_strcmp(name, ".text"))
		{
			shdr->sh_size += align(shdr->sh_size, shdr->sh_addralign);
			info->text_size = shdr->sh_size;
			info->text_offset = shdr->sh_offset;
			info->text_addr = shdr->sh_addr;
			info->align = shdr->sh_addralign;
			shdr->sh_size += payload_size;
		}
		else if (info->text_offset)
		{
			if (shdr->sh_addr)
				shdr->sh_addr += payload_mem_size;
			shdr->sh_offset += payload_mem_size;
		}
		show_section(shdr, sct_names, i);
	}
}

void	modify_program_header(void *ptr, elf_info *info)
{
	Elf64_Ehdr	*ehdr;
	Elf64_Phdr	*phdr;
	int			i;

	ehdr = ptr;
	phdr = ptr + ehdr->e_phoff;
	check_address(phdr + 1);
	check_address(phdr + ehdr->e_phnum);
	ft_printf("PROGRAM HEADERS:\n");
	i = -1;
	while (++i < ehdr->e_phnum)
	{
		ft_printf("header %d:\n\ttype: %x\n\tflags: %x\n\toffset: %x\n\tvaddr: %x\n\tpaddr: %x\n\tfilesz: %x\n\tmemsz: %x\n\talign: %x\n", i, phdr->p_type, phdr->p_flags, phdr->p_offset, phdr->p_vaddr, phdr->p_paddr, phdr->p_filesz, phdr->p_memsz, phdr->p_align);
		if (phdr->p_flags & PF_X)
		{
			phdr->p_flags = PF_R | PF_W | PF_X;
			phdr->p_memsz += payload_mem_size;
			phdr->p_filesz += payload_mem_size;
		}
		if (phdr->p_offset > info->text_offset)
		{
			phdr->p_offset += payload_mem_size;
			phdr->p_paddr += payload_mem_size;
			phdr->p_vaddr += payload_mem_size;
		}
		phdr += 1;
	}
}

void	write_binary(void *ptr, Elf64_Ehdr 	*ehdr, elf_info	*info)
{
	int		fd;
	char	alignement[16] = "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0";
	int		size_begining;
	void	*end_file;

	fd = open("woody", O_WRONLY | O_CREAT | O_TRUNC, S_IRWXU | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH);
	if (fd < 0)
		ft_quit("can't open new file woody");
	ehdr->e_shoff += payload_mem_size;
	ehdr->e_entry = info->text_addr + info->text_size;
	size_begining = info->text_offset + info->text_size;
	write(fd, ptr, size_begining);
	write(fd, payload2, payload_size); // writing payload in new section
	write(fd, alignement, align(payload_size, info->align)); // writing alignement
	end_file = ptr + size_begining;// + payload_mem_size;
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
	info.section_size = ehdr->e_shoff;
	info.old_entry = ehdr->e_entry;
	payload_size = (uint64_t)payload_end2 - (uint64_t)payload2 - 1;
	payload_mem_size = payload_size + align(payload_size, 16);
	payload_to_modify = malloc(payload_size);
	ft_memcpy(payload_to_modify, payload2, payload_size);
	payload2 = payload_to_modify;
	modify_payload(payload2, payload_size, &info.old_entry);
	modify_sections(ptr, ptr + ehdr->e_shoff, ehdr->e_shnum, ehdr->e_shstrndx, &info);
	modify_program_header(ptr, &info);
	write_binary(ptr, ehdr, &info);
	ft_printf("entry: %x\n", ehdr->e_entry);
	free(payload2);
}