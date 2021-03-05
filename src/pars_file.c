#include "../woody.h"

char		*payload2 = "\x53\x51\x52\x57\x56\x41\x50\x41\x51\x41\x52\x41\x53\x41\x54\x41\x55\x41\x56\x41\x57\x48\x8d\x3d\xe4\xff\xff\xff\x48\xb8\x22\x22\x22\x22\x22\x22\x22\x22\x48\x29\xc7\x48\xbe\x33\x33\x33\x33\x33\x33\x33\x33\x48\xba\x44\x44\x44\x44\x44\x44\x44\x44\xb9\x00\x00\x00\x00\x48\x39\xf1\x7d\x3a\x49\x89\xf1\x49\x29\xc9\x49\x83\xf9\x08\x7f\x1b\x4d\x89\xca\x41\xb9\x08\x00\x00\x00\x4d\x29\xd1\x4d\x6b\xc9\x08\x51\x4c\x89\xc9\x48\xd3\xe2\x48\xd3\xea\x59\x4c\x8b\x0f\x49\x31\xd1\x4c\x89\x0f\x48\x83\xc7\x08\x48\x83\xc1\x08\xeb\xc1\xbf\x01\x00\x00\x00\x48\xbe\x59\x2e\x2e\x2e\x2e\x0a\x00\x00\x56\x48\xbe\x2e\x2e\x2e\x2e\x57\x4f\x4f\x44\x56\x48\x89\xe6\xba\x0e\x00\x00\x00\xb8\x01\x00\x00\x00\x0f\x05\x48\x83\xc4\x10\x48\x8d\x3d\x4a\xff\xff\xff\x48\xb8\x11\x11\x11\x11\x11\x11\x11\x11\x48\x29\xc7\x48\x89\xf8\x41\x5f\x41\x5e\x41\x5d\x41\x5c\x41\x5b\x41\x5a\x41\x59\x41\x58\x5e\x5f\x5a\x59\x5b\xff\xe0";
char		*payload_end2 = "";
uint32_t	payload_size;
uint32_t	payload_mem_size;

int		align(uint64_t nb, int alignement)
{
	uint64_t	res;

	res = (alignement - nb % alignement) % alignement;
	return (res);
}

void	search_data_section(void *ptr, Elf64_Shdr *shdr_base, int shnum, uint32_t index, elf_info *info)
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
	info->text = NULL;
	i = -1;
	while (++i < shnum)
	{
		shdr = shdr_base + i;
		check_address((void*)shdr + sizeof(*shdr));
		name = sct_names + shdr->sh_name;
		check_address(name);
		if (!ft_strcmp(name, ".data"))
			info->data_offset = shdr->sh_offset;
	}
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
	info->text = NULL;
	i = -1;
	while (++i < shnum)
	{
		shdr = shdr_base + i;
		check_address((void*)shdr + sizeof(*shdr));
		name = sct_names + shdr->sh_name;
		check_address(name);
		if (!ft_strcmp(name, ".text"))
			info->text = shdr;
		if (shdr->sh_offset >= info->seg->p_offset + info->seg->p_filesz && ft_strcmp(".bss", name))
		{
			shdr->sh_addr ? shdr->sh_addr += info->bits_added : 0;
			shdr->sh_offset += info->bits_added;
		}
	}
}

void	modify_program_header(void *ptr, elf_info *info)
{
	Elf64_Ehdr	*ehdr;
	Elf64_Phdr	*phdr;
	int			i;
	//int			filled;

	ehdr = ptr;
	phdr = ptr + ehdr->e_phoff;
	check_address(phdr + 1);
	check_address(phdr + ehdr->e_phnum);
	i = -1;
	//filled = 0;
	info->seg = NULL;
	while (++i < ehdr->e_phnum)
	{
		//if (phdr->p_type == 1)
		//	filled++;
		if (phdr->p_type == 1)
			phdr->p_flags = PF_R | PF_W | PF_X;
		if (phdr->p_type == 1 && (info->data_offset >= phdr->p_offset && info->data_offset < phdr->p_offset + phdr->p_filesz))//&& filled == 2)
		{
			phdr->p_flags = PF_R | PF_W | PF_X;
			info->seg = phdr;
			info->new_entry = phdr->p_vaddr + phdr->p_memsz;
			info->bss_size = phdr->p_memsz - phdr->p_filesz;
			info->new_code_offset = phdr->p_offset + phdr->p_filesz;
		}
		else if (info->seg && phdr->p_offset > info->seg->p_offset + info->seg->p_filesz)
		{
			phdr->p_offset += info->bits_added;
			phdr->p_paddr ? phdr->p_paddr += info->bits_added : 0;
			phdr->p_vaddr ? phdr->p_vaddr += info->bits_added : 0;
		}
		phdr += 1;
	}
	if (!info->seg)
		ft_quit("coudn't find the data segement");
}

void	write_binary(void *ptr, Elf64_Ehdr 	*ehdr, elf_info	*info)
{
	int			fd;
	uint64_t	size_begining;
	void		*end_file;
	int			wrote;
	void		*new_binary;

	new_binary = malloc(get_ptr_end() - get_ptr_start() + info->bits_added);
	ehdr->e_shoff += info->bits_added;
	ehdr->e_entry = info->new_entry;
	info->seg->p_filesz += info->bits_added;
	info->seg->p_memsz = info->seg->p_filesz;
	size_begining = info->new_code_offset;
	wrote = 0;
	ft_memcpy(new_binary, ptr, size_begining);
	wrote += size_begining;
	ft_memset(new_binary + wrote, 0, info->bss_size);
	wrote += info->bss_size;
	ft_memcpy(new_binary + wrote, payload2, payload_size);
	wrote += payload_size;
	ft_memset(new_binary + wrote, 0x90, align(payload_size, 16));
	wrote += align(payload_size, 16);
	end_file = ptr + size_begining;
	ft_memcpy(new_binary + wrote, end_file, (size_t)(get_ptr_end() - end_file));
	wrote += (size_t)(get_ptr_end() - end_file);

	if (wrote != get_ptr_end() - get_ptr_start() + info->bits_added)
		ft_printf("wooot\n");
	fd = open("woody", O_WRONLY | O_CREAT | O_TRUNC, S_IRWXU | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH);
	if (fd < 0)
		ft_quit("can't open new file woody");
	write(fd, new_binary, wrote);
	if (close(fd) != 0)
		ft_quit("can't close woody properly");
}

void	rebuild_binary(void *ptr)
{
	Elf64_Ehdr	*ehdr;
	elf_info	info;
	char		*payload_to_modify;

	if (!is_in_address(ptr + sizeof(*ehdr)))
		ft_quit("file too small");
	ehdr = ptr;
	if (ft_strncmp((const char *)ehdr->e_ident, ELFMAG, 4))
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

	search_data_section(ptr, ptr + ehdr->e_shoff, ehdr->e_shnum, ehdr->e_shstrndx, &info);
	modify_program_header(ptr, &info);
	info.bits_added = info.bss_size + payload_mem_size;
	modify_sections(ptr, ptr + ehdr->e_shoff, ehdr->e_shnum, ehdr->e_shstrndx, &info);

	info.old_entry_offset = info.new_entry - info.old_entry;
	info.text_diff_addr = info.new_entry - info.text->sh_addr;
	encrypt_text_section(ptr, &info);
	modify_payload(payload2, payload_size, (void*)info.old_entry_offset,
		(void*)info.text_diff_addr, (uint64_t)info.text->sh_size, info.key);

	ft_printf("%llx\n", info.new_entry);
	write_binary(ptr, ehdr, &info);
	free(payload2);
}