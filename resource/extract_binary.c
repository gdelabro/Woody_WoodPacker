# include <stdio.h>
# include <stdlib.h>
# include <stdint.h>
# include <sys/mman.h>
# include <sys/stat.h>
# include <fcntl.h>
# include <elf.h>

int main(int ac, char **av)
{	int				fd;
	char			*ptr;
	struct stat		buf;
	char			*name;
	int				i;
	Elf64_Ehdr		*ehdr;
	Elf64_Phdr		*phdr;
	Elf64_Shdr		*shdr;
	char			*names;

	if (ac != 2)
		exit(0);
	name = av[1];
	fd = open(name, O_RDONLY);
	fstat(fd, &buf);
	ptr = mmap(NULL, buf.st_size, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);
	ehdr = (Elf64_Ehdr*)ptr;
	shdr = (Elf64_Shdr*)(ptr + ehdr->e_shoff);
	names = ptr + (shdr + ehdr->e_shstrndx)->sh_offset;
	i = -1;
	while (++i < ehdr->e_shnum)
	{
		if (strcmp(names + (shdr + i)->sh_name, ".text"))
			continue ;
		for (int j = 0; j < (shdr + i)->sh_size; j++)
		{
			printf("\\x%.2hhx", *(ptr+(shdr + i)->sh_offset + j));
		}
		printf("\n");
	}
	munmap(ptr, buf.st_size);
	close(fd);
}