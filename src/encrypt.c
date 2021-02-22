#include "../woody.h"

uint64_t	generate_rc4_key()
{
	int 		fd;
	uint64_t	key;

	fd = open("/dev/urandom", O_RDONLY);
	if (fd < 0)
		ft_quit("open failed");
	if (read(fd, &key, sizeof(uint64_t)) != sizeof(uint64_t))
		ft_quit("read didn't work");
	close(fd);
	return (key);
}

void	rc4_encrypt(uint64_t key, uint64_t *ptr, uint64_t size)
{
	int 		i;
	uint64_t	tmp;

	i = 0;
	while (i < size)
	{
		if (i + 8 >= size)
		{
			key <<= (8 - (size - i)) * 8;
			key >>= (8 - (size - i)) * 8;
			ft_printf("size: %d\nreste: %d\nkey: %llx\n", size, (8 - (size - i)) * 8, key);
		}
		*ptr ^= key;
		ptr++;
		i += 8;
	}
}

void	encrypt(void *ptr, elf_info *info)
{
	uint64_t	key;

	key = generate_rc4_key();
	info->key = key;
	ft_printf("key generated: [%llx]\n", key);
	rc4_encrypt(key, ptr + info->text->sh_offset, info->text->sh_size);
}