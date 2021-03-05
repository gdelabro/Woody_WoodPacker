#include "../woody.h"

uint64_t	generate_xor_key()
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

void	xor_cipher_encrypt(uint64_t key, uint64_t *ptr, uint64_t size)
{
	uint32_t	i;

	i = 0;
	while (i < size)
	{
		if (i + 8 >= size)
		{
			key <<= (8 - (size - i)) * 8;
			key >>= (8 - (size - i)) * 8;
		}
		*ptr ^= key;
		ptr++;
		i += 8;
	}
}

void	encrypt_text_section(void *ptr, elf_info *info)
{
	uint64_t	key;

	key = generate_xor_key();
	info->key = key;
	ft_printf("key generated: [%llx]\n", key);
	xor_cipher_encrypt(key, ptr + info->text->sh_offset, info->text->sh_size);
}