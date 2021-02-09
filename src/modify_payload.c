#include "../woody.h"

void	*ft_strnnstr(char *big, char *little, int size_big, int size_little)
{
	int i;
	int i2;

	i = -1;
	while (++i <= size_big - size_little)
	{
		i2 = -1;
		while (++i2 <= size_little)
		{
			if (i2 == size_little)
				return (big + i);
			if (big[i + i2] != little[i2])
				break ;
		}
	}
	return (NULL);
}

void	modify_payload(void *pl, int sz, void *jmp_addr)
{
	void	*addr_to_modify;

	addr_to_modify = ft_strnnstr(pl, "\x11\x11\x11\x11\x11\x11\x11\x11", sz, 8);
	ft_memcpy(addr_to_modify, jmp_addr, 8);
}