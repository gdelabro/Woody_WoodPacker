/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   check_address.c                                    :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: gdelabro <gdelabro@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2019/02/19 15:14:36 by gdelabro          #+#    #+#             */
/*   Updated: 2019/02/28 16:12:40 by gdelabro         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "../woody.h"

void	*my_address_pages(int mode, void *ptr, int size)
{
	static void		*ptr_start = NULL;
	static void		*ptr_end = NULL;

	if (!mode)
	{
		ptr_start = ptr;
		ptr_end = ptr + size;
	}
	if (mode == 1)
		if (ptr < ptr_start || ptr > ptr_end)
			ft_quit("an adress out of bounds was found");
	if (mode == 2)
	{
		if (ptr < ptr_start || ptr >= ptr_end)
			return (NULL);
		return ((void*)1);
	}
	if (mode == 3)
		return (ptr_start);
	if (mode == 4)
		return (ptr_end);
	return (NULL);
}

void	init_check_address(void *ptr, int size)
{
	my_address_pages(0, ptr, size);
}

void	check_address(void *ptr)
{
	my_address_pages(1, ptr, 0);
}

int		is_in_address(void *ptr)
{
	int ret;

	ret = (int)(long long int)my_address_pages(2, ptr, 0);
	return (ret);
}

void	*get_ptr_start(void)
{
	return (my_address_pages(3, NULL, 0));
}

void	*get_ptr_end(void)
{
	return (my_address_pages(4, NULL, 0));
}
