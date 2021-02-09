/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_memset.c                                        :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: gdelabro <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2016/11/04 11:28:33 by gdelabro          #+#    #+#             */
/*   Updated: 2017/07/10 16:21:10 by gdelabro         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"

void	*ft_memset(void *b, int c, size_t len)
{
	unsigned char	*tab;

	if (!len)
		return (b);
	tab = (unsigned char *)b;
	while (len)
	{
		*tab = (unsigned char)c;
		tab++;
		len--;
	}
	return (b);
}
