/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_strncmp.c                                       :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: gdelabro <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2016/11/06 18:04:10 by gdelabro          #+#    #+#             */
/*   Updated: 2017/07/11 13:44:53 by gdelabro         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"

int		ft_strncmp(const char *s1, const char *s2, size_t n)
{
	int				i;
	unsigned char	*tab1;
	unsigned char	*tab2;

	if (!n || !s1 || !s2)
		return (0);
	tab1 = (unsigned char *)s1;
	tab2 = (unsigned char *)s2;
	i = 0;
	while (tab1[i] == tab2[i] && n >= 2 && tab1[i] && tab2[i])
	{
		i++;
		n--;
	}
	return (tab1[i] - tab2[i]);
}
