/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_memalloc.c                                      :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: gdelabro <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2016/11/07 14:16:55 by gdelabro          #+#    #+#             */
/*   Updated: 2017/07/10 16:20:45 by gdelabro         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"

void	*ft_memalloc(size_t size)
{
	void	*tab;

	!(tab = (void*)malloc(sizeof(tab) * size)) ? exit(EXIT_FAILURE) : 0;
	if (!tab)
		return (NULL);
	ft_memset(tab, 0, size);
	return (tab);
}
