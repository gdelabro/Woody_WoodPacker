/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   add_char.c                                         :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: gdelabro <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2017/05/04 19:22:40 by gdelabro          #+#    #+#             */
/*   Updated: 2017/07/10 16:19:36 by gdelabro         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"

int		in_tab(char **tab, char *str)
{
	int i;

	i = -1;
	if (!tab || !str)
		return (0);
	while (tab[++i])
		if (!ft_strcmp(tab[i], str))
			return (1);
	return (0);
}

void	aff_tab(char **tab)
{
	int i;

	i = -1;
	while (tab && tab[++i])
		ft_putendl(tab[i]);
}

void	add_char2(char *str, char c)
{
	int i;

	i = ft_strlen(str);
	str[i + 1] = 0;
	while (i != -1 && (str[i] = str[i - 1]))
		--i;
	str[0] = c;
}
