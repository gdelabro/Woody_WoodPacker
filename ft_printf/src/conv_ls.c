/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   conv_ls.c                                          :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: gdelabro <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2017/05/14 18:03:43 by gdelabro          #+#    #+#             */
/*   Updated: 2017/07/10 16:24:38 by gdelabro         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "../ft_printf.h"

void	check_bad_uni(char *str)
{
	int i;

	i = -1;
	while (str[++i])
	{
		if (((str[i] & 0b11111000) == 0b11110000
					&& i + 4 > (int)ft_strlen(str))
		|| ((str[i] & 0b11110000) == 0b11100000 && i + 3 > (int)ft_strlen(str))
		|| ((str[i] & 0b11100000) == 0b11000000 && i + 2 > (int)ft_strlen(str)))
		{
			str[i] = 0;
			break ;
		}
	}
}

void	conv_ls(t_pf *e, t_format *u, wchar_t *str)
{
	char	tmp[2000];
	int		i;

	i = -1;
	ft_bzero(u->tmp, 2000);
	ft_bzero(&tmp, 2000);
	if (!str)
	{
		ft_strcat(tmp, "(null)");
		conv_s(u, e, tmp);
		return ;
	}
	while (str[++i])
	{
		to_unicode(u, e, str[i]);
		ft_strcat(tmp, u->tmp);
		ft_bzero(u->tmp, 6);
	}
	u->prec != -1 ? tmp[u->prec] = 0 : 0;
	check_bad_uni(tmp);
	conv_s(u, e, tmp);
}
