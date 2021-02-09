/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   change_conv.c                                      :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: gdelabro <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2017/05/10 18:20:27 by gdelabro          #+#    #+#             */
/*   Updated: 2017/07/10 16:24:10 by gdelabro         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "../ft_printf.h"

int		res_u_modif(t_format *u, char *str)
{
	u->l = 0;
	u->ll = 0;
	u->h = 0;
	u->hh = 0;
	u->z = 0;
	u->j = 0;
	!ft_strcmp("z", str) ? u->z = 1 : 0;
	!ft_strcmp("j", str) ? u->j = 1 : 0;
	!ft_strcmp("ll", str) ? u->ll = 1 : 0;
	!ft_strcmp("l", str) ? u->l = 1 : 0;
	!ft_strcmp("h", str) ? u->h = 1 : 0;
	!ft_strcmp("hh", str) ? u->hh = 1 : 0;
	return (1);
}

void	change_conv_d(t_format *u)
{
	if (u->l || u->ll || u->j || (!u->z && !u->h && !u->hh))
		res_u_modif(u, "ll");
	else if (u->h)
		res_u_modif(u, "l");
	else if (u->hh)
		res_u_modif(u, "zzzz");
	u->conv[0] += 32;
}

void	change_conv(t_format *u)
{
	char a;

	a = u->conv[0];
	a == 'x' || a == 'p' ? u->max = 'a' - 10 : 0;
	a == 'X' ? u->max = 'A' - 10 : 0;
	a == 'p' ? res_u_modif(u, "l") : 0;
	if (a == 'D' || a == 'U' || a == 'O')
		change_conv_d(u);
	if (a == 'C' && (u->conv[0] = 'c'))
		res_u_modif(u, "l");
	if (a == 'p' && (u->sharp = 1)
			&& (u->neg = 1))
		u->conv[0] = 'x';
	if (a == 'S' && res_u_modif(u, "l"))
		u->conv[0] = 's';
}
