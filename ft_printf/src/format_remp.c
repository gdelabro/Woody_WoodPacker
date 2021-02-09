/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   format_remp.c                                      :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: gdelabro <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2017/04/10 17:14:58 by gdelabro          #+#    #+#             */
/*   Updated: 2017/07/10 16:24:57 by gdelabro         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "../ft_printf.h"

void	init_u(t_format *u)
{
	u->zero = 0;
	u->sharp = 0;
	u->plus = 0;
	u->moins = 0;
	u->neg = 0;
	u->espace = 0;
	u->hh = 0;
	u->h = 0;
	u->ll = 0;
	u->l = 0;
	u->j = 0;
	u->z = 0;
	u->max = 0;
	u->prec = -1;
	u->taille = 0;
	ft_bzero(u->conv, 2);
}

void	change_hl(char *str, t_format *u)
{
	if ((!u->z && !u->j && !u->ll && !u->l && !u->h && !u->hh) ||
			(u->h || u->hh))
	{
		u->l = 0;
		u->ll = 0;
		u->hh = 0;
		u->h = 0;
		u->j = 0;
		u->z = 0;
		!ft_strcmp("j", str) ? u->j = 1 : 0;
		!ft_strcmp("z", str) ? u->z = 1 : 0;
		!ft_strcmp("hh", str) ? u->hh = 1 : 0;
		!ft_strcmp("h", str) ? u->h = 1 : 0;
		!ft_strcmp("l", str) ? u->l = 1 : 0;
		!ft_strcmp("ll", str) ? u->ll = 1 : 0;
	}
}

void	remp_struc(char *str, t_pf *e, t_format *u)
{
	char	a;
	char	b;

	a = str[e->i];
	b = a;
	while (a == '.' && !(u->prec = 0))
		while ((a = str[++e->i]) && a >= '0' && a <= '9'
				&& (u->prec *= 10) != -1)
			u->prec += a - 48;
	b == '.' ? --e->i : 0;
	a == '0' ? u->zero = 1 : 0;
	a == '#' ? u->sharp = 1 : 0;
	a == ' ' ? u->espace = 1 : 0;
	a == '+' ? u->plus = 1 : 0;
	a == '-' ? u->moins = 1 : 0;
	a == 'j' ? change_hl("j", u) : 0;
	a == 'z' ? change_hl("z", u) : 0;
	a == 'h' && str[e->i + 1] == 'h' ? change_hl("hh", u) : 0;
	a == 'h' && str[e->i + 1] != 'h' && str[e->i - 1] != 'h' ?
		change_hl("h", u) : 0;
	a == 'l' && str[e->i + 1] == 'l' ? change_hl("ll", u) : 0;
	a == 'l' && str[e->i + 1] != 'l' && str[e->i - 1] != 'l' ?
		change_hl("l", u) : 0;
}

void	next_arg(t_pf *e, t_format *u, va_list *ap)
{
	ft_strstr("sSpdDioOuUxXcCb", u->conv) ? u->nb = va_arg(*ap, size_t) : 0;
	change_conv(u);
	!ft_strstr("sSpdDioOuUxXcCb", u->conv) ? conv_c(u, e, u->conv[0]) : 0;
	u->conv[0] == 'i' ? u->conv[0] = 'd' : 0;
	u->conv[0] == 'd' ? conv_d(e, u) : 0;
	u->conv[0] == 's' && !u->l ? conv_s(u, e, (char *)u->nb) : 0;
	u->conv[0] == 's' && u->l ? conv_ls(e, u, (wchar_t *)u->nb) : 0;
	u->conv[0] == 'c' && !u->l ? conv_c(u, e, (char)u->nb) : 0;
	u->conv[0] == 'c' && u->l ? conv_c_unicode(u, e) : 0;
	u->conv[0] == 'u' ? u->plus = 0 : 0;
	u->conv[0] == 'u' ? u->espace = 0 : 0;
	u->conv[0] == 'u' ? conv_u(e, u) : 0;
	u->conv[0] == 'o' ? conv_o(e, u) : 0;
	u->conv[0] == 'b' ? conv_b(e, u) : 0;
	ft_strstr("xX", u->conv) ? conv_x(e, u) : 0;
}

void	remplir_buf(char *str, t_pf *e, va_list *ap)
{
	char		a;
	t_format	u;

	init_u(&u);
	while ((a = str[++e->i]) && ((a <= '9' && a >= '0') || a == '#' || a == '-'
			|| a == '+' || a == ' ' || a == '.' || a == 'h' || a == 'l' ||
			a == 'j' || a == 'z'))
	{
		if (a <= '9' && a >= '1' && (u.taille = a - 48))
			while ((a = str[e->i + 1]) && a <= '9' && a >= '0' && ++e->i
					&& (u.taille *= 10))
				u.taille += a - 48;
		else
			remp_struc(str, e, &u);
	}
	u.conv[0] = a;
	u.prec > 1000 ? u.prec = 1000 : 0;
	u.taille > 1000 ? u.prec = 1000 : 0;
	if (ft_strcmp(u.conv, "") && ++e->i)
		next_arg(e, &u, ap);
}
