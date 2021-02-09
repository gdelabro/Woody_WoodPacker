/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   conv_s.c                                           :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: gdelabro <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2017/04/28 19:21:56 by gdelabro          #+#    #+#             */
/*   Updated: 2017/07/10 16:24:46 by gdelabro         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "../ft_printf.h"

void	conv_s(t_format *u, t_pf *e, char *str)
{
	int		i;
	int		t;
	char	nul[7];

	nul[6] = 0;
	nul[0] = 0;
	ft_strcat(nul, "(null)");
	if (!str)
		str = nul;
	i = -1;
	t = (int)ft_strlen(str);
	u->prec < t && u->prec != -1 ? t = u->prec : 0;
	while (!u->moins && ++i < (int)u->taille - t)
		e->buf[e->i2++] = u->zero ? '0' : ' ';
	i = 0;
	while ((u->prec == -1 || i < u->prec) && str[i])
		e->buf[e->i2++] = str[i++];
	while (u->moins && ++i <= u->taille)
		e->buf[e->i2++] = ' ';
}

void	conv_c(t_format *u, t_pf *e, char c)
{
	int i;

	i = -1;
	while (!u->moins && ++i < u->taille - 1)
		e->buf[e->i2++] = u->zero ? '0' : ' ';
	e->buf[e->i2++] = c;
	while (++i < u->taille - 1)
		e->buf[e->i2++] = ' ';
}

void	add_char(char *str, char c)
{
	int i;

	i = ft_strlen(str);
	while (i != -1 && (str[i] = str[i - 1]))
		--i;
	str[0] = c;
}
