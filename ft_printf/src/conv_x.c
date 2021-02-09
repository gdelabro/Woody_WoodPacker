/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   conv_x.c                                           :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: gdelabro <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2017/05/12 17:40:43 by gdelabro          #+#    #+#             */
/*   Updated: 2017/07/10 16:24:54 by gdelabro         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "../ft_printf.h"

static int	taille_buf(t_format *u, size_t nb)
{
	int i;

	i = ft_taille_size_t(nb, 16);
	u->prec > i ? i = u->prec : 0;
	u->sharp && (nb || u->neg) ? i += 2 : 0;
	u->taille > i ? i = u->taille : 0;
	return (i);
}

static void	add_sharp(t_format *u)
{
	int i;

	i = 0;
	if (u->sharp && !u->zero && (u->nb || u->prec || u->neg))
	{
		while (u->tmp[i] == ' ' && u->tmp[i])
			++i;
		u->tmp[i - 1] = u->max + 'x' + 10 - 'a';
		u->tmp[i - 2] = '0';
	}
	else if (u->sharp && u->zero && (u->nb || u->prec || u->neg))
	{
		u->tmp[0] = '0';
		u->tmp[1] = u->max + 'x' + 10 - 'a';
	}
}

static void	reverse_space(t_format *u)
{
	int i;

	i = -1;
	while (u->tmp[0] == ' ' && u->moins && (i = -1))
		while (u->tmp[++i])
			u->tmp[i] = u->tmp[i + 1] ? u->tmp[i + 1] : ' ';
}

void		handle_x(t_pf *e, t_format *u, size_t nb)
{
	int i;
	int i2;

	u->prec != -1 || u->moins ? u->zero = 0 : 0;
	u->prec == -1 ? u->prec = 1 : 0;
	i2 = taille_buf(u, nb);
	ft_memset(u->tmp, ' ', i2);
	u->tmp[i2] = 0;
	i = ft_strlen(u->tmp);
	while (--i >= 0)
	{
		if (nb || i2 - i <= u->prec || u->zero)
			u->tmp[i] = nb % 16 < 10 ? nb % 16 + '0' : nb % 16 + u->max;
		nb /= 16;
	}
	add_sharp(u);
	reverse_space(u);
	ft_strcat_2(e->buf, u->tmp, &e->i2);
}
