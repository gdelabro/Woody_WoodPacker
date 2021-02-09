/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   conv_short_int.c                                   :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: gdelabro <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2017/05/05 20:24:14 by gdelabro          #+#    #+#             */
/*   Updated: 2017/07/10 16:24:49 by gdelabro         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "../ft_printf.h"

static int		taille_buf(t_format *u, short int nb)
{
	int i;

	i = ft_taille_nb(nb, 10);
	u->prec != -1 ? u->zero = 0
		: (u->prec = 1);
	u->prec > i ? i = u->prec : 0;
	u->taille > i ? i = u->taille : 0;
	(i == ft_taille_nb(nb, 10) || i == u->prec) && (u->neg || u->plus)
		? ++i : 0;
	return (i);
}

static int		ft_onedif(char *str, char c)
{
	int i;

	i = -1;
	while (str[++i])
		if (str[i] != c)
			return (1);
	return (0);
}

static void		add_prefix(t_format *u, t_pf *e)
{
	int i;

	i = -1;
	while (u->tmp[++i] == ' ' || (i == 0 && u->tmp[i] == '0'))
		;
	i && u->neg ? u->tmp[i - 1] = '-' : 0;
	i && !u->neg && u->plus ? u->tmp[i - 1] = '+' : 0;
	while (u->moins && ft_onedif(u->tmp, ' ') && (i = -1) && u->tmp[0] == ' ')
		while (u->tmp[++i])
			u->tmp[i + 1] ? u->tmp[i] = u->tmp[i + 1] :
				(u->tmp[i] = ' ');
	i = -1;
	while (u->tmp[++i] == ' ')
		;
	if (u->espace && !u->neg && !u->plus && !u->zero)
		if ((u->tmp[ft_strlen(u->tmp) - 1] == ' '
				&& !(u->tmp[ft_strlen(u->tmp) - 1] = 0)) || u->tmp[0] != ' ')
			e->buf[e->i2++] = ' ';
	if (u->espace && !u->neg && !u->plus && u->zero)
		u->tmp[0] == '0' ? u->tmp[0] = ' ' :
			(e->buf[e->i2++] = ' ');
	if (u->max && (i = ft_strlen(u->tmp)))
		while (u->tmp[--i] == ' ')
			;
	u->max ? u->tmp[i] += 1 : 0;
}

void			handle_short_int(t_pf *e, t_format *u, short int nb)
{
	int i;
	int i2;

	i = -1;
	if (nb == -32768 && (nb += 1))
		u->max = 1;
	nb < 0 ? u->neg = 1 : 0;
	nb < 0 ? nb *= -1 : 0;
	i2 = taille_buf(u, nb);
	ft_memset(u->tmp, ' ', i2);
	u->tmp[i2] = 0;
	i = i2;
	while (--i >= 0)
	{
		nb || i2 - i <= u->prec || (u->zero && u->prec == 1
				&& !u->moins) ? u->tmp[i] = nb % 10 + 48 : 0;
		nb /= 10;
	}
	add_prefix(u, e);
	i = 0;
	while (u->tmp[i])
		e->buf[e->i2++] = u->tmp[i++];
}
