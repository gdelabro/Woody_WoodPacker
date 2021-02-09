/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   unicode.c                                          :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: gdelabro <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2017/05/04 16:48:42 by gdelabro          #+#    #+#             */
/*   Updated: 2017/07/10 16:25:02 by gdelabro         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "../ft_printf.h"

void	remp(char *tab, int nb)
{
	int i;
	int i2;

	i = ft_strlen(tab);
	i2 = 0;
	while (nb && i > 0)
	{
		tab[--i] == (char)0b11100000 ? i2 = 1 : 0;
		tab[i] == (char)0b11000000 ? i2 = 2 : 0;
		tab[i] == (char)0b10000000 ? i2 = 3 : 0;
		tab[i] == (char)0b11110000 ? i2 = 4 : 0;
		tab[i] == (char)0b11111000 ? i2 = 5 : 0;
		tab[i] = nb;
		if (i2 == 1 && ((tab[i] &= 0b00001111) || 1))
			tab[i] |= 0b11100000;
		if (i2 == 2 && ((tab[i] &= 0b00011111) || 1))
			tab[i] |= 0b11000000;
		if (i2 == 3 && ((tab[i] &= 0b00111111) || 1))
			tab[i] |= 0b10000000;
		if (i2 == 4 && ((tab[i] &= 0b00000111) || 1))
			tab[i] |= 0b11110000;
		if (i2 == 5 && ((tab[i] &= 0b00000011) || 1))
			tab[i] |= 0b11111000;
		nb >>= 6;
	}
}

void	to_unicode(t_format *u, t_pf *e, int un)
{
	ft_memset((void *)u->tmp, 0b10000000, 4);
	if ((un > (int)0b100001111111111111111 || un < 0))
		e->ret = -1;
	if (un <= (int)0b01111111 && !(u->tmp[1] = 0)
			&& !(u->tmp[2] = 0)
			&& !(u->tmp[3] = 0))
		u->tmp[0] = un;
	else if ((un > (int)0b1111111111111111 && (u->tmp[0] = 0b11110000))
			|| (u->tmp[4] = 0))
		u->tmp[4] = 0;
	else if ((un > (int)0b11111111111 && (u->tmp[0] = 0b11100000))
			|| (u->tmp[3] = 0))
		u->tmp[3] = 0;
	else if ((un > (int)0b111111 && (u->tmp[0] = 0b11000000))
			|| (u->tmp[2] = 0))
		u->tmp[2] = 0;
	else
		u->tmp[1] = 0;
	remp(u->tmp, un);
}

void	conv_c_unicode(t_format *u, t_pf *e)
{
	int i;
	int i2;

	to_unicode(u, e, u->nb);
	i2 = ft_strlen(u->tmp);
	!u->nb ? i2 = 1 : 0;
	i = -1;
	while (e->ret != -1 && !u->moins && ++i < u->taille - i2)
		e->buf[e->i2++] = !u->zero ? ' ' : '0';
	e->ret != -1 ? ft_strcat_2(e->buf, u->tmp, &e->i2) : 0;
	!u->nb ? ++e->i2 : 0;
	while (e->ret != -1 && ++i < u->taille - i2)
		e->buf[e->i2++] = ' ';
}
