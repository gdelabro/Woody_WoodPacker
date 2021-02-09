/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   conv_o.c                                           :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: gdelabro <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2017/05/14 16:00:34 by gdelabro          #+#    #+#             */
/*   Updated: 2017/07/10 16:24:43 by gdelabro         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "../ft_printf.h"

static int	taille_buf(t_format *u, size_t nb)
{
	int i;

	i = ft_taille_size_t(nb, 8);
	u->prec <= i && u->sharp ? u->prec = i + 1 : 0;
	u->prec > i ? i = u->prec : 0;
	u->taille > i ? i = u->taille : 0;
	return (i);
}

static void	reverse_space(t_format *u)
{
	int i;

	i = -1;
	while (u->tmp[0] == ' ' && u->moins && (i = -1))
		while (u->tmp[++i])
			u->tmp[i] = u->tmp[i + 1] ? u->tmp[i + 1] : ' ';
}

void		handle_o(t_pf *e, t_format *u, size_t nb)
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
		nb || i2 - i <= u->prec || u->zero ? u->tmp[i] = nb % 8 + '0' : 0;
		nb /= 8;
	}
	reverse_space(u);
	ft_strcat_2(e->buf, u->tmp, &e->i2);
}
