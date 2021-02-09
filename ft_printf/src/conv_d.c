/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   conv_d.c                                           :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: gdelabro <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2017/04/25 16:25:08 by gdelabro          #+#    #+#             */
/*   Updated: 2017/07/10 16:24:25 by gdelabro         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "../ft_printf.h"

void	conv_x(t_pf *e, t_format *u)
{
	if (u->ll || u->l || u->j || u->z)
		handle_x(e, u, u->nb);
	else if (u->hh)
		handle_x(e, u, (unsigned char)u->nb);
	else if (u->h)
		handle_x(e, u, (unsigned short int)u->nb);
	else
		handle_x(e, u, (unsigned int)u->nb);
}

void	conv_o(t_pf *e, t_format *u)
{
	if (u->ll || u->l || u->j || u->z)
		handle_o(e, u, u->nb);
	else if (u->hh)
		handle_o(e, u, (unsigned char)u->nb);
	else if (u->h)
		handle_o(e, u, (unsigned short int)u->nb);
	else
		handle_o(e, u, (unsigned int)u->nb);
}

void	conv_b(t_pf *e, t_format *u)
{
	if (u->ll || u->l || u->j || u->z)
		handle_b(e, u, u->nb);
	else if (u->hh)
		handle_b(e, u, (unsigned char)u->nb);
	else if (u->h)
		handle_b(e, u, (unsigned short int)u->nb);
	else
		handle_b(e, u, (unsigned int)u->nb);
}

void	conv_u(t_pf *e, t_format *u)
{
	if (u->ll || u->l || u->j || u->z)
		handle_size_t(e, u, u->nb);
	else if (u->hh)
		handle_size_t(e, u, (unsigned char)u->nb);
	else if (u->h)
		handle_size_t(e, u, (unsigned short int)u->nb);
	else
		handle_size_t(e, u, (unsigned int)u->nb);
}

void	conv_d(t_pf *e, t_format *u)
{
	if (!u->hh && !u->h && !u->l && !u->ll && !u->z && !u->j)
		handle_int(e, u, (int)u->nb);
	else if (u->ll || u->l || u->j)
		handle_long_int(e, u, u->nb);
	else if (u->z)
		handle_long_int(e, u, u->nb);
	else if (u->hh)
		handle_char(e, u, u->nb);
	else if (u->h)
		handle_short_int(e, u, u->nb);
}
