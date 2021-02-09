/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_printf.c                                        :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: gdelabro <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2017/04/07 14:20:58 by gdelabro          #+#    #+#             */
/*   Updated: 2017/07/10 16:25:00 by gdelabro         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "../ft_printf.h"

t_pf	*init_struct(t_pf *e)
{
	e->i = 0;
	e->i2 = 0;
	return (e);
}

int		test_char(char *str, t_pf *e, va_list *ap)
{
	if (str[e->i] == '%')
		remplir_buf(str, e, ap);
	else if (test_colors(e, str))
		;
	else
		e->buf[e->i2++] = str[e->i++];
	return (0);
}

int		fd_printf(int fd, const char *str, ...)
{
	va_list		ap;
	static int	ret = 0;
	t_pf		e;

	va_start(ap, str);
	init_struct(&e);
	e.ret = 0;
	while (str[e.i])
		e.ret != -1 ? test_char((char*)str, &e, &ap) : ++e.i;
	write(fd, e.buf, e.i2);
	!e.ret ? e.ret = e.i2 : 0;
	e.ret == -1 ? ret = -1 :
		(ret = e.ret);
	va_end(ap);
	return (ret);
}

int		ft_printf(const char *str, ...)
{
	va_list		ap;
	static int	ret = 0;
	t_pf		e;

	va_start(ap, str);
	init_struct(&e);
	e.ret = 0;
	while (str[e.i])
		e.ret != -1 ? test_char((char*)str, &e, &ap) : ++e.i;
	write(1, e.buf, e.i2);
	!e.ret ? e.ret = e.i2 : 0;
	e.ret == -1 ? ret = -1 :
		(ret = e.ret);
	va_end(ap);
	return (ret);
}

int		ft_sprintf(char *buf, const char *str, ...)
{
	va_list		ap;
	static int	ret = 0;
	t_pf		e;

	va_start(ap, str);
	init_struct(&e);
	e.ret = 0;
	while (str[e.i])
		e.ret != -1 ? test_char((char*)str, &e, &ap) : ++e.i;
	ft_memcpy(buf, e.buf, e.i2);
	!e.ret ? e.ret = e.i2 : 0;
	e.ret == -1 ? ret = -1 :
		(ret = e.ret);
	va_end(ap);
	return (ret);
}

int		ft_sprintf2(char **buf, const char *str, ...)
{
	va_list		ap;
	static int	ret = 0;
	t_pf		e;

	va_start(ap, str);
	init_struct(&e);
	e.ret = 0;
	while (str[e.i])
		e.ret != -1 ? test_char((char*)str, &e, &ap) : ++e.i;
	*buf = malloc(e.i2);
	ft_memcpy(*buf, e.buf, e.i2);
	!e.ret ? e.ret = e.i2 : 0;
	e.ret == -1 ? ret = -1 :
		(ret = e.ret);
	va_end(ap);
	return (ret);
}