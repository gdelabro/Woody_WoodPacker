/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   colors.c                                           :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: gdelabro <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2017/05/16 17:49:33 by gdelabro          #+#    #+#             */
/*   Updated: 2020/11/03 16:50:04 by gdelabro         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "../ft_printf.h"

int		find_word(char *str, char *s, int i)
{
	int i2;

	i2 = 0;
	while (str[i] && s[i2])
	{
		if (str[i] != s[i2])
			return (0);
		i++;
		i2++;
	}
	if (s[i2])
		return (0);
	return (1);
}

void	fill_buf(t_pf *e, char *str, char *color)
{
	int i;

	i = -1;
	while (str[e->i] && str[e->i++] != '}')
		;
	while (color[++i])
		e->buf[e->i2++] = color[i];
}

int		test_colors(t_pf *e, char *str)
{
	if (find_word(str, "{cyan}", e->i))
		fill_buf(e, str, CCYAN);
	else if (find_word(str, "{none}", e->i))
		fill_buf(e, str, CNONE);
	else if (find_word(str, "{orange}", e->i))
		fill_buf(e, str, CORANGE);
	else if (find_word(str, "{black}", e->i))
		fill_buf(e, str, CBLACK);
	else if (find_word(str, "{red}", e->i))
		fill_buf(e, str, CRED);
	else if (find_word(str, "{green}", e->i))
		fill_buf(e, str, CGREEN);
	else if (find_word(str, "{brown}", e->i))
		fill_buf(e, str, CBROWN);
	else if (find_word(str, "{yellow}", e->i))
		fill_buf(e, str, CYELLOW);
	else if (find_word(str, "{blue}", e->i))
		fill_buf(e, str, CBLUE);
	else if (find_word(str, "{magenta}", e->i))
		fill_buf(e, str, CMAGENTA);
	else if (find_word(str, "{gray}", e->i))
		fill_buf(e, str, CGRAY);
	else
		return (0);
	return (1);
}
