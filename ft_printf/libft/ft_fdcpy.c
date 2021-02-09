/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_fdcpy.c                                         :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: gdelabro <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2016/11/15 13:20:57 by gdelabro          #+#    #+#             */
/*   Updated: 2017/07/10 16:19:59 by gdelabro         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"

int			ft_cpyfile(int fd, char **file2)
{
	char	*tmp;
	char	buf[BUFF_SIZE + 1];
	int		ret;

	ret = 1;
	*file2 = NULL;
	while (ret)
	{
		ret = read(fd, buf, BUFF_SIZE);
		if (ret < 0)
			return (-1);
		buf[ret] = '\0';
		tmp = *file2;
		*file2 = ft_strjoin(tmp, buf);
		free(tmp);
	}
	return (0);
}
