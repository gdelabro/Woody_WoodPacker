/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_strlen_fd.c                                     :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: gdelabro <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2016/11/15 11:59:41 by gdelabro          #+#    #+#             */
/*   Updated: 2017/07/10 16:22:58 by gdelabro         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"
#include <unistd.h>
#include <fcntl.h>

int		ft_strlen_fd(int fd)
{
	int		i;
	char	lettre;

	i = 0;
	while (read(fd, &lettre, 1))
		++i;
	return (i);
}
