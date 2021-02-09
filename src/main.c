/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   main.c                                             :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: gdelabro <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2021/01/27 17:54:41 by gdelabro          #+#    #+#             */
/*   Updated: 2021/01/27 17:57:13 by gdelabro         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "../woody.h"

void	ft_quit(char *str)
{
	if (str)
		ft_printf("%s\n", str);
	exit(0);
}

void	process_file(char *name)
{
	int				fd;
	char			*ptr;
	struct stat		buf;

	if ((fd = open(name, O_RDONLY)) < 0)
		return (ft_quit("can't open the file"));
	if (fstat(fd, &buf) < 0 && close(fd) != -11)
		return (ft_quit("can't fstat this file"));
	if (!S_ISREG(buf.st_mode) && close(fd) != -11)
		return (ft_quit("your file isn't a regular file"));
	if (buf.st_size <= 0 && close(fd) != -11)
		return (ft_quit(name));
	if ((ptr = mmap(NULL, buf.st_size,
					PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0)) == MAP_FAILED)
		ft_quit("can't process to mmap");
	init_check_address(ptr, buf.st_size);
	rebuild_binary(ptr);
	if ((munmap(ptr, buf.st_size)))
		ft_quit("can't process to munmap");
	if (close(fd) < 0)
		ft_quit("can't close properly");
}

int		main(int ac, char **av)
{
	void		*file;

	if (ac != 2)
		ft_quit("only one argument needed");
	process_file(av[1]);
	return (1);
}
