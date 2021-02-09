/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_printf.h                                        :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: gdelabro <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2017/05/14 17:44:45 by gdelabro          #+#    #+#             */
/*   Updated: 2020/11/03 16:54:00 by gdelabro         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#ifndef FT_PRINTF_H
# define FT_PRINTF_H

# include <unistd.h>
# include <stdio.h>
# include <stdlib.h>
# include <string.h>
# include <fcntl.h>
# include <stdarg.h>
# include <wchar.h>
# include "libft/libft.h"

# define CNONE			"\033[0m"
# define CBOLD			"\033[1m"
# define CBLACK			"\033[30m"
# define CRED			"\033[31m"
# define CRED_BOLD		"\033[31;1m"
# define CGREEN			"\033[32;1m"
# define CBROWN			"\033[33m"
# define CYELLOW		"\033[38;5;226m"
# define CBLUE			"\033[34m"
# define CMAGENTA		"\033[35m"
# define CCYAN			"\033[36;1m"
# define CGRAY			"\033[37m"
# define CORANGE		"\033[38;5;166m"
# define DEV_C			"\033[43;34m"
# define DEV_B			"\033[46;34m"

typedef struct			s_pf
{
	char				buf[100000];
	int					i;
	int					i2;
	int					ret;
}						t_pf;

typedef struct			s_format
{
	int					sharp;
	int					zero;
	int					prec;
	int					plus;
	int					moins;
	int					espace;
	int					hh;
	int					h;
	int					l;
	int					ll;
	int					j;
	int					z;
	int					taille;
	char				conv[2];
	long long			nb;
	int					neg;
	int					max;
	char				tmp[2000];
}						t_format;

int						ft_printf(const char *str, ...);
int						ft_sprintf(char *buf, const char *str, ...);
int						ft_sprintf2(char **buf, const char *str, ...);
int						fd_printf(int fd, const char *str, ...);
void					handle_int(t_pf *e, t_format *u, int nb);
void					conv_s(t_format *u, t_pf *e, char *str);
void					conv_b(t_pf *e, t_format *u);
void					conv_ls(t_pf *e, t_format *u, wchar_t *str);
void					conv_o(t_pf *e, t_format *u);
void					conv_c(t_format *u, t_pf *e, char c);
void					to_unicode(t_format *u, t_pf *e, int un);
int						test_colors(t_pf *e, char *str);
void					handle_size_t(t_pf *e, t_format *u, size_t nb);
void					handle_short_int(t_pf *e, t_format *u, short int nb);
void					handle_o(t_pf *e, t_format *u, size_t nb);
void					handle_b(t_pf *e, t_format *u, size_t nb);
void					handle_char(t_pf *e, t_format *u, char nb);
void					change_conv(t_format *u);
void					conv_c_unicode(t_format *u, t_pf *e);
void					remplir_buf(char *str, t_pf *e, va_list *ap);
void					conv_d(t_pf *e, t_format *u);
void					conv_x(t_pf *e, t_format *u);
void					handle_x(t_pf *e, t_format *u, size_t nb);
void					handle_long_int(t_pf *e, t_format *u, long int nb);
void					handle_o(t_pf *e, t_format *u, size_t nb);
void					conv_u(t_pf *e, t_format *u);

#endif
