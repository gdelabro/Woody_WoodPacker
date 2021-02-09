# **************************************************************************** #
#                                                                              #
#                                                         :::      ::::::::    #
#    Makefile                                           :+:      :+:    :+:    #
#                                                     +:+ +:+         +:+      #
#    By: gdelabro <marvin@42.fr>                    +#+  +:+       +#+         #
#                                                 +#+#+#+#+#+   +#+            #
#    Created: 2016/12/15 15:37:25 by gdelabro          #+#    #+#              #
#    Updated: 2017/05/16 17:58:05 by gdelabro         ###   ########.fr        #
#                                                                              #
# **************************************************************************** #

NAME = libftprintf.a

LIBFT_SRC = ft_atoi.c ft_memccpy.c ft_putendl.c ft_strcmp.c ft_strlen.c ft_strrchr.c aff_bin.c\
ft_bzero.c ft_memchr.c ft_putendl_fd.c ft_strcpy.c ft_strmap.c ft_strsplit.c ft_taille_nb.c\
ft_isalnum.c ft_memcmp.c ft_putnbr.c ft_strdel.c ft_strmapi.c ft_strstr.c ft_putlong.c add_char.c\
ft_isalpha.c ft_memcpy.c ft_putnbr_fd.c  ft_strdup.c ft_strncat.c ft_strsub.c add_str.c\
ft_isascii.c ft_memdel.c ft_putstr.c ft_strequ.c ft_strncmp.c ft_strtrim.c ft_strcpyend.c\
ft_isdigit.c ft_memmove.c ft_putstr_fd.c  ft_striter.c ft_strncpy.c ft_tolower.c ft_strccpy.c\
ft_isprint.c ft_memset.c ft_strcat.c ft_striteri.c ft_strnequ.c ft_toupper.c ft_putlong.c\
ft_itoa.c ft_putchar.c ft_strchr.c ft_strjoin.c ft_strnew.c ft_swap.c ft_strsplit_nbr.c ft_split_space.c\
ft_memalloc.c ft_putchar_fd.c ft_strclr.c ft_strlcat.c ft_strnstr.c ft_strlen_fd.c ft_fdcpy.c\
ft_lstadd.c ft_lstiter.c ft_lstmap.c ft_lstnew.c ft_lstdel.c ft_lstdelone.c get_next_line.c\

LIBFT_OBJ = $(addprefix libft/,$(LIBFT_SRC:.c=.o))

SRC_PATH = src
SRC_NAME = ft_printf.c format_remp.c conv_d.c conv_int.c conv_s.c conv_long_int.c conv_ls.c\
unicode.c conv_size_t.c conv_char.c conv_short_int.c change_conv.c conv_x.c conv_o.c conv_b.c colors.c

OBJ_PATH = obj
OBJ_NAME = $(SRC_NAME:.c=.o)

CC = gcc
CFLAGS = -g -Wall -Werror -Wextra

CPPFLAGS = -I includes -I libft/includes

LDFLAGS = -L libft
LDLIBS = -lft
LIB = libft/libft.a

SRC = $(addprefix $(SRC_PATH)/,$(SRC_NAME))
OBJ = $(addprefix $(OBJ_PATH)/,$(OBJ_NAME))

all: $(NAME)

$(NAME): $(OBJ)
	@printf "\n"
	@make -C libft
	@ar rc $@ $(OBJ) $(LIBFT_OBJ)
	@ranlib $(NAME)
	@echo "Compilation of \033[33;1m$(NAME)\033[0;1m: [\033[1;5;32mOK\033[0;1m]"

$(OBJ_PATH)/%.o: $(SRC_PATH)/%.c
	@printf "\033[34;1m| \033[0;1m"
	@mkdir $(OBJ_PATH) 2> /dev/null || true
	@$(CC) $(CFLAGS) -c $< $(CPPFLAGS) -o $@

clean:
	@make -C libft clean
	@rm -f $(OBJ)
	@rm -rf $(OBJ_PATH)
	@echo "\033[33;1m$(NAME)\033[0;1m: objects deleted"

fclean: clean
	@make -C libft fclean
	@rm -rf $(NAME)
	@echo "\033[33;1m$(NAME)\033[0;1m: $(NAME) deleted"

re: fclean all

.PHONY: all clean fclean re
