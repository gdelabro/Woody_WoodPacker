/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   woody.h                                            :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: gdelabro <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2021/01/27 17:53:22 by gdelabro          #+#    #+#             */
/*   Updated: 2021/01/27 17:54:33 by gdelabro         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#ifndef WOODY_H
# define WOODY_H

# include "ft_printf/ft_printf.h"
# include <stdio.h>
# include <stdlib.h>
# include <stdint.h>
# include <sys/mman.h>
# include <sys/stat.h>
# include <fcntl.h>
# include <elf.h>

typedef struct
{
	uint32_t	section_size;
	Elf64_Addr	old_entry;
	uint64_t	text_offset;
	uint64_t	text_addr;
	uint64_t	text_size;
	uint8_t		align;
	Elf64_Shdr	new_section;
}				elf_info;


void	ft_quit(char *str);

void	rebuild_binary(void *ptr);
void	modify_payload(void *pl, int sz, void *jmp_addr);

void	init_check_address(void *ptr, int size);
void	check_address(void *ptr);
int		is_in_address(void *ptr);
void	*get_ptr_start(void);
void	*get_ptr_end(void);

#endif
