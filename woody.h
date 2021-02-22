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
	uint64_t	new_entry;
	uint32_t	new_code_offset;
	uint32_t	bss_size;
	Elf64_Addr	old_entry;
	Elf64_Addr	old_entry_offset;
	Elf64_Addr	text_diff_addr;
	uint32_t	bits_added;
	uint64_t	key;
	Elf64_Shdr	*text;
	Elf64_Phdr	*seg;
}				elf_info;


void	ft_quit(char *str);

void	init_check_address(void *ptr, int size);
void	check_address(void *ptr);
int		is_in_address(void *ptr);
void	*get_ptr_start(void);
void	*get_ptr_end(void);

void	rebuild_binary(void *ptr);
void	modify_payload(void *pl, int sz, void *jmp_addr, void *text_diff, uint64_t size, uint64_t key);

void	encrypt(void *ptr, elf_info *info);

#endif
