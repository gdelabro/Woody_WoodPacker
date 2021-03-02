%macro PUSHAQ 0
        push rbx
        push rcx
        push rdx
        push rdi
        push rsi
        push r8
        push r9
        push r10
        push r11
        push r12
        push r13
        push r14
        push r15
%endmacro
%macro POPAQ 0
        pop r15
        pop r14
        pop r13
        pop r12
        pop r11
        pop r10
        pop r9
        pop r8
        pop rsi
        pop rdi
        pop rdx
        pop rcx
        pop rbx
%endmacro

section .text
_start:
	PUSHAQ

rc4_decrypt:
	lea		rdi, [rel _start]
	mov		rax, 0x2222222222222222  ; text entry
	sub		rdi, rax
	mov		rsi, 0x3333333333333333  ; size of section text
	mov		rdx, 0x4444444444444444  ; the key
	mov		rcx, 0x0

	while_rc4:
		cmp		rcx, rsi
		jge		jump_old_entry
		
		trunc_key:
			mov		r9, rsi
			sub		r9, rcx
			cmp		r9, 8
			jg		end_trunc
			mov		r10, r9
			mov		r9, 8
			sub		r9, r10
			imul	r9, 8
			push	rcx
			mov		rcx, r9
			shl		rdx, cl
			shr		rdx, cl
			pop		rcx
		end_trunc:

		mov		r9, QWORD [rdi]
		xor		r9, rdx
		mov		QWORD [rdi], r9
		add		rdi, 8
		add		rcx, 8
		jmp		while_rc4

jump_old_entry:
	mov		rdi, 1
	mov		rsi, 0x0a2e2e2e2e59
	push	rsi
	mov		rsi, 0x444f4f572e2e2e2e
	push	rsi
	mov		rsi, rsp
	mov		rdx, 14
	mov		rax, 1
	syscall
	add		rsp, 16

	lea		rdi, [rel _start]
	mov		rax, 0x1111111111111111
	sub		rdi, rax
	mov 		rax, rdi
	POPAQ
	jmp		rax
