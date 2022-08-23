.code

__clear_wp PROC

    push    rax                 
    mov     rax,cr0             
    and     eax,not 000010000h
    mov     cr0,rax
    pop     rax
    ret

__clear_wp ENDP

__set_wp PROC

    push    rax
    mov     rax,cr0
    or      eax,000010000h
    mov     cr0,rax
    pop     rax
    ret

__set_wp ENDP

__disable_interrupt PROC
	cli
	ret
__disable_interrupt ENDP

__enable_interrupt PROC
	sti
	ret
__enable_interrupt ENDP

end