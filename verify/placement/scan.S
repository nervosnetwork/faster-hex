.text
.globl scan_at
.type scan_at,@function
scan_at:
    push %rbp
    push %r13
    push %rbx
    mov %rdi,%r13
    mov %rdx,%rbx
    mov %rsi,%rax
    neg %rax
    mov $-1,%rbp
    jmp *%rcx
.Lvalid:
    mov %rsi,%rbp
.Lreturn:
    mov %rbp,%rax
    pop %rbx
    pop %r13
    pop %rbp
    ret
.size scan_at,.-scan_at

# The forward branch reaches +40, exactly as in the linked Rust function.
.macro place sym, offset
    .balign 128
    .fill \offset,1,0x90
    .globl \sym
    .type \sym,@function
\sym:
0:  lea (%rax,%rbp),%rcx
    cmp $-1,%rcx
    je 1f
    movzbl 1(%r13,%rbp),%ecx
    inc %rbp
    cmpb $255,(%rbx,%rcx)
    jne 0b
    jmp .Lreturn
    .fill 40-(.-\sym),1,0x90
1:  jmp .Lvalid
    .size \sym,.-\sym
.endm
.p2align 12
place loop_a16,16
place loop_a32,32
place loop_a48,48
.p2align 12
place loop_b48,48
place loop_b32,32
place loop_b16,16
.section .note.GNU-stack,"",@progbits
