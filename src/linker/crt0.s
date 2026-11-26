.global _start
.text
_start:
    xor %ebp, %ebp
    mov (%rsp), %rdi
    lea 8(%rsp), %rsi
    lea 16(%rsp,%rdi,8), %rdx
    call main
    mov %rax, %rdi
    mov $60, %rax
    syscall
