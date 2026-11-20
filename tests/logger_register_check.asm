; Verify that the logger entry preserves the volatile x64 general-purpose
; registers and flags.  Results[0..6] receive rax, rcx, rdx, r8, r9, r10, r11.
; Results[7] receives the post-callback flags.

OPTION CASEMAP:NONE

.code

PUBLIC LoggerCallAndCheck
LoggerCallAndCheck PROC FRAME
    push rbx
    .pushreg rbx
    push rbp
    .pushreg rbp
    push rsi
    .pushreg rsi
    push rdi
    .pushreg rdi
    push r12
    .pushreg r12
    push r13
    .pushreg r13
    push r14
    .pushreg r14
    push r15
    .pushreg r15
    sub rsp, 28h
    .allocstack 28h
    .endprolog

    mov r13, rcx
    mov r12, rdx
    mov rax, 1111111111111111h
    mov rcx, 2222222222222222h
    mov rdx, 3333333333333333h
    mov r8, 4444444444444444h
    mov r9, 5555555555555555h
    mov r10, 6666666666666666h
    mov r11, 7777777777777777h
    stc
    call r13

    mov qword ptr [r12 + 0], rax
    mov qword ptr [r12 + 8], rcx
    mov qword ptr [r12 + 16], rdx
    mov qword ptr [r12 + 24], r8
    mov qword ptr [r12 + 32], r9
    mov qword ptr [r12 + 40], r10
    mov qword ptr [r12 + 48], r11
    pushfq
    pop qword ptr [r12 + 56]

    add rsp, 28h
    pop r15
    pop r14
    pop r13
    pop r12
    pop rdi
    pop rsi
    pop rbp
    pop rbx
    ret
LoggerCallAndCheck ENDP

END
