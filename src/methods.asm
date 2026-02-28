; nasmhttp - methods.asm
; HTTP method identification and dispatch
; Author: manjunathh-xyz

global method_identify
global method_dispatch

%define METHOD_GET      1
%define METHOD_POST     2
%define METHOD_PUT      3
%define METHOD_DELETE   4
%define METHOD_PATCH    5
%define METHOD_UNKNOWN  0

section .data
    str_get     db "GET", 0
    str_post    db "POST", 0
    str_put     db "PUT", 0
    str_delete  db "DELETE", 0
    str_patch   db "PATCH", 0

section .text

; method_identify - identify HTTP method from string
; rdi = method string ptr
; returns: rax = method constant (METHOD_GET etc)
method_identify:
    push rbx

    ; check GET
    mov rsi, str_get
    call .streq
    test rax, rax
    jnz .is_get

    ; check POST
    mov rdi, rdi
    mov rsi, str_post
    call .streq
    test rax, rax
    jnz .is_post

    ; check PUT
    mov rsi, str_put
    call .streq
    test rax, rax
    jnz .is_put

    ; check DELETE
    mov rsi, str_delete
    call .streq
    test rax, rax
    jnz .is_delete

    ; check PATCH
    mov rsi, str_patch
    call .streq
    test rax, rax
    jnz .is_patch

    mov rax, METHOD_UNKNOWN
    pop rbx
    ret

.is_get:
    mov rax, METHOD_GET
    pop rbx
    ret

.is_post:
    mov rax, METHOD_POST
    pop rbx
    ret

.is_put:
    mov rax, METHOD_PUT
    pop rbx
    ret

.is_delete:
    mov rax, METHOD_DELETE
    pop rbx
    ret

.is_patch:
    mov rax, METHOD_PATCH
    pop rbx
    ret

; streq - compare two null-terminated strings exactly
; rdi = s1, rsi = s2
; returns: rax = 1 if equal, 0 if not
.streq:
    push rcx
.se_loop:
    mov al, [rdi]
    mov cl, [rsi]
    cmp al, cl
    jne .se_ne
    test al, al
    jz .se_eq
    inc rdi
    inc rsi
    jmp .se_loop
.se_eq:
    mov rax, 1
    pop rcx
    ret
.se_ne:
    xor rax, rax
    pop rcx
    ret

; method_dispatch - dispatch to correct handler based on method
; rdi = method constant
; rsi = SSL*
; rdx = req_struct ptr
; rcx = handler table ptr (array of fn ptrs: get,post,put,delete,patch,unknown)
method_dispatch:
    push rbp
    mov rbp, rsp
    push rbx
    push r12
    push r13
    push r14

    mov rbx, rdi            ; method
    mov r12, rsi            ; ssl
    mov r13, rdx            ; req
    mov r14, rcx            ; handler table

    ; bounds check method (1-5)
    cmp rbx, METHOD_UNKNOWN
    je .dispatch_unknown
    cmp rbx, METHOD_PATCH
    jg .dispatch_unknown

    ; handler table: index 0=get,1=post,2=put,3=delete,4=patch
    dec rbx                 ; 0-based
    lea rax, [r14 + rbx*8]
    mov rax, [rax]          ; load fn ptr

    test rax, rax
    jz .dispatch_unknown

    ; call handler(ssl, req)
    mov rdi, r12
    mov rsi, r13
    call rax

    pop r14
    pop r13
    pop r12
    pop rbx
    pop rbp
    ret

.dispatch_unknown:
    ; call unknown handler (index 5)
    mov rax, [r14 + 5*8]
    test rax, rax
    jz .done
    mov rdi, r12
    mov rsi, r13
    call rax
.done:
    pop r14
    pop r13
    pop r12
    pop rbx
    pop rbp
    ret

