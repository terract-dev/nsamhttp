; nasmhttp - main.asm
; Entry point for the HTTPS server
; Author: manjunathh-xyz

global _start
extern socket_init
extern tls_init
extern server_loop
extern graceful_shutdown

section .data
    msg_start   db "nasmhttp v0.1.0 starting...", 0x0A, 0
    msg_start_len equ $ - msg_start - 1
    msg_ready   db "Server ready on port 8443", 0x0A, 0
    msg_ready_len equ $ - msg_ready - 1
    msg_shutdown db "Shutting down...", 0x0A, 0
    msg_shutdown_len equ $ - msg_shutdown - 1
    err_socket  db "ERROR: socket_init failed", 0x0A, 0
    err_socket_len equ $ - err_socket - 1
    err_tls     db "ERROR: tls_init failed", 0x0A, 0
    err_tls_len equ $ - err_tls - 1

section .bss
    server_fd   resq 1
    tls_ctx     resq 1

section .text

_start:
    ; Align stack to 16 bytes (required for C ABI / OpenSSL calls)
    and rsp, ~0xF

    ; Print startup message
    mov rax, 1
    mov rdi, 1
    mov rsi, msg_start
    mov rdx, msg_start_len
    syscall

    ; Initialize socket
    call socket_init
    test rax, rax
    js .err_socket

    mov [server_fd], rax

    ; Initialize TLS context
    mov rdi, rax
    call tls_init
    test rax, rax
    js .err_tls

    mov [tls_ctx], rax

    ; Print ready message
    mov rax, 1
    mov rdi, 1
    mov rsi, msg_ready
    mov rdx, msg_ready_len
    syscall

    ; Enter main server loop
    mov rdi, [server_fd]
    mov rsi, [tls_ctx]
    call server_loop

    ; Graceful shutdown
    mov rdi, [server_fd]
    mov rsi, [tls_ctx]
    call graceful_shutdown

    mov rax, 1
    mov rdi, 1
    mov rsi, msg_shutdown
    mov rdx, msg_shutdown_len
    syscall

    ; Exit 0
    mov rax, 60
    xor rdi, rdi
    syscall

.err_socket:
    mov rax, 1
    mov rdi, 2
    mov rsi, err_socket
    mov rdx, err_socket_len
    syscall
    mov rax, 60
    mov rdi, 1
    syscall

.err_tls:
    mov rax, 1
    mov rdi, 2
    mov rsi, err_tls
    mov rdx, err_tls_len
    syscall
    mov rax, 60
    mov rdi, 1
    syscall

.error:
    ; Exit 1
    mov rax, 60
    mov rdi, 1
    syscall
