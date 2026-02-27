; nasmhttp - socket.asm
; Socket creation, binding, listening and accepting connections
; Author: manjunathh-xyz

global socket_init
global socket_accept
global socket_close

%define AF_INET         2
%define SOCK_STREAM     1
%define SOL_SOCKET      1
%define SO_REUSEADDR    2
%define SO_REUSEPORT    15
%define IPPROTO_TCP     6
%define TCP_NODELAY     1

%define SYS_SOCKET      41
%define SYS_BIND        49
%define SYS_LISTEN      50
%define SYS_ACCEPT4     288
%define SYS_SETSOCKOPT  54
%define SYS_CLOSE       3

section .data
    err_socket  db "Error: failed to create socket", 0x0A, 0
    err_socket_len equ $ - err_socket
    err_bind    db "Error: failed to bind socket", 0x0A, 0
    err_bind_len equ $ - err_bind
    err_listen  db "Error: failed to listen", 0x0A, 0
    err_listen_len equ $ - err_listen

section .bss
    sockaddr    resb 16
    opt_val     resd 1

section .text

; socket_init - creates, binds and starts listening on a TCP socket
; returns: rax = fd on success, negative on error
socket_init:
    push rbp
    mov rbp, rsp
    push rbx
    push r12

    ; socket(AF_INET, SOCK_STREAM, 0)
    mov rax, SYS_SOCKET
    mov rdi, AF_INET
    mov rsi, SOCK_STREAM
    xor rdx, rdx
    syscall

    test rax, rax
    js .err_socket
    mov r12, rax            ; save fd

    ; setsockopt SO_REUSEADDR
    mov dword [opt_val], 1
    mov rax, SYS_SETSOCKOPT
    mov rdi, r12
    mov rsi, SOL_SOCKET
    mov rdx, SO_REUSEADDR
    lea r10, [opt_val]
    mov r8, 4
    syscall

    ; setsockopt SO_REUSEPORT
    mov rax, SYS_SETSOCKOPT
    mov rdi, r12
    mov rsi, SOL_SOCKET
    mov rdx, SO_REUSEPORT
    lea r10, [opt_val]
    mov r8, 4
    syscall

    ; setsockopt TCP_NODELAY
    mov rax, SYS_SETSOCKOPT
    mov rdi, r12
    mov rsi, IPPROTO_TCP
    mov rdx, TCP_NODELAY
    lea r10, [opt_val]
    mov r8, 4
    syscall

    ; build sockaddr_in
    ; sin_family = AF_INET (2)
    mov word [sockaddr], AF_INET
    ; sin_port = htons(8443) = 0xF320 (big-endian)
    mov word [sockaddr+2], 0x2021
    ; sin_addr = INADDR_ANY = 0
    mov dword [sockaddr+4], 0
    ; pad
    mov qword [sockaddr+8], 0

    ; bind(fd, sockaddr, 16)
    mov rax, SYS_BIND
    mov rdi, r12
    lea rsi, [sockaddr]
    mov rdx, 16
    syscall

    test rax, rax
    js .err_bind

    ; listen(fd, 128)
    mov rax, SYS_LISTEN
    mov rdi, r12
    mov rsi, 128
    syscall

    test rax, rax
    js .err_listen

    mov rax, r12
    pop r12
    pop rbx
    pop rbp
    ret

.err_socket:
    mov rax, 1
    mov rdi, 2
    mov rsi, err_socket
    mov rdx, err_socket_len
    syscall
    mov rax, -1
    pop r12
    pop rbx
    pop rbp
    ret

.err_bind:
    mov rax, 1
    mov rdi, 2
    mov rsi, err_bind
    mov rdx, err_bind_len
    syscall
    mov rdi, r12
    mov rax, SYS_CLOSE
    syscall
    mov rax, -1
    pop r12
    pop rbx
    pop rbp
    ret

.err_listen:
    mov rax, 1
    mov rdi, 2
    mov rsi, err_listen
    mov rdx, err_listen_len
    syscall
    mov rdi, r12
    mov rax, SYS_CLOSE
    syscall
    mov rax, -1
    pop r12
    pop rbx
    pop rbx
    pop rbp
    ret

; socket_accept - accepts a new connection
; rdi = server fd
; returns: rax = client fd on success, negative on error
socket_accept:
    push rbp
    mov rbp, rsp

    mov rax, SYS_ACCEPT4
    ; rdi already set
    xor rsi, rsi            ; addr = NULL
    xor rdx, rdx            ; addrlen = NULL
    xor r10, r10            ; flags = 0
    syscall

    pop rbp
    ret

; socket_close - closes a fd
; rdi = fd
socket_close:
    push rbp
    mov rbp, rsp

    mov rax, SYS_CLOSE
    syscall

    pop rbp
    ret
    
