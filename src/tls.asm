; nasmhttp - tls.asm
; TLS support via OpenSSL (libssl, libcrypto)
; Author: manjunathh-xyz

global tls_init
global tls_accept
global tls_read
global tls_write
global tls_close
global tls_cleanup

extern SSL_library_init
extern SSL_load_error_strings
extern TLS_server_method
extern SSL_CTX_new
extern SSL_CTX_use_certificate_file
extern SSL_CTX_use_PrivateKey_file
extern SSL_CTX_check_private_key
extern SSL_CTX_free
extern SSL_new
extern SSL_set_fd
extern SSL_accept
extern SSL_read
extern SSL_write
extern SSL_shutdown
extern SSL_free
extern ERR_print_errors_fp

%define SSL_FILETYPE_PEM    1

section .data
    cert_path   db "certs/cert.pem", 0
    key_path    db "certs/key.pem", 0

    err_ctx     db "Error: failed to create SSL context", 0x0A, 0
    err_ctx_len equ $ - err_ctx
    err_cert    db "Error: failed to load certificate", 0x0A, 0
    err_cert_len equ $ - err_cert
    err_key     db "Error: failed to load private key", 0x0A, 0
    err_key_len equ $ - err_key
    err_check   db "Error: certificate and key do not match", 0x0A, 0
    err_check_len equ $ - err_check
    err_ssl     db "Error: failed to create SSL object", 0x0A, 0
    err_ssl_len equ $ - err_ssl
    err_accept  db "Error: TLS handshake failed", 0x0A, 0
    err_accept_len equ $ - err_accept

section .bss
    ssl_ctx     resq 1

section .text

; tls_init - initialize OpenSSL and create SSL context
; rdi = server fd (unused here, kept for API consistency)
; returns: rax = SSL_CTX* on success, -1 on error
tls_init:
    push rbp
    mov rbp, rsp
    push rbx

    ; SSL_library_init()
    call SSL_library_init

    ; SSL_load_error_strings()
    call SSL_load_error_strings

    ; method = TLS_server_method()
    call TLS_server_method
    mov rbx, rax

    ; ctx = SSL_CTX_new(method)
    mov rdi, rbx
    call SSL_CTX_new
    test rax, rax
    jz .err_ctx
    mov rbx, rax
    mov [ssl_ctx], rax

    ; SSL_CTX_use_certificate_file(ctx, cert_path, SSL_FILETYPE_PEM)
    mov rdi, rbx
    mov rsi, cert_path
    mov rdx, SSL_FILETYPE_PEM
    call SSL_CTX_use_certificate_file
    cmp rax, 1
    jne .err_cert

    ; SSL_CTX_use_PrivateKey_file(ctx, key_path, SSL_FILETYPE_PEM)
    mov rdi, rbx
    mov rsi, key_path
    mov rdx, SSL_FILETYPE_PEM
    call SSL_CTX_use_PrivateKey_file
    cmp rax, 1
    jne .err_key

    ; SSL_CTX_check_private_key(ctx)
    mov rdi, rbx
    call SSL_CTX_check_private_key
    cmp rax, 1
    jne .err_check

    mov rax, rbx
    pop rbx
    pop rbp
    ret

.err_ctx:
    mov rax, 1
    mov rdi, 2
    mov rsi, err_ctx
    mov rdx, err_ctx_len
    syscall
    mov rax, -1
    pop rbx
    pop rbp
    ret

.err_cert:
    mov rax, 1
    mov rdi, 2
    mov rsi, err_cert
    mov rdx, err_cert_len
    syscall
    mov rdi, rbx
    call SSL_CTX_free
    mov rax, -1
    pop rbx
    pop rbp
    ret

.err_key:
    mov rax, 1
    mov rdi, 2
    mov rsi, err_key
    mov rdx, err_key_len
    syscall
    mov rdi, rbx
    call SSL_CTX_free
    mov rax, -1
    pop rbx
    pop rbp
    ret

.err_check:
    mov rax, 1
    mov rdi, 2
    mov rsi, err_check
    mov rdx, err_check_len
    syscall
    mov rdi, rbx
    call SSL_CTX_free
    mov rax, -1
    pop rbx
    pop rbp
    ret

; tls_accept - perform TLS handshake on a client connection
; rdi = client fd
; rsi = SSL_CTX*
; returns: rax = SSL* on success, -1 on error
tls_accept:
    push rbp
    mov rbp, rsp
    push rbx
    push r12

    mov r12, rdi            ; save client fd
    mov rbx, rsi            ; save ctx

    ; ssl = SSL_new(ctx)
    mov rdi, rbx
    call SSL_new
    test rax, rax
    jz .err_ssl
    mov rbx, rax

    ; SSL_set_fd(ssl, client_fd)
    mov rdi, rbx
    mov rsi, r12
    call SSL_set_fd

    ; SSL_accept(ssl)
    mov rdi, rbx
    call SSL_accept
    cmp rax, 1
    jne .err_accept

    mov rax, rbx
    pop r12
    pop rbx
    pop rbp
    ret

.err_ssl:
    mov rax, 1
    mov rdi, 2
    mov rsi, err_ssl
    mov rdx, err_ssl_len
    syscall
    mov rax, -1
    pop r12
    pop rbx
    pop rbp
    ret

.err_accept:
    mov rax, 1
    mov rdi, 2
    mov rsi, err_accept
    mov rdx, err_accept_len
    syscall
    mov rdi, rbx
    call SSL_free
    mov rax, -1
    pop r12
    pop rbx
    pop rbp
    ret

; tls_read - read data from TLS connection
; rdi = SSL*
; rsi = buffer
; rdx = max bytes
; returns: rax = bytes read
tls_read:
    push rbp
    mov rbp, rsp

    call SSL_read

    pop rbp
    ret

; tls_write - write data to TLS connection
; rdi = SSL*
; rsi = buffer
; rdx = length
; returns: rax = bytes written
tls_write:
    push rbp
    mov rbp, rsp

    call SSL_write

    pop rbp
    ret

; tls_close - shutdown and free a TLS connection
; rdi = SSL*
tls_close:
    push rbp
    mov rbp, rsp
    push rbx

    mov rbx, rdi

    ; SSL_shutdown(ssl)
    call SSL_shutdown

    ; SSL_free(ssl)
    mov rdi, rbx
    call SSL_free

    pop rbx
    pop rbp
    ret

; tls_cleanup - free the SSL context
; rdi = SSL_CTX*
tls_cleanup:
    push rbp
    mov rbp, rsp

    call SSL_CTX_free

    pop rbp
    ret

