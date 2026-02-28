; nasmhttp - static.asm
; Static file serving
; Author: manjunathh-xyz

global static_serve
global static_get_ext

extern response_404
extern response_500
extern tls_write
extern headers_content_type
extern headers_build_response_headers

%define SYS_OPEN        2
%define SYS_READ        0
%define SYS_CLOSE       3
%define SYS_FSTAT       5
%define O_RDONLY        0

%define FILE_BUF_SIZE   65536
%define PATH_BUF_SIZE   512

%define ST_SIZE_OFF     48      ; offset of st_size in stat struct

section .data
    public_dir      db "public", 0
    public_dir_len  equ $ - public_dir - 1

    status_200_line db "HTTP/1.1 200 OK", 0x0D, 0x0A, 0
    status_200_len  equ $ - status_200_line - 1

    err_open        db "Error: could not open file", 0x0A, 0
    err_open_len    equ $ - err_open

section .bss
    file_buf        resb FILE_BUF_SIZE
    stat_buf        resb 144        ; struct stat size
    full_path       resb PATH_BUF_SIZE
    ext_buf         resb 16

section .text

; static_serve - serve a static file from public/
; rdi = SSL*
; rsi = request path string
static_serve:
    push rbp
    mov rbp, rsp
    push rbx
    push r12
    push r13
    push r14

    mov rbx, rdi            ; ssl
    mov r12, rsi            ; path

    ; build full path: "public" + path
    lea rdi, [full_path]
    mov rsi, public_dir
    mov rcx, public_dir_len
    rep movsb

    ; append request path
    mov rsi, r12
.copy_path:
    mov al, [rsi]
    mov [rdi], al
    inc rdi
    inc rsi
    test al, al
    jnz .copy_path

    ; null terminate
    dec rdi
    mov byte [rdi], 0

    ; get file extension
    lea rdi, [full_path]
    call static_get_ext
    mov r13, rax            ; extension ptr

    ; open file
    mov rax, SYS_OPEN
    lea rdi, [full_path]
    mov rsi, O_RDONLY
    xor rdx, rdx
    syscall

    test rax, rax
    js .file_not_found
    mov r14, rax            ; fd

    ; fstat to get file size
    mov rax, SYS_FSTAT
    mov rdi, r14
    lea rsi, [stat_buf]
    syscall

    test rax, rax
    js .file_error

    mov r8, [stat_buf + ST_SIZE_OFF]    ; file size

    ; get content type from extension
    mov rdi, r13
    call headers_content_type
    mov r9, rax             ; content-type string

    ; build response headers
    mov rdi, r9
    mov rsi, r8
    xor rdx, rdx            ; close connection
    call headers_build_response_headers

    ; send status line first
    mov rdi, rbx
    mov rsi, status_200_line
    mov rdx, status_200_len
    call tls_write

    ; send headers
    mov rdi, rbx
    ; rax has header buf ptr, rdx has header len from headers_build_response_headers
    ; need to save those
    push rax
    push rdx

    pop rdx
    pop rsi
    mov rdi, rbx
    call tls_write

    ; read and send file in chunks
.read_loop:
    mov rax, SYS_READ
    mov rdi, r14
    lea rsi, [file_buf]
    mov rdx, FILE_BUF_SIZE
    syscall

    test rax, rax
    jle .read_done

    mov rdx, rax
    mov rdi, rbx
    lea rsi, [file_buf]
    call tls_write
    jmp .read_loop

.read_done:
    mov rax, SYS_CLOSE
    mov rdi, r14
    syscall
    jmp .done

.file_not_found:
    mov rdi, rbx
    call response_404
    jmp .done

.file_error:
    mov rax, SYS_CLOSE
    mov rdi, r14
    syscall
    mov rdi, rbx
    call response_500

.done:
    pop r14
    pop r13
    pop r12
    pop rbx
    pop rbp
    ret

; static_get_ext - get file extension from path
; rdi = path string
; returns: rax = extension ptr (points inside path), or empty string
static_get_ext:
    push rbx
    push rcx

    mov rbx, rdi
    xor rcx, rcx
    xor rax, rax            ; last dot position

.scan:
    mov cl, [rbx]
    test cl, cl
    jz .done
    cmp cl, '.'
    jne .next
    lea rax, [rbx+1]       ; point past dot
.next:
    inc rbx
    jmp .scan

.done:
    ; if no dot found, rax = 0, return empty ext
    test rax, rax
    jnz .ret_ext
    lea rax, [empty_ext]
.ret_ext:
    pop rcx
    pop rbx
    ret

section .data
    empty_ext   db 0
    
