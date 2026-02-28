; nasmhttp - headers.asm
; HTTP header utilities
; Author: manjunathh-xyz

global headers_content_type
global headers_content_length
global headers_connection
global headers_add
global headers_build_response_headers

%define HDR_BUF_SIZE    2048

section .data
    ; Content-Type values
    ct_json         db "application/json", 0
    ct_html         db "text/html", 0
    ct_plain        db "text/plain", 0
    ct_css          db "text/css", 0
    ct_js           db "application/javascript", 0
    ct_octet        db "application/octet-stream", 0

    ; Connection values
    conn_close      db "close", 0
    conn_keep       db "keep-alive", 0

    ; Header name strings
    hdr_name_ct     db "Content-Type", 0
    hdr_name_cl     db "Content-Length", 0
    hdr_name_conn   db "Connection", 0
    hdr_name_server db "Server", 0

    ; Server value
    server_val      db "nasmhttp/0.1.0", 0

    hdr_sep         db ": ", 0
    hdr_sep_len     equ 2
    crlf            db 0x0D, 0x0A, 0
    crlf_len        equ 2

section .bss
    hdr_buf         resb HDR_BUF_SIZE
    hdr_buf_pos     resq 1

section .text

; headers_content_type - get content type string for extension
; rdi = file extension string (e.g. "html", "json")
; returns: rax = content-type string ptr
headers_content_type:
    push rbx

    mov rbx, rdi

    ; check json
    mov rsi, ext_json
    call hdr_streq
    
    jnz .ret_json

    ; check html
    mov rdi, rbx
    mov rsi, ext_html
    call hdr_streq
    
    jnz .ret_html

    ; check css
    mov rdi, rbx
    mov rsi, ext_css
    call hdr_streq
    
    jnz .ret_css

    ; check js
    mov rdi, rbx
    mov rsi, ext_js
    call hdr_streq
    
    jnz .ret_js

    ; check plain/txt
    mov rdi, rbx
    mov rsi, ext_txt
    call hdr_streq
    
    jnz .ret_plain

    ; default octet-stream
    mov rax, ct_octet
    pop rbx
    ret

.ret_json:
    mov rax, ct_json
    pop rbx
    ret

.ret_html:
    mov rax, ct_html
    pop rbx
    ret

.ret_css:
    mov rax, ct_css
    pop rbx
    ret

.ret_js:
    mov rax, ct_js
    pop rbx
    ret

.ret_plain:
    mov rax, ct_plain
    pop rbx
    ret

; streq utility
hdr_streq:
    push rcx
hdr_se_loop:
    mov al, [rdi]
    mov cl, [rsi]
    cmp al, cl
    jne hdr_se_ne
    test al, al
    jz hdr_se_eq
    inc rdi
    inc rsi
    jmp hdr_se_loop
hdr_se_eq:
    mov rax, 1
    pop rcx
    ret
hdr_se_ne:
    xor rax, rax
    pop rcx
    ret

; headers_add - append a header to the header buffer
; rdi = header name ptr
; rsi = header value ptr
; returns: rax = 0 on success
headers_add:
    push rbx
    push r12

    mov rbx, rdi            ; name
    mov r12, rsi            ; value

    mov r8, [hdr_buf_pos]
    lea r9, [hdr_buf + r8]

    ; copy name
    mov rdi, r9
    mov rsi, rbx
    call hdr_strcpy
    add r8, rax
    lea r9, [hdr_buf + r8]

    ; copy ": "
    mov byte [r9], ':'
    mov byte [r9+1], ' '
    add r9, 2
    add r8, 2

    ; copy value
    mov rdi, r9
    mov rsi, r12
    call hdr_strcpy
    add r8, rax
    lea r9, [hdr_buf + r8]

    ; CRLF
    mov word [r9], 0x0A0D
    add r8, 2

    mov [hdr_buf_pos], r8
    xor rax, rax

    pop r12
    pop rbx
    ret

; headers_build_response_headers - build standard response headers into buffer
; rdi = content-type string ptr
; rsi = content-length (u64)
; rdx = keep-alive flag (1 = keep-alive, 0 = close)
; returns: rax = header buffer ptr, rdx = length
headers_build_response_headers:
    push rbp
    mov rbp, rsp
    push rbx
    push r12
    push r13

    mov rbx, rdi            ; content type
    mov r12, rsi            ; content length
    mov r13, rdx            ; keep-alive

    ; reset buffer
    mov qword [hdr_buf_pos], 0

    ; Server header
    mov rdi, hdr_name_server
    mov rsi, server_val
    call headers_add

    ; Content-Type
    mov rdi, hdr_name_ct
    mov rsi, rbx
    call headers_add

    ; Content-Length
    mov rdi, hdr_name_cl
    ; convert r12 to string
    mov rax, r12
    lea rsi, [cl_num_buf]
    call hdr_uint_to_str
    ; null terminate
    mov byte [rsi + rax], 0
    mov rdi, hdr_name_cl
    lea rsi, [cl_num_buf]
    call headers_add

    ; Connection
    mov rdi, hdr_name_conn
    test r13, r13
    jz .conn_close
    mov rsi, conn_keep
    jmp .conn_set
.conn_close:
    mov rsi, conn_close
.conn_set:
    call headers_add

    ; final empty line
    mov r8, [hdr_buf_pos]
    lea r9, [hdr_buf + r8]
    mov word [r9], 0x0A0D
    add r8, 2
    mov [hdr_buf_pos], r8

    lea rax, [hdr_buf]
    mov rdx, r8

    pop r13
    pop r12
    pop rbx
    pop rbp
    ret

; strcpy - copy null terminated string, return length
; rdi = dst, rsi = src
; returns: rax = bytes copied (not including null)
hdr_strcpy:
    push rcx
    xor rcx, rcx
hdr_sc_loop:
    mov al, [rsi + rcx]
    mov [rdi + rcx], al
    test al, al
    jz hdr_sc_done
    inc rcx
    jmp hdr_sc_loop
hdr_sc_done:
    mov rax, rcx
    pop rcx
    ret

; uint_to_str
; rax = number, rsi = output buf
; returns: rax = length
hdr_uint_to_str:
    push rbx
    push rcx
    push rdx
    push r8
    push r9

    mov r9, rsi
    mov r8, 10
    xor rcx, rcx

    
    jnz hdr_uts_loop
    mov byte [rsi], '0'
    mov rax, 1
    pop r9
    pop r8
    pop rdx
    pop rcx
    pop rbx
    ret

hdr_uts_loop:
    
    jz hdr_uts_rev
    xor rdx, rdx
    div r8
    add dl, '0'
    push rdx
    inc rcx
    jmp .uts_loop

hdr_uts_rev:
    mov r8, rcx
hdr_uts_rl:
    pop rdx
    mov [rsi], dl
    inc rsi
    loop hdr_uts_rl
    mov rax, r8

    pop r9
    pop r8
    pop rdx
    pop rcx
    pop rbx
    ret

section .data
    ext_json    db "json", 0
    ext_html    db "html", 0
    ext_css     db "css", 0
    ext_js      db "js", 0
    ext_txt     db "txt", 0

section .bss
    cl_num_buf  resb 24
