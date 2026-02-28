; nasmhttp - response.asm
; HTTP/1.1 response building
; Author: manjunathh-xyz

global response_build
global response_send
global response_200
global response_201
global response_204
global response_301
global response_302
global response_400
global response_404
global response_405
global response_500

extern tls_write

%define RESP_BUF_SIZE   8192

section .data
    ; Status lines
    status_200  db "HTTP/1.1 200 OK", 0x0D, 0x0A, 0
    status_200_len equ $ - status_200
    status_201  db "HTTP/1.1 201 Created", 0x0D, 0x0A, 0
    status_201_len equ $ - status_201
    status_204  db "HTTP/1.1 204 No Content", 0x0D, 0x0A, 0
    status_204_len equ $ - status_204
    status_301  db "HTTP/1.1 301 Moved Permanently", 0x0D, 0x0A, 0
    status_301_len equ $ - status_301
    status_302  db "HTTP/1.1 302 Found", 0x0D, 0x0A, 0
    status_302_len equ $ - status_302
    status_400  db "HTTP/1.1 400 Bad Request", 0x0D, 0x0A, 0
    status_400_len equ $ - status_400
    status_404  db "HTTP/1.1 404 Not Found", 0x0D, 0x0A, 0
    status_404_len equ $ - status_404
    status_405  db "HTTP/1.1 405 Method Not Allowed", 0x0D, 0x0A, 0
    status_405_len equ $ - status_405
    status_500  db "HTTP/1.1 500 Internal Server Error", 0x0D, 0x0A, 0
    status_500_len equ $ - status_500

    ; Common headers
    hdr_server      db "Server: nasmhttp/0.1.0", 0x0D, 0x0A, 0
    hdr_server_len  equ $ - hdr_server
    hdr_ct_json     db "Content-Type: application/json", 0x0D, 0x0A, 0
    hdr_ct_json_len equ $ - hdr_ct_json
    hdr_ct_html     db "Content-Type: text/html", 0x0D, 0x0A, 0
    hdr_ct_html_len equ $ - hdr_ct_html
    hdr_ct_plain    db "Content-Type: text/plain", 0x0D, 0x0A, 0
    hdr_ct_plain_len equ $ - hdr_ct_plain
    hdr_conn_close  db "Connection: close", 0x0D, 0x0A, 0
    hdr_conn_close_len equ $ - hdr_conn_close
    hdr_conn_keep   db "Connection: keep-alive", 0x0D, 0x0A, 0
    hdr_conn_keep_len equ $ - hdr_conn_keep
    hdr_cl_prefix   db "Content-Length: ", 0
    hdr_cl_prefix_len equ $ - hdr_cl_prefix
    crlf            db 0x0D, 0x0A, 0
    crlf_len        equ 2

    ; Default bodies
    body_200    db "{}", 0
    body_200_len equ 2
    body_201    db "{}", 0
    body_201_len equ 2
    body_400    db '{"error":"Bad Request"}', 0
    body_400_len equ $ - body_400 - 1
    body_404    db '{"error":"Not Found"}', 0
    body_404_len equ $ - body_404 - 1
    body_405    db '{"error":"Method Not Allowed"}', 0
    body_405_len equ $ - body_405 - 1
    body_500    db '{"error":"Internal Server Error"}', 0
    body_500_len equ $ - body_500 - 1

section .bss
    resp_buf    resb RESP_BUF_SIZE
    cl_str      resb 24             ; content-length number as string

section .text

; response_build - build a full HTTP response into resp_buf
; rdi = status string ptr
; rsi = status string len
; rdx = body ptr (or 0 for no body)
; rcx = body len
; returns: rax = response ptr, rdx = response length
response_build:
    push rbp
    mov rbp, rsp
    push rbx
    push r12
    push r13
    push r14
    push r15

    mov r12, rdi            ; status str
    mov r13, rsi            ; status len
    mov r14, rdx            ; body ptr
    mov r15, rcx            ; body len

    lea rbx, [resp_buf]
    xor r8, r8              ; total length

    ; copy status line
    mov rdi, rbx
    mov rsi, r12
    mov rcx, r13
    rep movsb
    add r8, r13
    lea rbx, [resp_buf + r8]

    ; Server header
    mov rdi, rbx
    mov rsi, hdr_server
    mov rcx, hdr_server_len
    rep movsb
    add r8, hdr_server_len
    lea rbx, [resp_buf + r8]

    ; Content-Type: application/json
    mov rdi, rbx
    mov rsi, hdr_ct_json
    mov rcx, hdr_ct_json_len
    rep movsb
    add r8, hdr_ct_json_len
    lea rbx, [resp_buf + r8]

    ; Connection: close
    mov rdi, rbx
    mov rsi, hdr_conn_close
    mov rcx, hdr_conn_close_len
    rep movsb
    add r8, hdr_conn_close_len
    lea rbx, [resp_buf + r8]

    ; Content-Length: <n>
    test r14, r14
    jz .no_body

    mov rdi, rbx
    mov rsi, hdr_cl_prefix
    mov rcx, hdr_cl_prefix_len
    rep movsb
    add r8, hdr_cl_prefix_len
    lea rbx, [resp_buf + r8]

    ; convert body len to string
    mov rdi, r15
    lea rsi, [cl_str]
    call .uint_to_str
    ; rax = length of string

    mov rdi, rbx
    lea rsi, [cl_str]
    mov rcx, rax
    rep movsb
    add r8, rax
    lea rbx, [resp_buf + r8]

    ; CRLF after content-length
    mov word [rbx], 0x0A0D
    add rbx, 2
    add r8, 2

    ; blank line
    mov word [rbx], 0x0A0D
    add rbx, 2
    add r8, 2

    ; copy body
    mov rdi, rbx
    mov rsi, r14
    mov rcx, r15
    rep movsb
    add r8, r15
    jmp .done

.no_body:
    ; blank line only
    mov word [rbx], 0x0A0D
    add r8, 2

.done:
    lea rax, [resp_buf]
    mov rdx, r8

    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    pop rbp
    ret

; uint_to_str - convert unsigned 64-bit int to decimal string
; rdi = number
; rsi = output buffer
; returns: rax = string length
.uint_to_str:
    push rbx
    push rcx
    push rdx
    push r8

    mov rbx, rsi
    mov r8, 10
    xor rcx, rcx

    ; handle zero
    test rdi, rdi
    jnz .uts_loop
    mov byte [rsi], '0'
    mov rax, 1
    pop r8
    pop rdx
    pop rcx
    pop rbx
    ret

.uts_loop:
    test rdi, rdi
    jz .uts_reverse
    xor rdx, rdx
    mov rax, rdi
    div r8
    mov rdi, rax
    add dl, '0'
    push rdx
    inc rcx
    jmp .uts_loop

.uts_reverse:
    mov r8, rcx
.uts_rev_loop:
    pop rdx
    mov [rsi], dl
    inc rsi
    loop .uts_rev_loop

    mov rax, r8
    pop r8
    pop rdx
    pop rcx
    pop rbx
    ret

; response_send - send built response over TLS
; rdi = SSL*
; rsi = response ptr
; rdx = response length
response_send:
    push rbp
    mov rbp, rsp
    ; rdi, rsi, rdx already set correctly for tls_write
    call tls_write
    pop rbp
    ret

; --- Convenience response builders ---

; response_200 - send 200 OK with optional body
; rdi = SSL*, rsi = body ptr (or 0), rdx = body len
response_200:
    push rbp
    mov rbp, rsp
    push rbx
    push r12
    push r13

    mov rbx, rdi
    mov r12, rsi
    mov r13, rdx

    mov rdi, status_200
    mov rsi, status_200_len
    mov rdx, r12
    mov rcx, r13
    call response_build

    mov rdi, rbx
    mov rsi, rax
    ; rdx already has length
    call response_send

    pop r13
    pop r12
    pop rbx
    pop rbp
    ret

; response_201 - send 201 Created
; rdi = SSL*, rsi = body ptr, rdx = body len
response_201:
    push rbp
    mov rbp, rsp
    push rbx
    push r12
    push r13

    mov rbx, rdi
    mov r12, rsi
    mov r13, rdx

    mov rdi, status_201
    mov rsi, status_201_len
    mov rdx, r12
    mov rcx, r13
    call response_build

    mov rdi, rbx
    mov rsi, rax
    call response_send

    pop r13
    pop r12
    pop rbx
    pop rbp
    ret

; response_204 - send 204 No Content
; rdi = SSL*
response_204:
    push rbp
    mov rbp, rsp
    push rbx

    mov rbx, rdi

    mov rdi, status_204
    mov rsi, status_204_len
    xor rdx, rdx
    xor rcx, rcx
    call response_build

    mov rdi, rbx
    mov rsi, rax
    call response_send

    pop rbx
    pop rbp
    ret

; response_400 - send 400 Bad Request
; rdi = SSL*
response_400:
    push rbp
    mov rbp, rsp
    push rbx

    mov rbx, rdi

    mov rdi, status_400
    mov rsi, status_400_len
    mov rdx, body_400
    mov rcx, body_400_len
    call response_build

    mov rdi, rbx
    mov rsi, rax
    call response_send

    pop rbx
    pop rbp
    ret

; response_404 - send 404 Not Found
; rdi = SSL*
response_404:
    push rbp
    mov rbp, rsp
    push rbx

    mov rbx, rdi

    mov rdi, status_404
    mov rsi, status_404_len
    mov rdx, body_404
    mov rcx, body_404_len
    call response_build

    mov rdi, rbx
    mov rsi, rax
    call response_send

    pop rbx
    pop rbp
    ret

; response_405 - send 405 Method Not Allowed
; rdi = SSL*
response_405:
    push rbp
    mov rbp, rsp
    push rbx

    mov rbx, rdi

    mov rdi, status_405
    mov rsi, status_405_len
    mov rdx, body_405
    mov rcx, body_405_len
    call response_build

    mov rdi, rbx
    mov rsi, rax
    call response_send

    pop rbx
    pop rbp
    ret

; response_500 - send 500 Internal Server Error
; rdi = SSL*
response_500:
    push rbp
    mov rbp, rsp
    push rbx

    mov rbx, rdi

    mov rdi, status_500
    mov rsi, status_500_len
    mov rdx, body_500
    mov rcx, body_500_len
    call response_build

    mov rdi, rbx
    mov rsi, rax
    call response_send

    pop rbx
    pop rbp
    ret

