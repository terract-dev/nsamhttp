; nasmhttp - http.asm
; HTTP/1.1 request parsing
; Author: jackson-peg

global http_parse_request
global http_get_method
global http_get_path
global http_get_header
global http_get_body

; Request struct layout (at buffer start):
;   [0]   method ptr   (8 bytes)
;   [8]   path ptr     (8 bytes)
;   [16]  version ptr  (8 bytes)
;   [24]  headers ptr  (8 bytes)
;   [32]  body ptr     (8 bytes)
;   [40]  body_len     (8 bytes)
;   [48]  header_count (8 bytes)

%define REQ_METHOD      0
%define REQ_PATH        8
%define REQ_VERSION     16
%define REQ_HEADERS     24
%define REQ_BODY        32
%define REQ_BODY_LEN    40
%define REQ_HDR_COUNT   48
%define REQ_STRUCT_SIZE 56

%define MAX_HEADERS     32
%define HDR_NAME_OFF    0
%define HDR_VAL_OFF     8
%define HDR_ENTRY_SIZE  16

section .data
    method_get      db "GET", 0
    method_post     db "POST", 0
    method_put      db "PUT", 0
    method_delete   db "DELETE", 0
    method_patch    db "PATCH", 0

    cr              equ 0x0D
    lf              equ 0x0A
    sp              equ 0x20
    colon           equ 0x3A

section .bss
    ; parsed request struct
    req_struct      resb REQ_STRUCT_SIZE
    ; header name/value pairs (name ptr, value ptr)
    hdr_table       resb (MAX_HEADERS * HDR_ENTRY_SIZE)

section .text

; http_parse_request - parse raw HTTP request buffer
; rdi = raw buffer pointer
; rsi = buffer length
; returns: rax = pointer to req_struct on success, 0 on error
http_parse_request:
    push rbp
    mov rbp, rsp
    push rbx
    push r12
    push r13
    push r14
    push r15

    mov r12, rdi            ; buffer start
    mov r13, rsi            ; buffer length
    mov r14, rdi            ; current parse position
    xor r15, r15            ; header count

    ; zero out req struct
    lea rdi, [req_struct]
    mov rcx, REQ_STRUCT_SIZE
    xor al, al
    rep stosb

    ; zero out header table
    lea rdi, [hdr_table]
    mov rcx, MAX_HEADERS * HDR_ENTRY_SIZE
    xor al, al
    rep stosb

    ; --- Parse request line ---
    ; method starts at buffer start
    mov [req_struct + REQ_METHOD], r14

    ; find space after method
    mov rdi, r14
    mov rsi, r13
    call .find_space
    test rax, rax
    jz .error
    mov byte [rax], 0       ; null terminate method
    lea r14, [rax+1]        ; advance past space

    ; path starts here
    mov [req_struct + REQ_PATH], r14

    ; find space after path
    mov rdi, r14
    mov rsi, r13
    call .find_space
    test rax, rax
    jz .error
    mov byte [rax], 0       ; null terminate path
    lea r14, [rax+1]        ; advance past space

    ; version starts here
    mov [req_struct + REQ_VERSION], r14

    ; find CRLF after version
    mov rdi, r14
    mov rsi, r13
    call .find_crlf
    test rax, rax
    jz .error
    mov byte [rax], 0       ; null terminate version
    lea r14, [rax+2]        ; advance past CRLF

    ; set headers table pointer
    lea rbx, [hdr_table]
    mov [req_struct + REQ_HEADERS], rbx

    ; --- Parse headers ---
.parse_header:
    ; check for empty line (CRLF CRLF = end of headers)
    cmp byte [r14], cr
    je .end_headers
    cmp byte [r14], lf
    je .end_headers

    ; too many headers?
    cmp r15, MAX_HEADERS
    jge .end_headers

    ; header name starts here
    mov [rbx + HDR_NAME_OFF], r14

    ; find colon
    mov rdi, r14
    mov rsi, r13
    call .find_colon
    test rax, rax
    jz .end_headers
    mov byte [rax], 0       ; null terminate name
    lea r14, [rax+1]        ; skip colon

    ; skip optional space
    cmp byte [r14], sp
    jne .no_space
    inc r14
.no_space:

    ; header value starts here
    mov [rbx + HDR_VAL_OFF], r14

    ; find CRLF
    mov rdi, r14
    mov rsi, r13
    call .find_crlf
    test rax, rax
    jz .end_headers
    mov byte [rax], 0       ; null terminate value
    lea r14, [rax+2]        ; skip CRLF

    add rbx, HDR_ENTRY_SIZE
    inc r15
    jmp .parse_header

.end_headers:
    ; skip final CRLF
    cmp byte [r14], cr
    jne .skip_check_lf
    inc r14
.skip_check_lf:
    cmp byte [r14], lf
    jne .body_start
    inc r14

.body_start:
    ; body starts here
    mov [req_struct + REQ_BODY], r14

    ; body length = buffer_end - current
    mov rax, r12
    add rax, r13
    sub rax, r14
    mov [req_struct + REQ_BODY_LEN], rax
    mov [req_struct + REQ_HDR_COUNT], r15

    lea rax, [req_struct]
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    pop rbp
    ret

.error:
    xor rax, rax
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    pop rbp
    ret

; find_space - find next space in buffer
; rdi = start, rsi = len
; returns: rax = pointer to space, 0 if not found
.find_space:
    push rcx
    mov rcx, rsi
.fs_loop:
    cmp byte [rdi], sp
    je .fs_found
    inc rdi
    loop .fs_loop
    xor rax, rax
    pop rcx
    ret
.fs_found:
    mov rax, rdi
    pop rcx
    ret

; find_crlf - find CRLF sequence
; rdi = start, rsi = len
; returns: rax = pointer to CR, 0 if not found
.find_crlf:
    push rcx
    mov rcx, rsi
    dec rcx
.fc_loop:
    cmp byte [rdi], cr
    jne .fc_next
    cmp byte [rdi+1], lf
    je .fc_found
.fc_next:
    inc rdi
    loop .fc_loop
    xor rax, rax
    pop rcx
    ret
.fc_found:
    mov rax, rdi
    pop rcx
    ret

; find_colon - find colon in buffer
; rdi = start, rsi = len
; returns: rax = pointer to colon, 0 if not found
.find_colon:
    push rcx
    mov rcx, rsi
.fcolon_loop:
    cmp byte [rdi], colon
    je .fcolon_found
    cmp byte [rdi], cr
    je .fcolon_notfound
    inc rdi
    loop .fcolon_loop
.fcolon_notfound:
    xor rax, rax
    pop rcx
    ret
.fcolon_found:
    mov rax, rdi
    pop rcx
    ret

; http_get_method - get method string from parsed request
; rdi = req_struct ptr
; returns: rax = method string ptr
http_get_method:
    mov rax, [rdi + REQ_METHOD]
    ret

; http_get_path - get path string from parsed request
; rdi = req_struct ptr
; returns: rax = path string ptr
http_get_path:
    mov rax, [rdi + REQ_PATH]
    ret

; http_get_body - get body ptr and length
; rdi = req_struct ptr
; rsi = ptr to store length
; returns: rax = body ptr
http_get_body:
    mov rax, [rdi + REQ_BODY]
    mov rbx, [rdi + REQ_BODY_LEN]
    mov [rsi], rbx
    ret

; http_get_header - find a header value by name
; rdi = req_struct ptr
; rsi = header name string
; returns: rax = value ptr, 0 if not found
http_get_header:
    push rbx
    push r12
    push r13
    push r14

    mov r12, [rdi + REQ_HEADERS]   ; header table
    mov r13, [rdi + REQ_HDR_COUNT] ; count
    mov r14, rsi                    ; target name

    xor rcx, rcx
.hdr_loop:
    cmp rcx, r13
    jge .hdr_not_found

    mov rdi, [r12 + HDR_NAME_OFF]
    mov rsi, r14
    call .strcmp
    test rax, rax
    jz .hdr_found

    add r12, HDR_ENTRY_SIZE
    inc rcx
    jmp .hdr_loop

.hdr_found:
    mov rax, [r12 + HDR_VAL_OFF]
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

.hdr_not_found:
    xor rax, rax
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; strcmp - case insensitive compare
; rdi = s1, rsi = s2
; returns: rax = 0 if equal
.strcmp:
    push rcx
.sc_loop:
    mov al, [rdi]
    mov cl, [rsi]
    ; lowercase
    cmp al, 'A'
    jl .sc_noconv1
    cmp al, 'Z'
    jg .sc_noconv1
    add al, 32
.sc_noconv1:
    cmp cl, 'A'
    jl .sc_noconv2
    cmp cl, 'Z'
    jg .sc_noconv2
    add cl, 32
.sc_noconv2:
    cmp al, cl
    jne .sc_ne
    test al, al
    jz .sc_eq
    inc rdi
    inc rsi
    jmp .sc_loop
.sc_eq:
    xor rax, rax
    pop rcx
    ret
.sc_ne:
    mov rax, 1
    pop rcx
    ret
  
