; nasmhttp - router.asm
; Basic HTTP request router
; Author: manjunathh-xyz

global router_init
global router_add_route
global router_dispatch
global server_loop
global graceful_shutdown

extern socket_accept
extern socket_close
extern tls_accept
extern tls_close
extern tls_read
extern http_parse_request
extern http_get_method
extern http_get_path
extern method_identify
extern method_dispatch
extern response_404
extern response_405
extern response_400
extern response_500
extern static_serve

%define MAX_ROUTES      64
%define ROUTE_PATH      0
%define ROUTE_METHODS   8       ; bitmask of allowed methods
%define ROUTE_HANDLER   16      ; fn ptr
%define ROUTE_SIZE      24

%define METHOD_GET      1
%define METHOD_POST     2
%define METHOD_PUT      3
%define METHOD_DELETE   4
%define METHOD_PATCH    5

%define READ_BUF_SIZE   8192

%define SYS_FORK        57
%define SYS_WAIT4       61
%define SYS_EXIT        60

section .data
    err_read    db "Error: failed to read request", 0x0A, 0
    err_read_len equ $ - err_read

    path_root   db "/", 0
    path_data   db "/data", 0
    path_static db "/static", 0

section .bss
    route_table resb (MAX_ROUTES * ROUTE_SIZE)
    route_count resq 1
    read_buf    resb READ_BUF_SIZE
    server_running resb 1

section .text

; router_init - initialize the route table
router_init:
    push rbp
    mov rbp, rsp

    lea rdi, [route_table]
    mov rcx, MAX_ROUTES * ROUTE_SIZE
    xor al, al
    rep stosb

    mov qword [route_count], 0
    mov byte [server_running], 1

    pop rbp
    ret

; router_add_route - register a route
; rdi = path string ptr
; rsi = method bitmask (1<<METHOD_GET | 1<<METHOD_POST etc)
; rdx = handler fn ptr
; returns: rax = 0 on success, -1 if table full
router_add_route:
    push rbp
    mov rbp, rsp
    push rbx
    push r12
    push r13

    mov rbx, rdi
    mov r12, rsi
    mov r13, rdx

    mov rax, [route_count]
    cmp rax, MAX_ROUTES
    jge .full

    ; calculate slot address
    imul rax, ROUTE_SIZE
    lea rcx, [route_table + rax]

    mov [rcx + ROUTE_PATH], rbx
    mov [rcx + ROUTE_METHODS], r12
    mov [rcx + ROUTE_HANDLER], r13

    inc qword [route_count]
    xor rax, rax

    pop r13
    pop r12
    pop rbx
    pop rbp
    ret

.full:
    mov rax, -1
    pop r13
    pop r12
    pop rbx
    pop rbp
    ret

; router_dispatch - find matching route and call handler
; rdi = SSL*
; rsi = req_struct ptr
; rdx = method constant
router_dispatch:
    push rbp
    mov rbp, rsp
    push rbx
    push r12
    push r13
    push r14
    push r15

    mov rbx, rdi            ; ssl
    mov r12, rsi            ; req
    mov r13, rdx            ; method

    ; get path from request
    mov rdi, r12
    call http_get_path
    mov r14, rax            ; path string

    ; search route table
    xor r15, r15            ; route index
    lea rcx, [route_table]

.search_loop:
    cmp r15, [route_count]
    jge .not_found

    ; compare path
    mov rdi, r14
    mov rsi, [rcx + ROUTE_PATH]
    call .path_match
    test rax, rax
    jnz .found

    add rcx, ROUTE_SIZE
    inc r15
    jmp .search_loop

.found:
    ; check method is allowed
    mov rax, 1
    mov cl, r13b
    shl rax, cl
    test rax, [rcx + ROUTE_METHODS]
    jz .method_not_allowed

    ; call handler(ssl, req)
    mov rdi, rbx
    mov rsi, r12
    mov rax, [rcx + ROUTE_HANDLER]
    call rax
    jmp .done

.not_found:
    mov rdi, rbx
    call response_404
    jmp .done

.method_not_allowed:
    mov rdi, rbx
    call response_405

.done:
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    pop rbp
    ret

; path_match - match request path against route pattern
; rdi = request path, rsi = route path
; returns: rax = 1 if match, 0 if not
.path_match:
    push rcx
.pm_loop:
    mov al, [rdi]
    mov cl, [rsi]
    cmp al, cl
    jne .pm_ne
    test cl, cl
    jz .pm_match
    inc rdi
    inc rsi
    jmp .pm_loop
.pm_match:
    mov rax, 1
    pop rcx
    ret
.pm_ne:
    ; allow trailing slash flexibility
    test cl, cl
    jnz .pm_no
    cmp al, '/'
    jne .pm_no
    inc rdi
    cmp byte [rdi], 0
    jne .pm_no
    mov rax, 1
    pop rcx
    ret
.pm_no:
    xor rax, rax
    pop rcx
    ret

; server_loop - main accept and dispatch loop
; rdi = server fd
; rsi = SSL_CTX*
server_loop:
    push rbp
    mov rbp, rsp
    push rbx
    push r12
    push r13

    mov rbx, rdi            ; server fd
    mov r12, rsi            ; ssl ctx

    ; initialize router
    call router_init

    ; register default routes
    mov rdi, path_root
    mov rsi, (1 << METHOD_GET)
    mov rdx, handle_root
    call router_add_route

    mov rdi, path_data
    mov rsi, (1 << METHOD_GET) | (1 << METHOD_POST) | (1 << METHOD_PUT) | (1 << METHOD_DELETE) | (1 << METHOD_PATCH)
    mov rdx, handle_data
    call router_add_route

.accept_loop:
    cmp byte [server_running], 0
    je .shutdown

    ; accept connection
    mov rdi, rbx
    call socket_accept
    test rax, rax
    js .accept_loop         ; retry on error
    mov r13, rax            ; client fd

    ; fork to handle connection
    mov rax, SYS_FORK
    syscall

    test rax, rax
    jz .child               ; child process
    js .accept_loop         ; fork error, retry

    ; parent: close client fd and continue
    mov rdi, r13
    call socket_close
    jmp .accept_loop

.child:
    ; child process: handle the connection
    ; close server fd
    mov rdi, rbx
    call socket_close

    ; TLS handshake
    mov rdi, r13
    mov rsi, r12
    call tls_accept
    test rax, rax
    js .child_done
    push rax                ; save SSL*

    ; read request
    mov rdi, rax
    lea rsi, [read_buf]
    mov rdx, READ_BUF_SIZE
    call tls_read
    test rax, rax
    jle .child_tls_close
    mov r13, rax            ; bytes read

    ; parse request
    lea rdi, [read_buf]
    mov rsi, r13
    call http_parse_request
    test rax, rax
    jz .child_bad_request
    push rax                ; save req struct

    ; get method
    mov rdi, rax
    call http_get_method
    mov rdi, rax
    call method_identify
    mov r13, rax            ; method constant

    ; dispatch
    mov rdi, [rsp+8]        ; ssl (below req)
    mov rsi, [rsp]          ; req
    mov rdx, r13
    call router_dispatch
    jmp .child_tls_close

.child_bad_request:
    mov rdi, [rsp]          ; ssl
    call response_400

.child_tls_close:
    pop rax                 ; req or ssl depending on path
    pop rax                 ; ssl
    mov rdi, rax
    call tls_close

.child_done:
    mov rdi, r13
    call socket_close

    ; exit child
    mov rax, SYS_EXIT
    xor rdi, rdi
    syscall

.shutdown:
    pop r13
    pop r12
    pop rbx
    pop rbp
    ret

; graceful_shutdown
; rdi = server fd
; rsi = SSL_CTX*
graceful_shutdown:
    push rbp
    mov rbp, rsp
    push rbx
    push r12

    mov rbx, rdi
    mov r12, rsi

    mov byte [server_running], 0

    mov rdi, rbx
    call socket_close

    mov rdi, r12
    ; tls_cleanup called from main

    pop r12
    pop rbx
    pop rbp
    ret

; --- Default route handlers ---

; handle_root - GET /
; rdi = SSL*, rsi = req_struct
handle_root:
    push rbp
    mov rbp, rsp
    push rbx

    mov rbx, rdi

    ; respond 200 with simple JSON
    mov rdi, rbx
    mov rsi, root_body
    mov rdx, root_body_len
    ; call response_200 (defined in response.asm)
    extern response_200
    call response_200

    pop rbx
    pop rbp
    ret

; handle_data - /data endpoint (GET/POST/PUT/DELETE/PATCH)
; rdi = SSL*, rsi = req_struct
handle_data:
    push rbp
    mov rbp, rsp
    push rbx
    push r12

    mov rbx, rdi
    mov r12, rsi

    ; get method
    mov rdi, r12
    call http_get_method
    mov rdi, rax
    call method_identify

    cmp rax, METHOD_GET
    je .data_get
    cmp rax, METHOD_POST
    je .data_post
    cmp rax, METHOD_PUT
    je .data_put
    cmp rax, METHOD_DELETE
    je .data_delete
    cmp rax, METHOD_PATCH
    je .data_patch
    jmp .data_done

.data_get:
    extern response_200
    mov rdi, rbx
    mov rsi, data_get_body
    mov rdx, data_get_body_len
    call response_200
    jmp .data_done

.data_post:
    extern response_201
    mov rdi, rbx
    mov rsi, data_post_body
    mov rdx, data_post_body_len
    call response_201
    jmp .data_done

.data_put:
    mov rdi, rbx
    mov rsi, data_put_body
    mov rdx, data_put_body_len
    call response_200
    jmp .data_done

.data_delete:
    extern response_204
    mov rdi, rbx
    call response_204
    jmp .data_done

.data_patch:
    mov rdi, rbx
    mov rsi, data_patch_body
    mov rdx, data_patch_body_len
    call response_200

.data_done:
    pop r12
    pop rbx
    pop rbp
    ret

section .data
    root_body       db '{"status":"ok","server":"nasmhttp"}', 0
    root_body_len   equ $ - root_body - 1
    data_get_body   db '{"data":"get ok"}', 0
    data_get_body_len equ $ - data_get_body - 1
    data_post_body  db '{"data":"created"}', 0
    data_post_body_len equ $ - data_post_body - 1
    data_put_body   db '{"data":"updated"}', 0
    data_put_body_len equ $ - data_put_body - 1
    data_patch_body db '{"data":"patched"}', 0
    data_patch_body_len equ $ - data_patch_body - 1
