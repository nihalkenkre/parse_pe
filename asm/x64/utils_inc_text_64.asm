section .text

extern GetStdHandle
extern WriteFile

; arg0 str         ; rcx
; ret: num chars
strlen:
    push rbp
    mov rbp, rsp

    ; [rbp - 8] = output strlen
    sub rsp, 8
    mov qword [rbp - 8], 0              ; strlen = 0

    jmp .while_condition
    .loop:
         inc qword [rbp - 8]                ; ++strlen

        .while_condition:
            mov qword rax, [rbp - 8]        ; strlen counter in rax
            mov byte bl, [rcx + rax]        ; str char in bl

            cmp bl, 0                       ; chr == 0 ?
            jne .loop
    
    mov qword rax, [rbp - 8]            ; strlen in rax
    add rsp, 8

    leave
    ret

; arg0: wstr        rcx
; ret: num chars
wstrlen:
    push rbp
    mov rbp, rsp

    ; [rbp - 8] = output strlen
    sub rsp, 8
    mov qword [rbp - 8], 0

    jmp .while_condition
    .loop:
         inc qword [rbp - 8]                ; ++strlen

        .while_condition:
            mov qword rax, [rbp - 8]        ; strlen counter in rax
            mov qword rdx, 2
            mul rdx
            mov byte bl, [rcx + rax]        ; str char in bl

            cmp bl, 0                       ; chr == 0 ?
            jne .loop
    
    mov qword rax, [rbp - 8]            ; strlen in rax
    add rsp, 8

    leave
    ret


; arg0: dst         rcx
; arg1: src         rdx
; arg2: nBytes      r8
memcpy:
    push rbp
    mov rbp, rsp

    mov rsi, rdx
    mov rdi, rcx
    mov rcx, r8

    rep movsb

    leave
    ret

; arg0: str1                        rcx
; arg1: str1.len                    rdx
; arg2: wstr2                       r8

; ret: 1 if equal 0 otherwise       rax
strcmpAW:
    push rbp
    mov rbp, rsp

    mov rsi, rcx
    mov rcx, rdx
    mov rdi, r8

    .loop:
        mov al, [rsi]
        mov bl, [rdi]

        cmp al, bl

        jne .loop_end_not_equal

        inc qword rsi
        add rdi, 2
        dec qword rcx
        jnz .loop

    .loop_end_equal:
        mov rax, 1

        leave
        ret

    .loop_end_not_equal:
        xor rax, rax

        leave
        ret

; arg0: str1                        rcx
; arg1: str1.len                    rdx
; arg2: wstr2                       r8

; ret: 1 if equal 0 otherwise       rax
strcmpiAW:
    push rbp
    mov rbp, rsp

    mov rsi, rcx
    mov rcx, rdx
    mov rdi, r8

    .loop:
        mov al, [rsi]
        mov bl, [rdi]

        cmp al, bl

        jg .al_more_than_bl
        jl .al_less_than_bl

        inc qword rsi
        add rdi, 2
        dec qword rcx
        jnz .loop

    .loop_end_equal:
        mov rax, 1

        leave
        ret

        .al_more_than_bl:
            add bl, 32
            cmp al, bl

            jne .loop_end_not_equal

            inc qword rsi
            add rdi, 2
            dec qword rcx
            jnz .loop
        
        .al_less_than_bl:
            add al, 32
            cmp al, bl

            jne .loop_end_not_equal

            inc qword rsi
            add rdi, 2
            dec qword rcx
            jnz .loop

    .loop_end_not_equal:
        xor rax, rax

        leave
        ret


; arg0: str1                    rcx
; arg1: str1 len                rdx
; arg2: str2                    r8

; ret: 1 if equal 0 otherwise   rax
strcmpAA:
    push rbp
    mov rbp, rsp

    mov rsi, rcx
    mov rcx, rdx
    mov rdi, r8

    repe cmpsb
    jrcxz .equal

    .not_equal:
        xor rax, rax

        leave
        ret

    .equal:
        mov rax, 1

        leave
        ret

; arg0: str1                    rcx 
; arg1: str1 len                rdx
; arg2: wstr2                   r8

; ret: 1 if equal 0 otherwise   rax
strcmpiAA:
    push rbp
    mov rbp, rsp

    mov rsi, rcx
    mov rcx, rdx
    mov rdi, r8

    .loop:
        xor rax, rax
        mov al, [rsi]

        xor rbx, rbx
        mov bl, [rdi]

        cmp al, bl
        jg .al_more_than_bl
        jl .al_less_than_bl
        
        inc rsi
        inc rdi
        dec rcx
        jnz .loop

    .loop_end_equal:

        mov rax, 1
    
        leave
        ret

        .al_more_than_bl:
            add bl, 32
            cmp al, bl

            jne .loop_end_not_equal

            inc rsi
            inc rdi
            dec rcx
            jnz .loop

        .al_less_than_bl:
            add al, 32
            cmp al, bl

            jne .loop_end_not_equal
         
            inc rsi
            inc rdi
            dec rcx
            jnz .loop

    .loop_end_not_equal:
        xor rax, rax

        leave
        ret

; arg0: data            rcx
; arg1: data_len        rdx
; arg2: key             r8
; arg3: key_len         r9
my_xor:
    push rbp
    mov rbp, rsp

    ; [rbp + 16] = data, [rbp + 24] = data_len
    ; [rbp + 32] = key, [rbp + 40] = key_len
    mov qword [rbp + 16], rcx
    mov qword [rbp + 24], rdx
    mov qword [rbp + 32], r8
    mov qword [rbp + 40], r9

    ; [rbp - 8] = i, [rbp - 16] = j
    ; [rbp - 24] = bInput, [rbp - 32] = b
    ; [rbp - 40] = data_bit_i, [rbp - 48] = key_bit_j
    ; [rbp - 56] = bit_xor
    sub rsp, 56

    mov qword [rbp - 8], 0          ; i = 0
    mov qword [rbp - 16], 0          ; j = 0

    .data_loop:
        mov rax, [rbp - 16]         ; j in rax
        cmp rax, [rbp + 40]         ; j == key_len ?

        jne .continue_data_loop
        xor rax, rax
        mov [rbp - 16], rax         ; j = 0
        
    .continue_data_loop:
        mov qword [rbp - 24], 0         ; bInput = 0
        mov qword [rbp - 32], 0         ; b = 0

        .bit_loop:
        ; bit test data
            xor rdx, rdx

            mov qword rdx, [rbp + 16]        ; ptr to data in rdx
            mov qword rbx, [rbp - 8]       ; i in rbx

            xor rax, rax
            mov al, [rdx + rbx]             ; data char in al

            xor rbx, rbx
            mov bl, [rbp - 32]              ; b in bl

            bt rax, rbx

            jc .data_bit_is_set
            mov qword [rbp - 40], 0         ; data_bit_i = 0
            jmp .bit_loop_continue_data

            .data_bit_is_set:
                mov qword [rbp - 40], 1     ; data_bit_i = 1

        .bit_loop_continue_data:
            ; bit test key

            xor rdx, rdx

            mov qword rdx, [rbp + 32]       ; ptr to key in rdx
            mov qword rbx, [rbp - 16]       ; j in rbx
            
            xor rax, rax
            mov al, [rdx + rbx]             ; key char in al

            xor rbx, rbx
            mov bl, [rbp - 32]              ; b in bl

            bt rax, rbx

            jc .key_bit_is_set
            mov qword [rbp - 48], 0         ; key_bit_i = 0
            jmp .bit_loop_continue_key

            .key_bit_is_set:
                mov qword [rbp - 48], 1     ; key_bit_i = 1

        .bit_loop_continue_key:
            xor rax, rax

            mov al, [rbp - 40]              ; data_bit_i in al
            cmp al, [rbp - 48]              ; data_bit_i == key_bit_i ?

            je .bits_equal
            ; bits are unequal
            mov qword rax, 1
            xor rcx, rcx
            mov cl, [rbp - 32]              ; b in cl
            shl al, cl
            mov [rbp - 56], al              ; bit_xor = (data_bit_i != key_bit_j) << b

            jmp .bits_continue
            .bits_equal:
            ; bits equal
            ; so (data_bit_i != key_bit_j) == 0
                mov qword [rbp - 56], 0     ; bit_xor = 0

        .bits_continue:
            xor rax, rax
            mov al, [rbp - 24]              ; bInput in al
            or al, [rbp - 56]               ; bInput |= bit_xor

            mov [rbp - 24], al              ; al to bInput

            inc qword [rbp - 32]            ; ++b
            mov qword rax, [rbp - 32]       ; b in rax
            cmp qword rax, 8                ; b == 8 ?
            jnz .bit_loop


        mov qword rdx, [rbp + 16]        ; ptr to data in rdx
        mov qword rbx, [rbp - 8]       ; i in rbx

        xor rax, rax
        mov al, [rbp - 24]              ; bInput in al
        mov [rdx + rbx], al             ; data[i] = bInput

        inc qword [rbp - 16]       ; ++j

        inc qword [rbp - 8]        ; ++i
        mov rax, [rbp - 8]         ; i in rax
        cmp rax, [rbp + 24]         ; i == data_len ?

        jne .data_loop

    add rsp, 56

    leave
    ret


; arg0: ptr to string           rcx
; arg1: chr                     rdx
strchr:
    push rbp
    mov rbp, rsp

    ; [rbp + 16] = ptr to string, [rbx + 24] = chr
    mov [rbp + 16], rcx
    mov [rbp + 24], rdx

    ; [rbp - 8] = cRet, [rbp - 16] = strlen
    ; [rbp - 24] = c
    sub rsp, 24 

    mov qword [rbp - 8], 0         ; cRet = 0

    sub rsp, 32
    call strlen                     ; rax = strlen
    add rsp, 32

    mov [rbp - 16], rax

    mov qword [rbp - 24], 0         ; c = 0
    .loop:
        mov rdx, [rbp + 16]          ; ptr to string in rdx     
        mov rbx, [rbp - 24]         ; c in rbx

        mov cl, [rdx + rbx]         ; sStr[c]

        cmp cl, [rbp + 24]          ; sStr[c] == chr ?

        je .equal

        inc qword [rbp - 24]        ; ++c
        mov rax, [rbp - 16]         ; strlen in rax
        cmp [rbp - 24], rax         ; c < strlen ?

        jne .loop

        .equal:
            add rdx, rbx
            mov [rbp - 8], rdx     ; cRet = str + c

    add rsp, 24

    mov rax, [ebp - 24]

    leave
    ret

; arg0: string buffer           rcx
; arg1: string len              rdx
print_string:
    push rbp
    mov rbp, rsp

    ; [rbp + 16] = ptr to string, [rbp + 24] = string len
    mov [rbp + 16], rcx          ; ptr to string
    mov [rbp + 24], rdx         ; string len

    ; [rbp - 8] = std handle
    sub rsp, 8                 ; allocate space for local variables

    sub rsp, 32
    mov rcx, -11                ; STD_HANDLE_ENUM
    call GetStdHandle
    add rsp, 32

    mov [rbp - 8], rax         ; std handle in rax

    cmp byte [rbp + 24], 0
    jne .continue
        sub rsp, 32
        mov rcx, [rbp + 16]
        call strlen

        mov [rbp + 24], rax

        add rsp, 32

.continue:
    sub rsp, 32 + 8 + 8         ; shadow space + 8 byte param + 16 byte stack align

    mov rcx, [rbp - 8]
    mov rdx, [rbp + 16]
    mov r8, [rbp + 24]
    xor r9, r9
    mov dword [rsp + 32], 0
    call WriteFile

    add rsp, 32 + 8 + 8

    add rsp, 8                 ; de allocate space for local variables

    leave
    ret