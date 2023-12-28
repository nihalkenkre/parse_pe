section .text
extern _GetStdHandle@4
extern _WriteFile@20

; arg0: str                     [ebp + 8]
strlen:
    push ebp
    mov ebp, esp

    ; [ebp - 4] = output strlen
    sub esp, 4                          ; alloc local variable space
    mov dword [ebp - 4], 0              ; strlen = 0
    
    jmp .while_condition
    .loop:
        inc dword [ebp - 4]

        .while_condition:
            xor ebx, ebx
            mov ebx, [ebp + 8]          ; str ptr in ebx
            mov dword eax, [ebp - 4]    ; strlen counter in eax
            mov bl, [ebx + eax]         ; str char in bl

            cmp bl, 0
            jne .loop

    mov dword eax, [ebp - 4]            ; strlen in eax
    add esp, 4                          ; free local variable space

    add esp, 4                          ; free arg stack

    leave
    ret

; arg0: wstr                     [ebp + 8]
wstrlen:
    push ebp
    mov ebp, esp

    ; [ebp - 4] = output strlen
    sub esp, 4                          ; allocate local variables space
    mov dword [ebp - 4], 0              ; strlen = 0
    
    jmp .while_condition
    .loop:
        inc dword [ebp - 4]

        .while_condition:
            xor ebx, ebx
            mov ebx, [ebp + 8]          ; str ptr in ebx
            mov dword eax, [ebp - 4]    ; strlen counter in eax
            mov dword edx, 2
            mul edx
            mov bl, [ebx + eax]         ; str char in bl

            cmp bl, 0
            jne .loop


    mov dword eax, [ebp - 4]            ; strlen in eax
    add esp, 4                          ; free local variable space

    add esp, 4                          ; free arg stack

    leave
    ret

; arg0: dst                     [ebp + 8]
; arg1: src                     [ebp + 12]
; arg2: nBytes                  [ebp + 16]
memcpy:
    push ebp
    mov ebp, esp

    mov dword ecx, [ebp + 16]
    mov dword esi, [ebp + 12]
    mov dword edi, [ebp + 8]

    rep movsb

    add esp, 12                 ; free arg stack

    leave
    ret

; arg0: str1                    [ebp + 8]
; arg1: str1 len                [ebp + 12]
; arg2: wstr2                   [ebp + 16]

; ret: 1 if equal 0 otherwise   eax
strcmpAW:
    push ebp
    mov ebp, esp

    pusha
    
    mov esi, [ebp + 8]
    mov ecx, [ebp + 12]
    mov edi, [ebp + 16]

    .loop:
        xor eax, eax
        mov al, [esi]

        xor ebx, ebx
        mov bl, [edi]

        cmp al, bl

        jne .loop_end_not_equal

        inc esi
        add edi, 2
        dec dword ecx 
        jnz .loop

.loop_end_equal:
    popa

    mov eax, 1
    
    add esp, 12                 ; free arg stack

    leave
    ret

.loop_end_not_equal:
    popa

    xor eax, eax

    add esp, 12                 ; free arg stack

    leave
    ret

; arg0: str1                    [ebp + 8]
; arg1: str1 len                [ebp + 12]
; arg2: wstr                    [ebp + 16]

; ret: 1 if equal 0 otherwise   eax
strcmpiAW:
    push ebp
    mov ebp, esp

    pusha

    mov esi, [ebp + 8]
    mov ecx, [ebp + 12]
    mov edi, [ebp + 16]

    .loop:
        xor eax, eax
        mov al, [esi]

        xor ebx, ebx
        mov bl, [edi]

        cmp al, bl
        jg .al_more_than_bl
        jl .al_less_than_bl
        
        inc esi
        add edi, 2
        dec dword ecx
        jnz .loop

    .loop_end_equal:
        popa

        mov eax, 1

        add esp, 12             ; free arg stack
    
        leave
        ret

        .al_more_than_bl:
            add bl, 32
            cmp al, bl

            jne .loop_end_not_equal

            inc esi
            add edi, 2
            dec dword ecx
            jnz .loop

        .al_less_than_bl:
            add al, 32
            cmp al, bl

            jne .loop_end_not_equal
         
            inc esi
            add edi, 2       
            dec dword ecx
            jnz .loop


    .loop_end_not_equal:
        popa

        xor eax, eax

        add esp, 12             ; free arg stack

        leave
        ret


; arg0: str1                    [ebp + 8]
; arg1: str1 len                [ebp + 12]
; arg2: str2                    [ebp + 16]

; ret: 1 if equal 0 otherwise   eax
strcmpAA:
    push ebp
    mov ebp, esp

    pusha
    
    mov esi, [ebp + 8]          
    mov ecx, [ebp + 12]
    mov edi, [ebp + 16]

    repe cmpsb
    jecxz .equal

    .not_equal:
        popa

        xor eax, eax

        add esp, 12             ; free arg stack

        leave
        ret

    .equal:
        popa

        mov eax, 1

        add esp, 12             ; free arg stack
    
        leave
        ret

; arg0: str1                    [ebp + 8]
; arg1: str1 len                [ebp + 12]
; arg2: wstr2                   [ebp + 16]

; ret: 1 if equal 0 otherwise   eax
strcmpiAA:
    push ebp
    mov ebp, esp

    pusha

    mov esi, [ebp + 8]
    mov ecx, [ebp + 12]
    mov edi, [ebp + 16]

    .loop:
        xor eax, eax
        mov al, [esi]

        xor ebx, ebx
        mov bl, [edi]

        cmp al, bl
        jg .al_more_than_bl
        jl .al_less_than_bl
        
        inc esi
        inc edi
        dec dword ecx
        jnz .loop

    .loop_end_equal:
        popa

        mov eax, 1
    
        ; add esp, 12             ; free arg stack

        leave
        ret

        .al_more_than_bl:
            add bl, 32
            cmp al, bl

            jne .loop_end_not_equal

            inc esi
            inc edi
            dec dword ecx
            jnz .loop

        .al_less_than_bl:
            add al, 32
            cmp al, bl

            jne .loop_end_not_equal
         
            inc esi
            inc edi
            dec dword ecx
            jnz .loop

    .loop_end_not_equal:
        popa

        xor eax, eax

        add esp, 12             ; free arg stack

        leave
        ret


; arg0: data            [ebp + 8]
; arg1: data_len        [ebp + 12]
; arg2: key             [ebp + 16]
; arg3: key_len         [ebp + 20]
my_xor_xor:
    push ebp
    mov ebp, esp

    sub esp, 8

    pusha

    ; edx = data_len_reverse_counter_index(i)
    ; eax = key_len_counter_index(j)

    xor edx, edx
    xor eax, eax

    .data_loop:
        cmp eax, [ebp + 20]

        jnc .continue_data_loop
        xor eax, eax

    .continue_data_loop:
        mov ebx, [ebp + 8]
        mov byte bl, [ebx + edx]            ; data char in bl

        mov ecx, [ebp + 16]
        mov byte cl, [ecx + eax]            ; key char in cl

        xor bl, cl

        mov ecx, [ebp + 8]
        add ecx, edx

        mov byte [ecx], bl

        inc dword eax

        inc dword edx
        cmp edx, [ebp + 12]
        jnz .data_loop

    popa

    add esp, 8

    add esp, 16             ; free arg stack

    leave
    ret


; arg0: data            [ebp + 8]
; arg1: data_len        [ebp + 12]
; arg2: key             [ebp + 16]
; arg3: key_len         [ebp + 20]
my_xor:
    push ebp
    mov ebp, esp

    ; [ebp - 4] = i, [ebp - 8] = j
    ; [ebp - 12] = bInput, [ebp - 16] = b
    ; [ebp - 20] = data_bit_i, [ebp - 24] = key_bit_j
    ; [ebp - 28] = bit_xor

    sub esp, 28
    pusha

    mov dword [ebp - 4], 0          ; i = 0
    mov dword [ebp - 8], 0          ; j = 0

    .data_loop:
        mov eax, [ebp - 8]          ; j in eax
        cmp eax, [ebp + 20]         ; if (j == key_len)

        jne .continue_data_loop
        xor eax, eax
        mov [ebp - 8], eax          ; j = 0

    .continue_data_loop:
        mov dword [ebp - 12], 0     ; bInput = 0
        mov dword [ebp - 16], 0     ; b = 0

        .bit_loop:
            ; bit test data
            xor edx, edx

            mov dword edx, [ebp + 8]        ; ptr to data in edx
            mov dword ebx, [ebp - 4]        ; i in ebx

            xor eax, eax
            mov al, [edx + ebx]            ; data char in al
            xor ebx, ebx
            mov bl, [ebp - 16]             ; b in bl

            bt eax, ebx

            jc .data_bit_is_set
            mov dword [ebp - 20], 0         ; data_bit_i = 0
            jmp .bit_loop_continue_data

            .data_bit_is_set:
                mov dword [ebp - 20], 1     ; data_bit_i = 1
            
        .bit_loop_continue_data:
            ; bit test key
            xor edx, edx

            mov dword edx, [ebp + 16]       ; ptr to key in edx
            mov dword ebx, [ebp - 8]        ; j in ebx

            xor eax, eax
            mov al, [edx + ebx]             ; key char in al
            xor ebx, ebx
            mov bl, [ebp - 16]              ; b in bl

            bt eax, ebx

            jc .key_bit_is_set
            mov dword [ebp - 24], 0         ; key_bit_j = 0
            jmp .bit_loop_continue_key

            .key_bit_is_set:
                mov dword [ebp - 24], 1     ; key_bit_j = 1

        .bit_loop_continue_key:
            xor eax, eax
            mov al, [ebp - 20]          ; data_bit_i in al
            cmp al, [ebp - 24]          ; data_bit_i == key_bit_j ?

            je .bits_equal
            ; bits are unequal
            mov dword eax, 1
            xor ecx, ecx
            mov cl, [ebp - 16]          ; b in cl
            shl al, cl
            mov [ebp - 28], al          ; bit_xor = (data_bit_i != key_bit_j) << b;
            
            jmp .bits_continue
            .bits_equal:
            ; bits are equal 
            ; so (data_bit_i != key_bit_j) == 0
                mov dword [ebp - 28], 0     ; bit_xor = 0

        .bits_continue:
            xor eax, eax
            mov al, [ebp - 12]              ; bInput in al 
            or al, [ebp - 28]               ; bInput != bit_xor

            mov [ebp - 12], al              ; al to bInput
            
            inc dword [ebp - 16]            ; ++b
            mov dword eax, [ebp - 16]       ; b in eax
            cmp dword eax, 8                ; b == 8 ?
            jnz .bit_loop


        mov dword edx, [ebp + 8]        ; ptr to data in edx
        mov dword ebx, [ebp - 4]        ; i in ebx

        xor eax, eax
        mov al, [ebp - 12]              ; bInput in al
        mov [edx + ebx], al             ; data[i] = bInput

        inc dword [ebp - 8]             ; ++j

        inc dword [ebp - 4]             ; ++i
        mov eax, [ebp - 4]              ; i in eax
        cmp eax, [ebp + 12]             ; i == data_len ?

        jnz .data_loop

    popa
    add esp, 28
    
    add esp, 16                         ; free arg stack

    leave
    ret

; arg0: string buffer       [ebp + 8]
; arg1: chr                 [ebp + 12]
strchr:
    push ebp
    mov ebp, esp
    
    ; [ebp - 4] = cRet, [ebp - 8] = strlen
    ; [ebp - 12] = c
    sub esp, 12
    pusha

    mov dword [ebp - 4], 0      ; cRet = 0

    push dword [ebp + 8]
    call strlen
    mov [ebp - 8], eax          ; strlen in [ebp -8]
    add esp, 4

    mov dword [ebp - 12], 0     ; c = 0
    .loop:
        mov dword edx, [ebp + 8]        ; ptr to string in edx
        mov dword ebx, [ebp - 12]       ; c in ebx

        mov cl, [edx + ebx]     ; sStr[c]

        cmp byte cl, [ebp + 12]         ; string[c] = chr ?

        je .equal

        inc dword [ebp - 12]    ; ++c
        mov eax,  [ebp - 8]     ; strlen in eax
        cmp [ebp - 12], eax     ; c < strlen

        jne .loop

        .equal:
            add edx, ebx 
            mov [ebp - 4], edx ; cRet = str + c

    popa
    add esp, 12

    mov eax, [ebp - 4]

    add esp, 8                  ; free arg stack

    leave
    ret

; arg0: string buffer      [ebp + 8]
; arg1: string len         [ebp + 12]
print_string:
    push ebp
    mov ebp, esp

    ; [ebp - 4] = std handle
    sub esp, 4                  ; allocate local variable space

    push STD_HANDLE_ENUM
    call _GetStdHandle@4

    cmp eax, INVALID_HANDLE_VALUE
    je .shutdown

    mov [ebp - 4], eax          ; std handle in [ebp - 4]

    cmp byte [ebp + 12], 0           ; strlen == 0 ? if yes then call strlen
    jne .continue
        push dword [ebp + 8]
        call strlen

        mov [ebp + 12], eax          ; strlen in [ebp + 12]

.continue:

    push 0
    push 0
    push dword [ebp + 12]
    push dword [ebp + 8]
    push dword [ebp - 4]
    call _WriteFile@20 

    xor eax, eax

    .shutdown:
        add esp, 4                  ; free local variable space

        add esp, 8                  ; free arg stack

        leave
        ret

;arg0  : ptr to string template         [ebp + 8]
;arg1..: values for placeholders        [ebp + 12] onwards
printf:
    push ebp
    mov ebp, esp

    leave
    ret