section .text
global _parse_pe

%include '../utils/utils_32_text.asm'

; arg0: rva                         [ebp + 8]
; arg1: section headers             [ebp + 12]
; arg2: section header count        [ebp + 16]
;
; returns offset                    rax > 0
rva_to_offset:
    push ebp
    mov ebp, esp

    ; [ebp - 4] = return code
    ; [ebp - 8] = current section header
    sub esp, 8                                      ; allocate local variable space

    mov dword [ebp - 4], 0                          ; return code

    mov ecx, [ebp + 16]                             ; section header count
    mov edx, [ebp + 12]                             ; section headers

    .loop:
        mov [ebp - 8], edx                          ; current section header
        add edx, 12                                 ; virtual addr
        mov eax, [edx]                              ; virtual addr in eax

        add edx, 4                                  ; size of raw data
        add eax, [edx]                              ; eax = virtual addr + raw data size

        cmp eax, [ebp + 8]                          ; x >= rva
        jge .return_offset

        add edx, 24                                 ; add offset to end of section header (go to next header)

        dec ecx
        cmp ecx, 0
        jnz .loop

    .return_offset:
        mov eax, [ebp + 8]                          ; rva in eax
        mov edx, [ebp - 8]                          ; current section header

        add edx, 12                                 ; virtual addr
        sub eax, [edx]                              ; rva - virtual addr

        add edx, 8                                  ; raw data ptr
        add eax, [edx]                              ; rva - virtual addr + raw data pointer

        mov [ebp - 4], eax                          ; return value
    
.shutdown:
    mov eax, [ebp - 4]                              ; return value

    leave
    ret 12

; arg0: section headers             [ebp + 8]
; arg1: section header count        [ebp + 12]
loop_section_headers:
    push ebp
    mov ebp, esp

    ; ebp - 4 = return value
    sub esp, 4                                      ; allocate local variable space

    mov dword [ebp - 4], 0                          ; return value


    mov ecx, [ebp + 12]                             ; section header count
    mov edx, [ebp + 8]                              ; section headers

    .loop:
        add edx, 40                                 ; add section header size (next section header)

        dec ecx
        cmp ecx, 0
        jnz .loop

.shutdown:
    mov eax, [ebp - 4]                              ; return value

    leave
    ret 8

; arg0: import descriptor table rva     [ebp + 8]
; arg1: section headers                 [ebp + 12]
; arg2: section header count            [ebp + 16]
; arg3: base addr file contents         [ebp + 20]
loop_import_descriptor_table:
    push ebp
    mov ebp, esp

    ; ebp - 4 = return value
    ; ebp - 8 = offset
    sub esp, 8                                      ; allocate local variable space

    mov dword [ebp - 4], 0                          ; return value

    push dword [ebp + 16]                           ; section header count
    push dword [ebp + 12]                           ; section headers
    push dword [ebp + 8]                            ; IDT rva
    call rva_to_offset                              ; offset in eax

    cmp eax, 0                                      ; offset == 0 ?
    jle .shutdown

    mov [ebp - 8], eax                              ; offset
    mov eax, [ebp + 20]                             ; base addr
    add eax, [ebp - 8]                              ; base addr + offset
        
    .loop:
        add eax, 12                                 ; name RVA
        cmp dword [eax], 0
        je .loop_end

        add eax, 8                                  ; next IDT
        jmp .loop

    ; TODO: Loop through functions of each imported DLL

.loop_end:

.shutdown:
    mov eax, [ebp - 4]                              ; return value

    leave
    ret 16

; arg0: export directory table rva      [ebp + 8]
; arg1: section headers                 [ebp + 12]
; arg2: section header count            [ebp + 16]
; arg3: file contents base addr         [ebp + 20]
loop_export_descriptor_table:
    push ebp
    mov ebp, esp

    ; ebp - 4 = return value
    ; ebp - 8 = offset
    sub esp, 8                                      ; allocate local variable space

    mov dword [ebp - 4], 0                          ; return value

    push dword [ebp + 16]                           ; section header count
    push dword [ebp + 12]                           ; section headers
    push dword [ebp + 8]                            ; IDT rva
    call rva_to_offset                              ; offset in eax

    cmp eax, 0                                      ; offset == 0 ?
    jle .shutdown

    mov [ebp - 8], eax                              ; offset
    mov eax, [ebp + 20]                             ; base addr
    add eax, [ebp - 8]                              ; base + offset

    mov ecx, [eax + 20]                             ; number of entries in eat
    
    ; TODO: Loop through exported functions / names

.shutdown:
    mov eax, [ebp - 4]                              ; return value

    leave
    ret 16

; arg0: ptr to dos header           [ebp + 8]
; arg1: ptr to sprintf buffer       [ebp + 12]
; arg2: std handle                  [ebp + 16]
print_dos_header:
    push ebp
    mov ebp, esp

    ; ebp - 4 = return value
    sub esp, 4                      ; allocate local variable space
    mov dword [ebp - 4], 0          ; return value

    mov eax, [ebp + 8]              ; ptr to dos header

    push dword [eax + 64]

    push dword [eax + 60]
    push dword [eax + 58]
    push dword [eax + 56]
    push dword [eax + 54]
    push dword [eax + 52]
    push dword [eax + 50]
    push dword [eax + 48]
    push dword [eax + 46]
    push dword [eax + 44]
    push dword [eax + 42]
    push dword [eax + 40]
    push dword [eax + 38]
    push dword [eax + 36]
    push dword [eax + 34]
    push dword [eax + 32]
    push dword [eax + 30]
    push dword [eax + 28]
    push dword [eax + 26]
    push dword [eax + 24]
    push dword [eax + 22]
    push dword [eax + 20]
    push dword [eax + 18]
    push dword [eax + 16]
    push dword [eax + 14]
    push dword [eax + 12]
    push dword [eax + 10]
    push dword [eax + 8]
    push dword [eax + 6]
    push dword [eax + 4]
    push dword [eax + 2]
    push dword [eax]

    push dos_header_str
    push dword [ebp + 12]           ; sprintf buffer
    call sprintf
    add esp, 128

    push dword [ebp + 12]           ; sprintf buffer
    call strlen

    push eax                        ; strlen
    push dword [ebp + 12]           ; sprintf buffer
    push dword [ebp + 16]           ; std handle
    call print_string

.shutdown:
    mov eax, [ebp - 4]              ; return value

    leave
    ret 12

; arg0: ptr to nt header            [ebp + 8]
; arg1: sprintf buffer              [ebp + 12]
; arg2: std handle                  [ebp + 16]
print_nt_headers_signature:
    push ebp
    mov ebp, esp

    ; ebp - 4 = return value
    sub esp, 4                      ; allocate local variable space
    mov dword [ebp - 4], 0          ; return value

    mov eax, [ebp + 8]
    push dword [eax]                ; ptr to nt headers
    push nt_headers_signature_str
    push dword [ebp + 12]           ; sprintf buffer
    call sprintf
    add esp, 12

    push dword [ebp + 12]           ; sprintf buffer
    call strlen

    push eax                        ; strlen
    push dword [ebp + 12]           ; sprintf buffer
    push dword [ebp + 16]           ; std handle
    call print_string

.shutdown:
    mov eax, [ebp - 4]              ; return value

    leave
    ret 12

; arg0: ptr to nt header file header    [ebp + 8]
; arg1: sprintf buffer                  [ebp + 12]
; arg2: std handle                      [ebp + 16]
print_nt_headers_file_header:
    push ebp
    mov ebp, esp

    ; ebp - 4 = return value
    sub esp, 4                      ; allocate local variable space

    mov dword [ebp - 4], 0          ; return value

    mov eax, [ebp + 8]
    
    push dword [eax + 20]
    push dword [eax + 18]
    push dword [eax + 16]
    push dword [eax + 12]
    push dword [eax + 8]
    push dword [eax + 4]
    push dword [eax + 2]
    push dword [eax]                ; ptr to nt headers file header
    push nt_headers_file_header_str
    push dword [ebp + 12]           ; sprintf buffer
    call sprintf
    add esp, 40

    push dword [ebp + 12]           ; sprintf buffer
    call strlen
    
    push eax                        ; strlen
    push dword [ebp + 12]           ; sprintf buffer 
    push dword [ebp + 16]           ; std handle
    call print_string

.shutdown:
    mov eax, [ebp - 4]              ; return value

    leave
    ret 12

; arg0: ptr to nt header optional header    [ebp + 8]
; arg1: sprintf buffer                      [ebp + 12]
; arg2: std handle                          [ebp + 16]
print_nt_headers_optional_header:
    push ebp
    mov ebp, esp

    ; ebp - 4 = return value
    sub esp, 4                      ; allocate local variable space

    mov dword [ebp - 4], 0          ; return value

    mov eax, [ebp + 8]              ; nt headers optional header

    cmp word [eax], 0x20b           ; is pe 64 bit ?
    je .64bitOptionalHeader

    ; 32 bit optional header
    push dword [eax + 224]
    push dword [eax + 220]
    push dword [eax + 216]
    push dword [eax + 212]
    push dword [eax + 208]
    push dword [eax + 204]
    push dword [eax + 200]
    push dword [eax + 196]
    push dword [eax + 192]
    push dword [eax + 188]
    push dword [eax + 184]
    push dword [eax + 180]
    push dword [eax + 176]
    push dword [eax + 172]
    push dword [eax + 168]
    push dword [eax + 164]
    push dword [eax + 160]
    push dword [eax + 156]
    push dword [eax + 152]
    push dword [eax + 148]
    push dword [eax + 144]
    push dword [eax + 140]
    push dword [eax + 136]
    push dword [eax + 132]
    push dword [eax + 128]
    push dword [eax + 124]
    push dword [eax + 120]
    push dword [eax + 116]
    push dword [eax + 112]
    push dword [eax + 108]
    push dword [eax + 104]
    push dword [eax + 100]
    push dword [eax + 96]
    push dword [eax + 92]
    push dword [eax + 88]
    push dword [eax + 84]
    push dword [eax + 80]
    push dword [eax + 76]
    push dword [eax + 72]
    push dword [eax + 70]
    push dword [eax + 68]
    push dword [eax + 64]
    push dword [eax + 60]
    push dword [eax + 56]
    push dword [eax + 52]
    push dword [eax + 50]
    push dword [eax + 48]
    push dword [eax + 46]
    push dword [eax + 44]
    push dword [eax + 42]
    push dword [eax + 40]
    push dword [eax + 36]
    push dword [eax + 32]
    push dword [eax + 28]
    push dword [eax + 24]
    push dword [eax + 20]
    push dword [eax + 16]
    push dword [eax + 12]
    push dword [eax + 8]
    push dword [eax + 4]
    push dword [eax + 3]
    push dword [eax + 2]
    push dword [eax] 
    push nt_headers_optional_header_32_str
    jmp .continue_after_push

.64bitOptionalHeader:
    push dword [eax + 240]
    push dword [eax + 236]
    push dword [eax + 232]
    push dword [eax + 228]
    push dword [eax + 224]
    push dword [eax + 220]
    push dword [eax + 216]
    push dword [eax + 212]
    push dword [eax + 208]
    push dword [eax + 204]
    push dword [eax + 200]
    push dword [eax + 196]
    push dword [eax + 192]
    push dword [eax + 188]
    push dword [eax + 184]
    push dword [eax + 180]
    push dword [eax + 176]
    push dword [eax + 172]
    push dword [eax + 168]
    push dword [eax + 164]
    push dword [eax + 160]
    push dword [eax + 156]
    push dword [eax + 152]
    push dword [eax + 148]
    push dword [eax + 144]
    push dword [eax + 140]
    push dword [eax + 136]
    push dword [eax + 132]
    push dword [eax + 128]
    push dword [eax + 124]
    push dword [eax + 120]
    push dword [eax + 116]
    push dword [eax + 112]
    push dword [eax + 108]
    push dword [eax + 104]
    push dword [eax + 96]
    push dword [eax + 100]
    push dword [eax + 88]
    push dword [eax + 92]
    push dword [eax + 80]
    push dword [eax + 84]
    push dword [eax + 72]
    push dword [eax + 76]
    push dword [eax + 70]
    push dword [eax + 68]
    push dword [eax + 64]
    push dword [eax + 60]
    push dword [eax + 56]
    push dword [eax + 52]
    push dword [eax + 50]
    push dword [eax + 48]
    push dword [eax + 46]
    push dword [eax + 44]
    push dword [eax + 42]
    push dword [eax + 40]
    push dword [eax + 36]
    push dword [eax + 32]
    push dword [eax + 24]
    push dword [eax + 28]
    push dword [eax + 20]
    push dword [eax + 16]
    push dword [eax + 12]
    push dword [eax + 8]
    push dword [eax + 4]
    push dword [eax + 3]
    push dword [eax + 2]
    push dword [eax] 
    push nt_headers_optional_header_64_str

.continue_after_push:

    push dword [ebp + 12]           ; sprintf buffer
    call sprintf

    mov eax, [ebp + 8]              ; nt headers optional header
    cmp word [eax], 0x20b           ; is pe 64 bit ?
    je .clear_64bit_stack

    add esp, 260
    jmp .continue_after_stack_clear

.clear_64bit_stack:
    add esp, 280

.continue_after_stack_clear:
    push dword [ebp + 12]           ; sprintf buffer
    call strlen
    
    push eax                        ; strlen
    push dword [ebp + 12]           ; sprintf buffer 
    push dword [ebp + 16]           ; std handle
    call print_string

.shutdown:
    mov eax, [ebp - 4]              ; return value

    leave
    ret 12

; arg0: base addr file contents     [ebp + 8]
; arg1: Options                     [ebp + 12]
; arg2: std handle                  [ebp + 16]
parse_pe:
    push ebp
    mov ebp, esp

    ; ebp - 4 = return value
    ; ebp - 8 = nt header
    ; ebp - 12 = file header
    ; ebp - 16 = optional header
    ; ebp - 20 = section header count
    ; ebp - 24 = section headers
    ; ebp - 28 = file bitness 1: 64 bit, 0: 32 bit
    ; ebp - 32 = ebx
    ; ebp - 36 = options enum;  1 = dos header, 2 = dos stub, 3 = signature
    ;                           4 = file header, 5 = optional header, 6 = section header
    ;                           7 = export directory, 8 = import directory
    ; ebp - 8228 = 8192 byte buffer for sprintf
    sub esp, 8228                                   ; allocate local variable space
    mov dword [ebp - 4], 0                          ; return value
    mov [ebp - 32], ebx                             ; save ebx

    mov eax, [ebp + 12]
    mov eax, [eax]
    push eax                                        ; Options
    push dos_header_arg
    call strcmpAA
    cmp eax, 0
    je .cmp_dos_stub

    mov dword [ebp - 36], 1                         ; dos header
    jmp .cmp_end

.cmp_dos_stub:
    mov eax, [ebp + 12]
    mov eax, [eax]
    push eax                                        ; Options
    push dos_stub_arg
    call strcmpAA
    cmp eax, 0
    je .cmp_nt_headers_signature

    mov dword [ebp - 36], 2                         ; dos stub
    jmp .cmp_end

.cmp_nt_headers_signature:
    mov eax, [ebp + 12]
    mov eax, [eax]
    push eax                                        ; Options
    push nt_headers_signature_arg
    call strcmpAA
    cmp eax, 0
    je .cmp_nt_headers_file_header

    mov dword [ebp - 36], 3                         ; dos stub
    jmp .cmp_end

.cmp_nt_headers_file_header:
    mov eax, [ebp + 12]
    mov eax, [eax]
    push eax                                        ; Options
    push nt_headers_file_header_arg
    call strcmpAA
    cmp eax, 0
    je .cmp_nt_headers_optional_header

    mov dword [ebp - 36], 4                         ; file header
    jmp .cmp_end

.cmp_nt_headers_optional_header:
    mov eax, [ebp + 12]
    mov eax, [eax]
    push eax                                        ; Options
    push nt_headers_optional_header_arg
    call strcmpAA
    cmp eax, 0
    je .cmp_section_headers

    mov dword [ebp - 36], 5                         ; optional header
    jmp .cmp_end

.cmp_section_headers:
    mov eax, [ebp + 12]
    mov eax, [eax]
    push eax                                        ; Options
    push section_headers_arg
    call strcmpAA
    cmp eax, 0
    je .cmp_exported_functions

    mov dword [ebp - 36], 6                         ; section headers
    jmp .cmp_end

.cmp_exported_functions:
    mov eax, [ebp + 12]
    mov eax, [eax]
    push eax                                        ; Options
    push exported_functions_arg
    call strcmpAA
    cmp eax, 0
    je .cmp_imported_functions

    mov dword [ebp - 36], 7                         ; export directory
    jmp .cmp_end

.cmp_imported_functions:
    mov eax, [ebp + 12]
    mov eax, [eax]
    push eax                                        ; Options
    push imported_functions_arg
    call strcmpAA
    cmp eax, 0
    je .options_arg_err

    mov dword [ebp - 36], 8                         ; import directory

    jmp .cmp_end

.options_arg_err:
    push ret_val_1_str.len
    push ret_val_1_str
    push dword [ebp + 16]                           ; std handle
    call print_string

    jmp .shutdown

.cmp_end:
    ; retrive and save the information
    mov ebx, [ebp + 8]                              ; base addr
    cmp dword [ebp - 36], 1                         ; print dos header
    jne .continue_from_print_dos_header_check

    ; print dos header
    push dword [ebp + 16]                           ; std handle
    mov eax, ebp
    sub eax, 8228                                   ; sprintf buffer
    push eax
    push ebx                                        ; base addr
    call print_dos_header

.continue_from_print_dos_header_check:

    add ebx, 0x3c                                   ; offset of e_lfanew
    movzx eax, word [ebx]                           ; e_lfanew

    cmp dword [ebp - 36], 2                         ; print dos stub
    jne .continue_from_print_dos_stub_check

    ; print dos stub

.continue_from_print_dos_stub_check:

    mov ebx, [ebp + 8]
    add ebx, eax                                    ; nt headers
    mov [ebp - 8], ebx                              ; nt headers saved

    cmp dword [ebp - 36], 3                         ; print nt headers signature
    jne .continue_from_nt_headers_signature_check
    
    ; print nt headers signature
    push dword [ebp + 16]                           ; std handle
    mov eax, ebp
    sub eax, 8228                                   ; sprintf buffer
    push eax
    push dword [ebp - 8]                            ; nt headers
    call print_nt_headers_signature

.continue_from_nt_headers_signature_check:
    add ebx, 4                                      ; file header
    mov [ebp - 12], ebx                             ; file header saved

    cmp dword [ebp - 36], 4                         ; print nt headers file header
    jne .continue_from_nt_headers_file_header_check

    ; print nt headers file header
    push dword [ebp + 16]                           ; std handle
    mov eax, ebp
    sub eax, 8228                                   ; sprintf buffer
    push eax
    push dword [ebp - 12]                           ; nt headers file header
    call print_nt_headers_file_header

.continue_from_nt_headers_file_header_check:
    add ebx, 20                                     ; optional header
    mov [ebp - 16], ebx                             ; optional header saved

    cmp dword [ebp - 36], 5                         ; print nt headers optional header
    jne .continue_from_nt_headers_optional_header_check

    ; print nt headers optional header
    push dword [ebp + 16]                           ; std handle
    mov eax, ebp
    sub eax, 8228                                   ; sprintf buffer
    push eax
    push dword [ebp - 16]                           ; nt headers optional header
    call print_nt_headers_optional_header

.continue_from_nt_headers_optional_header_check:
    mov ebx, [ebp - 12]                             ; file header
    add ebx, 2                                      ; section header count
    movzx eax, word [ebx]
    mov [ebp - 20], eax                             ; section header count saved

    mov eax, [ebp - 12]                             ; file header
    mov ax, [eax]
    cmp word ax, 0x14c                              ; is file 32 bit
    je .32bit
        mov eax, [ebp - 16]                         ; optional header
        add eax, 240                                ; end of optional header, start of section headers

        mov [ebp - 24], eax                         ; section headers
        mov dword [ebp - 28], 1                     ; file bitness 1 for 64 bit

        jmp .continue_32_bit

    .32bit:
        mov eax, [ebp - 16]                         ; optional header
        add eax, 224                                ; end of optional header, start of section header

        mov [ebp - 24], eax                         ; section headers
        mov dword [ebp - 24], 0                     ; file bitness 0 for 32 bit

.continue_32_bit:
    ; loop section headers

    push dword [ebp - 20]                           ; section header count
    push dword [ebp - 24]                           ; section headers
    call loop_section_headers

.idt:
    ; loop IDT
    mov eax, [ebp - 16]                             ; optional header

    cmp dword [ebp - 28], 0                         ; is file 32 bit
    je .32bitidt
        add eax, 120                                ; IDT
        mov eax, [eax]

        cmp eax, 0                                  ; if IDT rva == 0 ?

        je .edt
        jmp .continue_bitcheck_idt

    .32bitidt:
        add eax, 104                                ; IDT
        mov eax, [eax]

        cmp eax, 0                                  ; if IDT rva == 0 ?

        je .edt

.continue_bitcheck_idt:
    push dword [ebp + 8]                            ; base addr
    push dword [ebp - 20]                           ; section header count
    push dword [ebp - 24]                           ; section headers
    push eax                                        ; IDT rva
    call loop_import_descriptor_table

.edt:
    ; loop EDT
    mov eax, [ebp - 16]                             ; optional header

    cmp dword [ebp - 28], 0                         ; is file 32 bit
    je .32bitedt
        add eax, 112                                ; EDT
        mov eax, [eax]

        cmp eax, 0                                  ; if EDT rva == 0 ?

        je .shutdown
        jmp .continue_bitcheck_edt

    .32bitedt:
        add eax, 96                                 ; EDT
        mov eax, [eax]

        cmp eax, 0                                  ; if EDT rva == 0 ?

        je .shutdown

.continue_bitcheck_edt:
    push dword [ebp + 8]                            ; base addr
    push dword [ebp - 20]                           ; section header count
    push dword [ebp - 24]                           ; section headers
    push eax                                        ; EDT rva
    call loop_export_descriptor_table

.shutdown:

    mov eax, [ebp - 4]                              ; return value
    mov ebx, [ebp - 32]                             ; restore ebx

    leave
    ret 8

; arg0: argc        [ebp + 8]
; arg1: *argv[]     [ebp + 12]
_parse_pe:
    push ebp
    mov ebp, esp

    ; ebp - 4 = retuen value
    ; ebp - 148 = OFFILESTRUCT
    ; ebp - 152 = file handle
    ; ebp - 156 = getfilesize high order dw of file size
    ; ebp - 160 = getfilesize low order dw of file size
    ; ebp - 164 = allocated mem for input file read
    ; ebp - 168 = kernel handle
    ; ebp - 172 = std handle
    ; ebp - 176 = shlwapi addr
    sub esp, 176                                    ; allocate local variable space

    mov dword [ebp - 4], 0                          ; return value

    call get_kernel_module_handle
    mov [ebp - 168], eax                            ; kernel handle

    push dword [ebp - 168]                          ; kernel handle
    call populate_kernel_function_ptrs_by_name

    push STD_HANDLE_ENUM
    call [get_std_handle]

    mov [ebp - 172], eax                            ; std handle

    ; check if 2 args are passed to the exe
    cmp dword [ebp + 8], 3                          ; argc == 3 ?
    je .continue_argc_check

    push ret_val_1_str.len
    push ret_val_1_str
    push dword [ebp - 172]                          ; std handle
    call print_string

    call [get_last_error]

    mov dword [ebp - 4], 1                          ; return value

    jmp .shutdown

.continue_argc_check:

    push xor_key.len
    push xor_key
    push shlwapi_xor.len
    push shlwapi_xor
    call my_xor

    push shlwapi_xor
    call [load_library_a]

    cmp eax, 0
    je .shutdown

    mov [ebp - 176], eax                            ; shlwapi addr

    push xor_key.len
    push xor_key
    push path_file_exists_a_xor.len
    push path_file_exists_a_xor
    call my_xor

    push path_file_exists_a_xor
    push dword [ebp - 176]                          ; shlwapi addr
    call get_proc_address_by_get_proc_addr

    cmp eax, 0
    je .shutdown

    mov [path_file_exists_a], eax

    mov edx, [ebp + 12]                             ; argv in edx
    mov edx, [edx + 4]                              ; argv[1] in edx

    push edx
    call [path_file_exists_a]

    cmp eax, 1                                      ; does file exist
    je .continue_path_file_check
        push ret_val_2_str.len
        push ret_val_2_str
        push dword [ebp - 172]                      ; std handle
        call print_string

        call [get_last_error]

        mov dword [ebp - 4], 2

        jmp .shutdown

.continue_path_file_check:
    push 0

    mov edx, esp
    sub edx, 148                                    ; OFFILESTRUCT
    push edx

    mov edx, [ebp + 12]                             ; argv
    add edx, 4                                      ; argv + 1
    push dword [edx]                                ; argv[1]

    call [open_file]                                ; file handle in eax

    cmp eax, INVALID_HANDLE_VALUE
    jne .continue_open_file
        push ret_val_3_open_file_str.len
        push ret_val_3_open_file_str
        push dword [ebp - 172]                      ; std handle
        call print_string

        call [get_last_error]

        mov dword [ebp - 4], 3

        jmp .shutdown

.continue_open_file:
    mov [ebp - 152], eax                            ; file handle

    mov edx, ebp
    sub edx, 156                                    ; file size high order dword
    push edx

    push dword [ebp - 152]                          ; file handle
    call [get_file_size]                            ; file size in eax

    cmp eax, INVALID_FILE_SIZE
    jne .continue_get_file_size
        push ret_val_4_get_file_size_str.len
        push ret_val_4_get_file_size_str
        push dword [ebp - 172]                      ; std handle
        call print_string

        call [get_last_error]

        mov dword [ebp - 4], 4                      ; return value

        jmp .shutdown

.continue_get_file_size:
    mov [ebp - 160], eax                            ; file size saved

    mov edx, PAGE_READWRITE
    push edx

    mov edx, MEM_RESERVE
    or edx, MEM_COMMIT
    push edx

    push dword [ebp - 160]                          ; file size
    push 0
    call [virtual_alloc]

    cmp eax, 0                                      ; if addr is 0
    jne .continue_virtual_alloc
        push ret_val_5_virtual_alloc_str.len
        push ret_val_5_virtual_alloc_str
        push dword [ebp - 172]                      ; std handle
        call print_string
        
        call [get_last_error]

        mov dword [ebp - 4], 5                      ; return value

        jmp .shutdown

.continue_virtual_alloc:
    mov dword [ebp - 164], eax                      ; alloced mem

    push 0
    push 0
    push dword [ebp - 160]                          ; file size
    push dword [ebp - 164]                          ; alloced mem
    push dword [ebp - 152]                          ; file handle
    call [read_file]

    cmp eax, 0                                      ; 1: successful read
    jne .continue_read_file
        push ret_val_6_read_file_str.len
        push ret_val_6_read_file_str
        push dword [ebp - 172]                      ; std handle
        call print_string

        call [get_last_error]

        mov dword [ebp - 4], 6                      ; return value

        jmp .shutdown

.continue_read_file:
    push dword [ebp - 172]                          ; file handle
    mov edx, [ebp + 12]                             ; argv
    add edx, 8                                      ; command line Options
    push edx
    push dword [ebp - 164]                          ; alloced mem
    call parse_pe

.shutdown:
    push MEM_RELEASE
    push 0
    push dword [ebp - 164]                          ; alloced mem
    call [virtual_free]

    push dword [ebp - 152]                          ; file handle
    call [close_handle]

    mov eax, [ebp - 4]                              ; return value

    leave
    ret 8


section .data
%include '../utils/utils_32_data.asm'

ret_val_1_str: db 'Usage: parse_pe.exe <filename> <options>', 0xa, ' <options>: --dos-header', 0xa, '            --dos-stub', 0xa, '            --nt-headers-signature', 0xa,'            --nt-headers-file-header', 0xa, '            --nt-headers-optional-header', 0xa, '            --section-headers', 0xa, '            --imported-functions', 0xa, '            --exported-functions', 0
.len equ $ - ret_val_1_str

ret_val_2_str: db 'ERR: Input file does not exist', 0
.len equ $ - ret_val_2_str

ret_val_3_open_file_str: db 'OpenFile failed', 0
.len equ $ - ret_val_3_open_file_str

ret_val_4_get_file_size_str: db 'GetFileSize failed', 0
.len equ $ - ret_val_4_get_file_size_str

ret_val_5_virtual_alloc_str: db 'VirtualAlloc failed', 0
.len equ $ - ret_val_5_virtual_alloc_str

ret_val_6_read_file_str: db 'ERR: ReadFile failed', 0
.len equ $ - ret_val_6_read_file_str

dos_header_arg: db '--dos-header', 0
.len equ $ - dos_header_arg

dos_stub_arg: db '--dos-stub', 0
.len equ $ - dos_stub_arg

nt_headers_signature_arg: db '--nt-headers-signature', 0
.len equ $ - nt_headers_signature_arg

nt_headers_file_header_arg: db '--nt-headers-file-header', 0
.len equ $ - nt_headers_file_header_arg

nt_headers_optional_header_arg: db '--nt-headers-optional-header', 0
.len equ $ - nt_headers_optional_header_arg

section_headers_arg: db '--section-headers', 0
.len equ $ - section_headers_arg

imported_functions_arg: db '--imported-functions', 0
.len equ $ - imported_functions_arg

exported_functions_arg: db '--exported-functions', 0
.len equ $ - exported_functions_arg

help_arg: db '-h', 0
.len equ $ - help_arg

shlwapi_xor: db 0x63, 0x58, 0x5c, 0x47, 0x51, 0x40, 0x59, 0x1e, 0x54, 0x5c, 0x5c, 0
.len equ $ - shlwapi_xor - 1

path_file_exists_a_xor: db 0x60, 0x51, 0x44, 0x58, 0x76, 0x59, 0x5c, 0x55, 0x75, 0x48, 0x59, 0x43, 0x44, 0x43, 0x71, 0
.len equ $ - path_file_exists_a_xor - 1

dos_header_str: db '                DOS Header', 0xa, \
                'Magic Number                   : %xw', 0xa, \
                'Bytes on Last Page             : 0x%xw', 0xa, \
                'Pages in file                  : 0x%xw', 0xa, \
                'Relocations                    : 0x%xw', 0xa, \
                'Paragaph Header Size           : 0x%xw', 0xa, \
                'Min. extra paragaphs           : 0x%xw', 0xa, \
                'Max. extra paragaphs           : 0x%xw', 0xa, \
                'Initial Relative SS value      : 0x%xw', 0xa, \
                'Initial SP value               : 0x%xw', 0xa, \
                'Checksum                       : 0x%xw', 0xa, \
                'Initial IP value               : 0x%xw', 0xa, \
                'Initial Relative CS value      : 0x%xw', 0xa, \
                'File Addr of Reloc table       : 0x%xw', 0xa, \
                'Overlay Number                 : 0x%xw', 0xa, \
                'Reserved Words                 : 0x%xw 0x%xw 0x%xw 0x%xw', 0xa, \
                'OEM Identifier                 : 0x%xw', 0xa, \
                'OEM Information                : 0x%xw', 0xa, \
                'Reserved Words                 : 0x%xw 0x%xw 0x%xw 0x%xw 0x%xw 0x%xw 0x%xw 0x%xw 0x%xw 0x%xw', 0xa, \
                'File Addr of New EXE header    : 0x%xd', 0
.len equ $ - dos_header_str

dos_stub_str: db '', 0

nt_headers_signature_str: db '      NT headers Signature', 0xa, \
                            'Signature: 0x%xd', 0
.len equ $ - nt_headers_signature_str

nt_headers_file_header_str: db '        NT headers File Header', 0xa, \
                                'Machine            : 0x%xw', 0xa, \
                                'Section Count      : 0x%xw', 0xa, \
                                'Time Date Stamp    : 0x%xd', 0xa, \
                                'Sym Table Ptr      : 0x%xd', 0xa, \
                                'Sym Count          : 0x%xd', 0xa, \
                                'Optional Hdr Size  : 0x%xw', 0xa, \
                                'Characteristics    : 0x%xw', 0
.len equ $ - nt_headers_file_header_str

nt_headers_optional_header_32_str: db '        NT Headers Optional Header', 0xa, \
                                    'Magic                      : 0x%xw', 0xa, \
                                    'Major Linker Version       : 0x%xb', 0xa, \
                                    'Minor Linker Version       : 0x%xb', 0xa, \
                                    'Code Size                  : 0x%xd', 0xa, \
                                    'Initialized Data Size      : 0x%xd', 0xa, \
                                    'Uninitialized Data Size    : 0x%xd', 0xa, \
                                    'Entry Point Addr           : 0x%xd', 0xa, \
                                    'Base of Code               : 0x%xd', 0xa, \
                                    'Base of Data               : 0x%xd', 0xa, \
                                    'Base                       : 0x%xd', 0xa, \
                                    'Section Alignment          : 0x%xd', 0xa, \
                                    'File Alignment             : 0x%xd', 0xa, \
                                    'Major OS Version           : 0x%xw', 0xa, \
                                    'Minor OS Version           : 0x%xw', 0xa, \
                                    'Major Image Version        : 0x%xw', 0xa, \
                                    'Minor Image Version        : 0x%xw', 0xa, \
                                    'Major Subsystem Version    : 0x%xw', 0xa, \
                                    'Minor Subsystem Version    : 0x%xw', 0xa, \
                                    'Win32 Version value        : 0x%xd', 0xa, \
                                    'Size                       : 0x%xd', 0xa, \
                                    'Headers Size               : 0x%xd', 0xa, \
                                    'Checksum                   : 0x%xd', 0xa, \
                                    'Subsystem                  : 0x%xw', 0xa, \
                                    'Dll Characteristics        : 0x%xw', 0xa, \
                                    'Stack Reserve Size         : 0x%xd', 0xa, \
                                    'Stack Commit Size          : 0x%xd', 0xa, \
                                    'Heap Reserve Size          : 0x%xd', 0xa, \
                                    'Heap Commit Size           : 0x%xd', 0xa, \
                                    'Loader Flags               : 0x%xd', 0xa, \
                                    'Number of RVAs and Sizes   : 0x%xd', 0xa, \
                                    'Export Directory           : RVA 0x%xd Size 0x%xd', 0xa, \
                                    'Import Directory           : RVA 0x%xd Size 0x%xd', 0xa, \
                                    'Resource Directory         : RVA 0x%xd Size 0x%xd', 0xa, \
                                    'Exception Directory        : RVA 0x%xd Size 0x%xd', 0xa, \
                                    'Security Directory         : RVA 0x%xd Size 0x%xd', 0xa, \
                                    'Base Relocation Table      : RVA 0x%xd Size 0x%xd', 0xa, \
                                    'Debug Directory            : RVA 0x%xd Size 0x%xd', 0xa, \
                                    'Arch Specific Data         : RVA 0x%xd Size 0x%xd', 0xa, \
                                    'RVA of Global Ptr          : RVA 0x%xd Size 0x%xd', 0xa, \
                                    'TLS Directory              : RVA 0x%xd Size 0x%xd', 0xa, \
                                    'Load Config Directory      : RVA 0x%xd Size 0x%xd', 0xa, \
                                    'Bound Import Directory     : RVA 0x%xd Size 0x%xd', 0xa, \
                                    'Import Address Table       : RVA 0x%xd Size 0x%xd', 0xa, \
                                    'Delay Load Import Descr    : RVA 0x%xd Size 0x%xd', 0xa, \
                                    '.NET Header                : RVA 0x%xd Size 0x%xd', 0
.len equ $ - nt_headers_optional_header_32_str

nt_headers_optional_header_64_str: db '        NT Headers Optional Header', 0xa, \
                                    'Magic                      : 0x%xw', 0xa, \
                                    'Major Linker Version       : 0x%xb', 0xa, \
                                    'Minor Linker Version       : 0x%xb', 0xa, \
                                    'Code Size                  : 0x%xd', 0xa, \
                                    'Initialized Data Size      : 0x%xd', 0xa, \
                                    'Uninitialized Data Size    : 0x%xd', 0xa, \
                                    'Entry Point Addr           : 0x%xd', 0xa, \
                                    'Base of Code               : 0x%xd', 0xa, \
                                    'Base                       : 0x%xd%xd', 0xa, \
                                    'Section Alignment          : 0x%xd', 0xa, \
                                    'File Alignment             : 0x%xd', 0xa, \
                                    'Major OS Version           : 0x%xw', 0xa, \
                                    'Minor OS Version           : 0x%xw', 0xa, \
                                    'Major Image Version        : 0x%xw', 0xa, \
                                    'Minor Image Version        : 0x%xw', 0xa, \
                                    'Major Subsystem Version    : 0x%xw', 0xa, \
                                    'Minor Subsystem Version    : 0x%xw', 0xa, \
                                    'Win32 Version value        : 0x%xd', 0xa, \
                                    'Size                       : 0x%xd', 0xa, \
                                    'Headers Size               : 0x%xd', 0xa, \
                                    'Checksum                   : 0x%xd', 0xa, \
                                    'Subsystem                  : 0x%xw', 0xa, \
                                    'Dll Characteristics        : 0x%xw', 0xa, \
                                    'Stack Reserve Size         : 0x%xd%xd', 0xa, \
                                    'Stack Commit Size          : 0x%xd%xd', 0xa, \
                                    'Heap Reserve Size          : 0x%xd%xd', 0xa, \
                                    'Heap Commit Size           : 0x%xd%xd', 0xa, \
                                    'Loader Flags               : 0x%xd', 0xa, \
                                    'Number of RVAs and Sizes   : 0x%xd', 0xa, \
                                    'Export Directory           : RVA 0x%xd Size 0x%xd', 0xa, \
                                    'Import Directory           : RVA 0x%xd Size 0x%xd', 0xa, \
                                    'Resource Directory         : RVA 0x%xd Size 0x%xd', 0xa, \
                                    'Exception Directory        : RVA 0x%xd Size 0x%xd', 0xa, \
                                    'Security Directory         : RVA 0x%xd Size 0x%xd', 0xa, \
                                    'Base Relocation Table      : RVA 0x%xd Size 0x%xd', 0xa, \
                                    'Debug Directory            : RVA 0x%xd Size 0x%xd', 0xa, \
                                    'Arch Specific Data         : RVA 0x%xd Size 0x%xd', 0xa, \
                                    'RVA of Global Ptr          : RVA 0x%xd Size 0x%xd', 0xa, \
                                    'TLS Directory              : RVA 0x%xd Size 0x%xd', 0xa, \
                                    'Load Config Directory      : RVA 0x%xd Size 0x%xd', 0xa, \
                                    'Bound Import Directory     : RVA 0x%xd Size 0x%xd', 0xa, \
                                    'Import Address Table       : RVA 0x%xd Size 0x%xd', 0xa, \
                                    'Delay Load Import Descr    : RVA 0x%xd Size 0x%xd', 0xa, \
                                    '.NET Header                : RVA 0x%xd Size 0x%xd', 0
.len equ $ - nt_headers_optional_header_64_str

STD_HANDLE_ENUM equ -11
INVALID_HANDLE_VALUE equ -1
INVALID_FILE_SIZE equ -1
OF_READ equ 0
OF_FILE_STRUCT_SIZE equ 144
DOS_HEADER_BUFFER_SIZE equ 64
NT_FILE_HEADER_BUFFER_SIZE equ 20
OPTIONAL_HEADER_BUFFER_SIZE_64 equ 240
OPTIONAL_HEADER_BUFFER_SIZE_32 equ 224

; Virtual Alloc
MEM_COMMIT equ 0x00001000
MEM_RESERVE equ 0x00002000

PAGE_READWRITE equ 0x04
PAGE_EXECUTE_READWRITE equ 0x40

; Virtual Free
MEM_RELEASE equ 0x00008000

section .bss
path_file_exists_a: dd ?
%include '../utils/utils_32_bss.asm'