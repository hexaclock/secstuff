# ----------------------------------------------------------------------------------------
# Writes "Hello, World" to the console using only system calls. Runs on 64-bit Linux only.
# To assemble and run:
#
#     gcc -c hello.s && ld hello.o && ./a.out
#
# or
#
#     gcc -nostdlib hello.s && ./a.out
# ----------------------------------------------------------------------------------------

.global _start
.text

_start:
	jmp data
logic:	
        # write(1, message, 13)
        mov     $268435455, %rax        
	sub     $268435454, %rax	# system call 1 is write
        mov     %rax, %rdi              # file handle 1 is stdout
	pop     %rsi                    # get message address
	#mov	$268435455, %rsi
	#sub     $264240967, %rsi
        mov     $268435455, %rdx
	sub     $268435442, %rdx	# 13 bytes in msg
        syscall                   # invoke operating system to do the write

        # exit(0)
	mov     $268435455, %rax
	sub     $268435395, %rax        # $60 in %rax
        xor     %rdi, %rdi              # we want return code 0
        syscall                         # invoke operating system to exit

data:
	call logic
        .ascii  "Hello, world\n"
