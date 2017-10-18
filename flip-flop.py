import r2pipe
import argparse
from termcolor import cprint, colored

expected = 0

def hex_int(x):
	return int(x, 0)

# return address of target function
def get_module_addr(target):
	for i in range(1000): 
		maps = r2.cmdj("dmj")
		for m in maps:
			if m['name'].endswith(target) and m['perm'] == '-r-x':
				return int(m['addr'])
		r2.cmd("dsp")
	return None

# continue to target function
def dcf(target, module = False, offset = 0):
	ret = get_function_addr(target, module)	
	if ret >= 0:
		ret += offset
		r2.cmd("db " + str(ret))
		r2.cmd("dc")
	return ret

# check if we succeed in modifying the
# expected return value
def check_ret(value):
	#return value != expected
	return value == 0

if __name__ == '__main__':

	parser = argparse.ArgumentParser()
	parser.add_argument('binary', nargs = '+')
	parser.add_argument('-t', '--target', required = True, help = "set target function or module")
	parser.add_argument('-o', '--offset', default = 0, type = hex_int)
	parser.add_argument('-p', '--profile', default = '')
	parser.add_argument('-s', '--skip', default = 0, type = int, help = "skip N instructions")

	args = parser.parse_args()
	argv = args.binary
	arguments = ' '.join(argv[1:])
	binary = argv[0]
	target = args.target
	offset = args.offset
	skip = args.skip
	profile = args.profile
	module = target.endswith(".so")
	
	cprint("[!] This program could have unexpected effect. Use it with caution !!!", "red")

	r2 = r2pipe.open(binary)

	if profile:
		print("[+] Setting profile from {}".format(profile))
		r2.cmd("e dbg.profile=" + profile)

	print("[+] Opening {} in debug mode".format(binary))
	#r2.cmd("doo " + arguments)
	r2.cmd("doo")

	# skip sigchld handler
	r2.cmd("dko 17 skip")

	print("[+] Getting address of target function")
	if not module:
		start = r2.cmd("s @ sym." + target)
		start = int(start, 16)
	else:
		start = get_module_addr(target)
	
	if not start:
		cprint("[+] no such module or function !!", "red")
		exit()
	
	start += offset

	print("[+] Continuing to target function ...")
	r2.cmd("db " + str(start))
	r2.cmd("dc")

	print("[+] Analyzing function")
	r2.cmd("af")
	ret = r2.cmd('afi')
	if not ret:
		cprint("[+] No function in here !!", "red")
		exit()

	print("[+] Disas target function")
	# hack: can't get raw bytes with pxf!!!!
	raw = r2.cmd("puf").replace('%', '')
	asm = r2.cmdj("pdfj")['ops']

	# set breakpoint at function end	
	for inst in asm:
		if inst['type'] == 'ret':
			end = inst['offset']
			r2.cmd("db " + str(end))
			break

	print("[+] Saving trace session")
	r2.cmd("dts+")

	# main bit-flip loop
	asm = asm[skip:]
	o = asm[0]['offset'] - start
	s = 0
	for inst in asm:
		type = inst['type']
		if type == 'invalid': break

		opcode = colored(inst['opcode'], "yellow")
		print("[+] Patching instruction {}".format(opcode))
		bytes = bytearray.fromhex(inst['bytes'])
		for b in bytes:
			# skip sensitive instructions
			if type in ('ret', 'leave'): continue
			for i in range(8):
				# flip bit
				c = b ^ (1 << i)

				# patch opcode
				r2.cmd("s + " + str(o))
				r2.cmd("wx " + hex(c))

				# TODO: check if assembly is ok
				
				# step until end of frame
				#r2.cmd("dcf")
				r2.cmd("dc")
				rip = r2.cmd("dr rip")
				rip = int(rip, 16)
				if (rip == end):
					# check rax register			
					rax = r2.cmd("dr rax")
					rax = int(rax, 16)
					if check_ret(rax):
						s += 1
						print("[*] Bit {} at offset {} could be flipped".format(colored(i, 'green'), colored(hex(o), 'green')))

				# restore session
				r2.cmd("dcb")
				rip = r2.cmd("dr rip")
				r2.cmd("s " + str(start))
				r2.cmd("wx " + raw)
			
			# do not mess with branch instruction operands !!
			if type in ('jmp', 'cjmp', 'call'):
				o += inst['size']
				break
			else:
				o += 1

	print("[+] Found {} potential bit-flips".format(colored(s, "green")))
	cprint("[!] Row-hammering could damage your computer bastard", 'red')

	print("[!] Quit.")
	r2.cmd("q")
