REGISTER_LIST = []
REGISTERS_DICT = {}
REGISTERS_128 = []
REGISTERS_64 = []
REGISTERS_32 = []
REGISTERS_16 = []
REGISTERS_8 = []

for reg in ['ax', 'bx', 'cx', 'dx']:
	REGISTER_LIST.append('r' + reg)  # 8 bytes
	REGISTERS_64.append('r' + reg)
	REGISTERS_DICT['r' + reg] = {'64': 'r' + reg}
	REGISTER_LIST.append('e' + reg)  # 4 bytes
	REGISTERS_32.append('e' + reg)
	REGISTERS_DICT['r' + reg]['32'] = 'e' + reg
	REGISTER_LIST.append(reg)  # 2 bytes
	REGISTERS_16.append(reg)
	REGISTERS_DICT['r' + reg]['16'] = reg
	REGISTER_LIST.append(reg.replace('x', 'l'))  # 1 byte low
	REGISTERS_8.append(reg.replace('x', 'l'))
	REGISTERS_DICT['r' + reg]['8l'] = reg.replace('x', 'l')
	REGISTER_LIST.append(reg.replace('x', 'h'))  # 1 byte high
	REGISTERS_8.append(reg.replace('x', 'h'))
	REGISTERS_DICT['r' + reg]['8h'] = reg.replace('x', 'h')

for reg in ['si', 'di', 'sp', 'bp']:
	REGISTER_LIST.append('r' + reg)  # 8 bytes
	REGISTERS_64.append('r' + reg)
	REGISTERS_DICT['r' + reg] = {'64': 'r' + reg}
	REGISTER_LIST.append('e' + reg)  # 4 bytes
	REGISTERS_32.append('e' + reg)
	REGISTERS_DICT['r' + reg]['32'] = 'e' + reg
	REGISTER_LIST.append(reg)  # 2 bytes
	REGISTERS_16.append(reg)
	REGISTERS_DICT['r' + reg]['16'] = reg
	REGISTER_LIST.append(reg + 'l')  # 1 byte
	REGISTERS_8.append(reg + 'l')
	REGISTERS_DICT['r' + reg]['8'] = reg + 'l'

for i in xrange(8, 16):
	REGISTER_LIST.append('r' + str(i))	# QWORD ; 8 BYTES
	REGISTERS_64.append('r' + str(i))
	REGISTERS_DICT['r' + str(i)] = {'64': 'r' + str(i)}
	REGISTER_LIST.append('r' + str(i) + 'd')  # DWORD ; DOUBLE WORD; 4 BYTES
	REGISTERS_32.append('r' + str(i) + 'd')
	REGISTERS_DICT['r' + str(i)]['32'] = 'r' + str(i) + 'd'
	REGISTER_LIST.append('r' + str(i) + 'w')  # WORD  ; 2 BYTES
	REGISTERS_16.append('r' + str(i) + 'w')
	REGISTERS_DICT['r' + str(i)]['16'] = 'r' + str(i) + 'w'
	REGISTER_LIST.append('r' + str(i) + 'b')  # BYTE  ; BYTE
	REGISTERS_8.append('r' + str(i) + 'b')
	REGISTERS_DICT['r' + str(i)]['8'] = 'r' + str(i) + 'b'

for i in xrange(0, 16):
	REGISTER_LIST.append('xmm' + str(i))  # XMM registers
	REGISTERS_128.append('xmm' + str(i))
	REGISTERS_DICT['xmm' + str(i)] = {'128': 'xmm' + str(i)}


def is_register(arg):
	return arg in REGISTER_LIST


def get_register(partial_reg):
	if partial_reg in ['al', 'ax', 'eax', 'rax']:
		return 'rax'
	elif partial_reg in ['bl', 'bx', 'ebx', 'rbx']:
		return 'rbx'
	elif partial_reg in ['cl', 'cx', 'ecx', 'rcx']:
		return 'rcx'
	elif partial_reg in ['dl', 'dx', 'edx', 'rdx']:
		return 'rdx'
	elif partial_reg in ['sil', 'si', 'esi', 'rsi']:
		return 'rsi'
	elif partial_reg in ['dil', 'di', 'edi', 'rdi']:
		return 'rdi'
	elif partial_reg in REGISTERS_128:
		return partial_reg
	
	for i in xrange(8, 16):
		if partial_reg in ['r' + str(i) + 'b', 'r' + str(i) + 'w', 'r' + str(i) + 'd', 'r' + str(i)]:
			return 'r' + str(i)
	
	raise Exception('Invalid register %s\n' % partial_reg)
