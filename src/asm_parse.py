import pwn
import re


class AsmFunction(object):
	def __init__(self, src_file, function_name):
		self._address, self._size, self._content = self.get_func_by_name(src_file, function_name)
		self._instructions = self.func_content_to_instruction_arr(self._content)

	@staticmethod
	def get_func_by_name(elf_file, func_name):
		e = pwn.ELF(elf_file)
		func = e.functions[func_name]
		return func.address, func.size, e.disasm(func.address,func.size)
	
	@staticmethod
	def func_content_to_instruction_arr(func_content):
		instructions = []
		for line in func_content.split('\n'):
			inst = InstructionLine(line)
			try:
				instructions.append(inst)
			except Exception as err: # TODO: replace with a custom Exception
				print err 
		
		return instructions
	

class InstructionLine(object):
	def __init__(self, line):
		command_pattern = ' *([0-9a-f]+): *(?:[0-9a-f]{2} ){1,7} *(.+)'
		if not re.match(command_pattern, line):
			raise Exception('Invalid command pattern')

		temp_line = re.sub(command_pattern, '\\1:\\2', line)
		
		self._address, self._command = temp_line.split(':')
		self._address = int('0x'+self._address,16)
		self._command = self._command.strip()
		if '# 0x' in line: # In case of addresses in the binary file 
			self._comment_address = int('0x'+line.split('# 0x')[-1],16)
		else:
			self._comment_address = None


if __name__=='__main__':
	params = '''  400527:       48 89 e5                mov    rbp,rsp
  40052a:       48 83 ec 10             sub    rsp,0x10
  40052e:       c7 45 f4 05 00 00 00    mov    DWORD PTR [rbp-0xc],0x5
  400535:       c7 45 f8 07 00 00 00    mov    DWORD PTR [rbp-0x8],0x7'''
	for l in params.split('\n'):
		try:
			print l
			ins = InstructionLine(l)
			print "Address: {} \n Command: {}".format(ins._address, ins._command)
		except Exception as err:
			print err
