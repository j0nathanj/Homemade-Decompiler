import pwn
import re
from registers import *
import AsmInstructionParser
from collections import namedtuple

'''
(18.8.2018) TODOs:
-----------------------------------------------------------------
* Shahaf- Parameters handling (type, stack-element mapping)
* Jonathan- Return value & return type
-----------------------------------------------------------------
'''


def is_int(s):
	try:
		int(s)
		return True
	except Exception:
		return False

StackEntry = namedtuple('StackEntry', ['value', 'type'])

class AsmFile(object):
	"""
	Abstract class to describe an ASM file.
	The inheriting subclasses should receive only a binary file name and disassemble it in order to implement this
	class' functions.
	"""

	def __init__(self, bin_filename):
		pass

	def get_func_address_size_and_content(self, func_name):
		"""
		Get the address, size and content of the function.

		:param func_name: The function name
		:type func_name: str
		:return: The address of the function, its size (in bytes) and its content
		:rtype: tuple(int, int, str)
		"""
		pass

	def get_function(self, func_name):
		"""
		Get an AsmFunction object describing the function.

		:param func_name: The function name
		:type func_name: str
		:return: AsmFunction object of the function
		:rtype: AsmFunction
		"""
		pass


class AsmElfFile(AsmFile):
	def __init__(self, elf_filename):
		"""
		Initiate the ELF file name and pwn.ELF object.

		:param elf_filename: The ELF filename
		:type elf_filename: str
		"""
		super(AsmElfFile, self).__init__(elf_filename)
		self._filename = elf_filename
		self._file = pwn.ELF(elf_filename)

	def get_func_address_size_and_content(self, func_name):
		"""
		Get the function's address, size and instructions.
		:param func_name: The function name.
		:type func_name: str
		:return: The function's address, size and instructions
		:rtype: tuple(int, int, str)
		"""
		func = self._file.functions[func_name]
		return func.address, func.size, self._file.disasm(func.address, func.size)

	def get_function(self, func_name):
		"""
		Get an AsmFunction of the function
		:param func_name: The function name
		:type func_name: str
		:return: An AsmFunction representing the function
		:rtype: AsmFunction
		"""
		return AsmFunction(self, func_name)


class AsmFunction(object):
	def __init__(self, src_file, function_name):
		"""
		Initiate the assembly function file, name, address, size and instructions.

		:param src_file: The ELF file from which to take the function
		:param function_name: The function name
		:type src_file: AsmFile
		:type function_name: str
		"""
		self._src_file = src_file
		self._name = function_name
		self._address, self._size, self._content = src_file.get_func_address_size_and_content(function_name)
		self._instructions = self.func_content_to_instruction_arr(self._content)
		self._reg_state_dict = {}
		self._stack_frame_state = {}
		self._parameters = []
		self._c_code = []
		self._curr_index = 0
		self._return_type = ''
		self._asm_instruction_parser = AsmInstructionParser.AsmInstructionParser(self)

	def decompile(self):
		self.init_parameters()
		self.make_c_code()
		self.calculate_return_type()

	def __str__(self):
		result = 'Function name: %s\n' % self._name
		result += 'Function address: %s\n' % hex(self._address)
		result += 'Function size: %d\n' % self._size
		result += 'Function parameters: %s\n' % ','.join(self._parameters)
		result += 'Function return type: %s\n' % self._return_type
		result += 'Content:\n%s' % self._content
		result += '\n' + '-' * 100 + '\n'
		result += 'Pseudo C Code:\n%s' % '\n'.join(self._c_code)
		return result

	@staticmethod
	def func_content_to_instruction_arr(func_content):
		"""
		Convert the instructions string into a list of InstructionLine

		:param func_content: The instructions
		:type func_content: str
		:return: The corresponding list of InstructionLine
		:rtype: list[AsmInstruction]
		"""
		instructions = []
		for line in func_content.split('\n'):
			try:
				inst = AsmInstruction(line)
				instructions.append(inst)
			except InvalidInstructionLineException as err:
				print err
		return instructions

	def calculate_return_type(self):
		"""
		[*] IN CASE OF A FUNCTION RETURNING A NON FLOATING-POINT VALUE:
			Iterate from the end of the instructions set of the function, search for the last assignment into RAX/EAX.
			RAX/EAX are the return value in x64 calling  convention, thus, by knowing the type put into RAX/EAX,
			we can also know what the return value's type is.

		[*] IF RETURN VALUE TYPE IS FLOAT:
			Need to handle.

		"""
		instructions = self._instructions[::-1]  # traverse from the end of the list.

		for inst in instructions:
			if len(inst.operands) > 1 and get_register(inst.operands[0]) == 'rax':
				src = inst.operands[1]
				return_type = self.get_english_size(
					src if not is_register(src) else self._reg_state_dict[get_register(src)])
				self._return_type = return_type
				return return_type

	def get_value(self, var):

		if is_int(var):
			return var

		elif is_register(var):
			if var in self._reg_state_dict:
				return self._reg_state_dict[var]
			else:
				return self._reg_state_dict[get_register(var)] if get_register(
					var) in self._reg_state_dict else var
		else:
			return self._stack_frame_state[var].value if var in self._stack_frame_state else var

	def set_value(self, var, value):
		if is_register(var):
			self._reg_state_dict[var] = value
			reg_size = 0

			for reg, partial_regs in REGISTERS_DICT.items():
				for size, pr in partial_regs.items():
					if pr == var:
						reg_size = size
						break

				if reg_size != 0:
					if is_int(reg_size):
						reg_size = int(reg_size)

						for size, pr in partial_regs.items():
							if (not is_int(size) or reg_size > int(size)) and pr in self._reg_state_dict:
								del self._reg_state_dict[pr]
					break
		else:
			if var in self._stack_frame_state:
				self._stack_frame_state[var]= self._stack_frame_state[var]._replace(value=value)
			else:
				self._stack_frame_state[var] = StackEntry(value=value, type=None)

	def get_english_size(self, value):
		"""
		For the given value, return the size of the value in english-words.

		Example:
			get_english_size("DWORD ptr [ebp-0x10]") ---> "DWORD"

		:param value: The value we wish to know the size of.
		:type: str
		:return: Size in words.
		:rtype: str
		"""
		numeric_size = self.get_size(value)

		if numeric_size == 128:
			raise Exception('Return-value type is 128 bits long, unhandled.\n')

		size_mapping = {
			8: 'BYTE',
			16: 'WORD',
			32: 'DWORD',
			64: 'QWORD'
		}
		return size_mapping[numeric_size]

	def get_size(self, value):
		"""
		For the given value, return the size of the value (amount of bits).

		Example:
			get_size('DWORD ptr [ebp-0x10]') ---> 32

		:param value: The value we wish to know the size of.
		:type: str
		:return: The size in bits.
		:rtype: int
		"""
		if is_register(value):
			if value in REGISTERS_128:
				return 128
			elif value in REGISTERS_64:
				return 64
			elif value in REGISTERS_32:
				return 32
			elif value in REGISTERS_16:
				return 16
			else:
				return 8
		else:
			SZ = value.split(' ')[0]
			if SZ == 'BYTE':
				return 8
			elif SZ == 'WORD':
				return 16
			elif SZ == 'DWORD':
				return 32
			elif SZ == 'QWORD':
				return 64
			else:
				raise Exception('Invalid size in dst/src of an instruction, value: %s ' % value)

	def make_c_code(self):
		while self._curr_index < len(self._instructions) - 1:
			self.update_state_dicts_by_inst(self._curr_index + 1, True)
			self._curr_index += 1

	def update_state_dicts_by_inst(self, ind, make_c_code=False):
		"""
		Process the instruction and update the state dicts according to it.

		NOTE:
			- We haven't handled access to global variables / addresses.

		:param ind: The index of the instruction in the function's instructions list
		:param make_c_code: A flag indicating whether the asm instruction should also be translated to a C instruction
			(if possible)
		:type ind: int
		:type make_c_code: bool
		:return: None
		"""
		inst = self._instructions[ind]
		dst = self._asm_instruction_parser.handle_instruction(inst)

		if dst is not None and not is_register(dst) and make_c_code:
			self.write_c_inst(dst)

	def write_c_inst(self, mem_var):
		c_inst = mem_var + ' = ' + self.get_value(mem_var) + ';'
		self._c_code.append(c_inst)
		self.set_value(mem_var, mem_var)

	def sorted_stack_frame(self):
		"""
		Sort the stack frame to fit the way stack behaves.

		:return: list representing stack frame keys.
		"""
		positive_idx = []
		negative_idx = []

		for k in self._stack_frame_state.keys():
			if '+' in k:
				positive_idx.append(k)
			else:
				negative_idx.append(k)

		# Sort it from highest positive to lowest
		positive_idx.sort(key=lambda x: int(x.split('+')[-1][2:-1], 16), reverse=True)

		# Sort from lowest highest negative to lowest
		negative_idx.sort(key=lambda x: int(x.split('-')[-1][2:-1], 16), reverse=False)

		return positive_idx + negative_idx

	def get_type(self, stack_element):
		if is_int(stack_element) or is_register(stack_element):
			raise Exception('Eror: Invalid stack element\n')
		return stack_element.split(' ')[0]
	
	def set_type(self, stack_element, element_type):
		if is_int(stack_element) or is_register(stack_element):
			raise Exception('Eror: Invalid stack element\n')
		
		if stack_element in self._stack_frame_state:
			self._stack_frame_state[stack_element]= self._stack_frame_state[stack_element]._replace(type=element_type)
		else:
			self._stack_frame_state[stack_element] = StackEntry(value=stack_element, type=element_type)

	def init_parameters(self):
		"""
		Parse the function's arguments based on the function's content.

		:return: None
		"""
		last_init_index = 0
		for inst in self._instructions:
			if inst.does_read_from_stack() and not inst.does_read_args_from_stack():  # reads from local variables
				last_init_index -= 1
				break

			last_init_index += 1

		for i in xrange(2, last_init_index + 1):
			self.update_state_dicts_by_inst(i)

		for stack_element in self.sorted_stack_frame():
			# stack_element is in the stack frame && looks like: `DWORD PTR [rbp-0x24]`.
			# value is the value stored in that stack frame location
			element_type = self.get_type(stack_element)
			self._parameters.append(element_type)
			self.set_type(stack_element, element_type)

		self._curr_index = last_init_index


class AsmInstruction(object):
	def __init__(self, line):
		"""
		Initiate the assembly instruction line address, command and comment address.

		If the command line doesn't contain a command, an exception is raised.

		:param line: The command line according to pwnlib.disasm output format
		:type line: str
		"""
		command_pattern = ' *([0-9a-f]+): *(?:[0-9a-f]{2} ){1,7} *([^ ]+)( *(?:[^,]+(?:,[^,]+)?)?)( *(?:# 0x.+)?)'
		if not re.match(command_pattern, line):
			raise InvalidInstructionLineException(line, 'Invalid instruction pattern')

		temp_line = re.sub(command_pattern, '\\1:\\2:\\3:\\4', line)

		address_str, self.operator, self.operands, comment_address = temp_line.split(':')
		self.operands = self.operands.strip().split(',') if self.operands.strip() != '' else []
		self._address = int('0x' + address_str, 16)
		if comment_address != '':  # In case of addresses in the binary file
			self._comment_address = int(''.join(comment_address[2:]), 16)
		else:
			self._comment_address = None

	def __str__(self):
		return self.operator + ' ' + ','.join(self.operands)

	def does_read_from_stack(self):
		"""
		Check if the instruction reads from the stack.
		:return: True if the instruction reads from the stack
		:rtype: bool
		"""
		return len(self.operands) == 2 and '[' in self.operands[1] and ']' in self.operands[1]

	def does_read_args_from_stack(self):
		"""
		Check if the instruction reads a function argument (function parameter).
		:return: True if the instruction reads a function argument
		:rtype: bool
		"""
		return self.does_read_from_stack() and '[rbp+' in self.operands[1]


class InvalidInstructionLineException(Exception):
	def __init__(self, instruction_line, reason=None):
		self._instruction_line = instruction_line
		self._reason = reason

	def __str__(self):
		s = "The instruction '{}' is invalid"
		if self._reason:
			s += " due to the reason '{}'"
		return s.format(self._instruction_line, self._reason)


if __name__ == '__main__':
	TestFile = AsmElfFile("calling_convention_chk")
	func = AsmFunction(TestFile, "four_chars_int")
	func.decompile()
	print str(func)
