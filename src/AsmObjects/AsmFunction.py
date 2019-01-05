from collections import namedtuple

from AsmInstructionParser import AsmInstructionParser
from AsmObjects.AsmInstruction import InvalidInstructionLineException, AsmInstruction
from AsmObjects.BasicBlock import BasicBlock
from AsmObjects.RegistersManager import RegistersManager
from Utilities import is_int

StackEntry = namedtuple('StackEntry', ['value', 'type'])

JUMPS_INSTRUCTION_OPTION_PATH = ("GENERAL", "jump")
CONDITIONAL_JUMPS_SECTION_NAME = "CONDITIONAL_JUMPS"
VARIABLE_FORMAT_OPTION_PATH = ("GENERAL", "variable_format")
PC_REG_OPTION_PATH = ("GENERAL", "pc_reg")

class AsmFunction(object):

	def __init__(self, src_file, function_name, config_parser):
		"""
		Initiate the assembly function file, name, address, size and instructions.

		:param src_file: The ELF file from which to take the function
		:type src_file: BaseAsmFile
		:param function_name: The function name
		:type function_name: str
		:param config_parser: The configuration file parser of the project.
		:type config_parser: ConfigParser.ConfigParser
		"""
		self._src_file = src_file
		self._name = function_name
		self._config_parser = config_parser
		self._registers_manager = RegistersManager(config_parser)
		self._address, self._size, self._content = src_file.get_func_address_size_and_content(function_name)
		self._instructions = self.func_content_to_instruction_arr(self._content)
		self._reg_state_dict = {}
		self._stack_frame_state = {}
		self._global_state_dict = {}
		self._parameters = []
		self._c_code = ""
		self._basic_blocks = []
		self._curr_index = 0
		self._return_type = ''
		self._return_value = ''
		self.asm_instruction_parser = AsmInstructionParser(self, self._registers_manager)
		self._init_jumps()

	def _init_jumps(self):
		"""
		Initiate the jump instructions.
		"""
		self._jump_instruction = self._config_parser.get(*JUMPS_INSTRUCTION_OPTION_PATH)
		self._conditional_jumps = {}

		for cond_jmp, operator in self._config_parser.items(CONDITIONAL_JUMPS_SECTION_NAME):
			self._conditional_jumps[cond_jmp] = operator

	def decompile(self):
		self.init_parameters()
		self.calculate_return_type()
		self.calculate_return_value()
		self.split_to_basic_blocks()
		self.decompile_basic_blocks()
		self.connect_basic_blocks()
		self._c_code = self.make_c_code(self._basic_blocks[0])
		self.rename_local_variables()

	def __str__(self):
		result = 'Function name: %s\n' % self._name
		result += 'Function address: %s\n' % hex(self._address)
		result += 'Function size: %d\n' % self._size
		result += 'Function parameters: %s\n' % ','.join([a[1] + ' ' + a[0] for a in self._parameters])
		result += 'Function return type: %s\n' % self._return_type
		result += 'Return Value: %s\n' % self._return_value
		result += 'Content:\n%s' % self._content
		result += '\n' + '-' * 100 + '\n'
		result += 'Pseudo C Code:\n'

		result += self._c_code

		result += '\nreturn ' + self._return_value + ';\n'
		print self._stack_frame_state
		print self._reg_state_dict
		return result

	def func_content_to_instruction_arr(self, func_content):
		"""
		Convert the instructions string into a list of InstructionLine

		:param func_content: The instructions
		:type func_content: str
		:return: The corresponding list of InstructionLine
		:rtype: list[AsmInstruction]
		"""
		instructions = []
		for index, line in enumerate(func_content.split('\n')):
			try:
				inst = AsmInstruction(line, index, self._registers_manager)
				instructions.append(inst)
			except InvalidInstructionLineException as err:
				print err
			except Exception as e:
				print e
				print index, line
				raise
		return instructions

	def rename_local_variables(self):
		"""
		Rename local variables (from "DWORD ptr ..." to something more human-readable).
		The _c_code attribute should contain the C code.
		"""
		variable_format = self._config_parser.get(*VARIABLE_FORMAT_OPTION_PATH)
		for idx, stack_var in enumerate(self._stack_frame_state):
			self._c_code = self._c_code.replace(stack_var, variable_format.format(idx))

	def split_to_basic_blocks(self):
		basic_blocks_beginnings = {self._instructions[self._curr_index].address}  # start addresses of the basic blocks
		basic_blocks_endings = set()
		basic_blocks_instructions = []	# list of tuples, each tuple is: (start_addr, LIST_OF_INSTRUCTIONS)
		all_jmp_options = self._conditional_jumps.keys() + [self._jump_instruction]
		basic_block_curr = (self._instructions[self._curr_index].address, [])

		while self._curr_index < len(self._instructions):

			if self._instructions[self._curr_index].address in basic_blocks_beginnings and len(
					basic_blocks_beginnings) != 1:
				basic_blocks_instructions.append(basic_block_curr)
				basic_block_curr = (self._instructions[self._curr_index].address, [])
				basic_blocks_endings.add(self._instructions[self._curr_index].address)

			basic_block_addr, basic_block_curr_list = basic_block_curr
			basic_block_curr_list.append(self._instructions[self._curr_index])
			basic_block_curr = (basic_block_addr, basic_block_curr_list)

			if self._instructions[self._curr_index].operator in all_jmp_options:
				basic_blocks_beginnings.add(self._instructions[self._curr_index + 1].address)
				basic_blocks_beginnings.add(int(self._instructions[self._curr_index].operands[0], 16))
				basic_blocks_endings.add(self._instructions[self._curr_index].address)

			self._curr_index += 1

		basic_blocks_endings.add(self._instructions[self._curr_index - 1].address)
		basic_blocks_instructions.append(basic_block_curr)

		basic_blocks_beginnings = sorted(basic_blocks_beginnings, key=int)
		basic_blocks_endings = sorted(basic_blocks_endings, key=int)
		basic_blocks_instructions = sorted(basic_blocks_instructions, key=lambda x: x[0])
		self._basic_blocks = []

		# BasicBlock(self, start_addr, end_addr, asm_instructions, asm_function)
		for ind in xrange(len(basic_blocks_beginnings)):
			basic_block = BasicBlock(basic_blocks_beginnings[ind], basic_blocks_endings[ind],
									 basic_blocks_instructions[ind][1], self, self._registers_manager)
			self._basic_blocks.append(basic_block)

	def decompile_basic_blocks(self):
		for basic_block in self._basic_blocks:
			basic_block.decompile_block()

	def find_block_by_index(self, index):
		for basic_block in self._basic_blocks:
			if basic_block.asm_instructions[0].index == index:
				return basic_block

	def find_block_by_address(self, address):
		address = int(address, 16)
		for basic_block in self._basic_blocks:
			if basic_block.start_addr == address:
				return basic_block

	def connect_basic_blocks(self):

		for block in self._basic_blocks:
			operator = block.asm_instructions[-1].operator

			if operator in self._conditional_jumps:
				target_address = block.asm_instructions[-1].operands[0]
				target_true = self.find_block_by_address(target_address)
				target_false = self.find_block_by_index(block.asm_instructions[-1].index + 1)
				block_map = {True: target_true, False: target_false}
				target_true.reachers.add(block)
				target_false.reachers.add(block)

			elif operator == 'jmp':  # direct jump
				target_address = block.asm_instructions[-1].operands[0]
				block_map = self.find_block_by_address(target_address)
				block_map.reachers.add(block)

			else:
				block_map = self.find_block_by_index(block.asm_instructions[-1].index + 1)
				if block_map:
					block_map.reachers.add(block)

			block.block_map = block_map

	def make_c_code(self, start_block, stop_at=None, indent_level = 0):
		"""
		Get the C code of the function.
		:param start_block: The basic block to start with.
		:type start_block: BasicBlock
		:param stop_at: The basic block to stop at.
		:type stop_at: BasicBlock
		:return: The C code from the start_block to the stop_at block (or end of function is stop_at is None).
		:rtype: str
		"""

		if (stop_at and start_block == stop_at) or start_block is None:
			return ''
		
		c_code = [' '*(4*indent_level) + c_line for c_line in start_block.c_code]
		
		#c_code = '\n'.join(start_block.c_code)
		c_code  = '\n'.join(c_code)
		block_type = self.get_block_type(start_block)  # 'NORMAL' / 'IF' / 'LOOP'

		if block_type == 'NORMAL':
			c_code += self.make_c_code(start_block.block_map, stop_at=stop_at, indent_level = indent_level)
		elif block_type == 'IF':
			meeting_block, distance = self.get_meeting_block(start_block.block_map[True], start_block.block_map[False])
			if meeting_block == start_block.block_map[True]:
				c_code += self.get_if_statement(start_block, invert=True, indent_level = indent_level)
				c_code += self.make_c_code(start_block.block_map[False], stop_at=meeting_block, indent_level = indent_level + 1)
				c_code += '\n' + indent_level * 4 * ' ' + '}\n'


			elif meeting_block == start_block.block_map[False]:
				c_code += self.get_if_statement(start_block, invert=False, indent_level = indent_level )
				c_code += self.make_c_code(start_block.block_map[True], stop_at=meeting_block, indent_level = indent_level + 1)
				c_code += '\n' + indent_level * 4 * ' ' + '}\n'

			else:
				c_code += self.get_if_statement(start_block, invert=False, indent_level = indent_level)
				c_code += self.make_c_code(start_block.block_map[True], stop_at=meeting_block, indent_level = indent_level + 1)
				c_code += '\n' + indent_level * 4 * ' ' + '}\n'
				c_code += self.get_else_statement(indent_level = indent_level)
				c_code += self.make_c_code(start_block.block_map[False], stop_at=meeting_block, indent_level = indent_level + 1)
				c_code += '\n' + indent_level * 4 * ' ' + '}\n'


			c_code += self.make_c_code(meeting_block, stop_at=stop_at, indent_level = indent_level)

		elif block_type == 'LOOP':
			c_code += self.get_while_statement(start_block, invert=False, indent_level = indent_level)
			c_code += self.make_c_code(start_block.block_map[True], stop_at=start_block, indent_level = indent_level + 1)
			c_code += '\n' + indent_level * 4 * ' ' + '}\n'
			c_code += self.make_c_code(start_block.block_map[False], stop_at=stop_at, indent_level = indent_level)

		else:
			raise Exception('[!] Invalid block type!')

		return c_code

	def get_meeting_block(self, block1, block2, exclude_list=None, distance=0):
		if block1 == block2:
			return block1, distance

		if not exclude_list:
			exclude_list = []
		else:
			exclude_list = exclude_list[:]

		if block1 in exclude_list or block1 is None:
			return None, distance

		exclude_list.append(block1)
		exclude_list.append(block2)
		result_list = []

		if type(block1.block_map) == dict:
			result_list.append(self.get_meeting_block(block1.block_map[True], block2, exclude_list, distance + 1))
			result_list.append(self.get_meeting_block(block1.block_map[False], block2, exclude_list, distance + 1))
		else:
			result_list.append(self.get_meeting_block(block1.block_map, block2, exclude_list, distance + 1))

		if type(block2.block_map) == dict:
			result_list.append(self.get_meeting_block(block2.block_map[True], block1, exclude_list, distance + 1))
			result_list.append(self.get_meeting_block(block2.block_map[False], block1, exclude_list, distance + 1))
		else:
			result_list.append(self.get_meeting_block(block2.block_map, block1, exclude_list, distance + 1))

		min_distance = None
		closest_block = None

		for block, dist in result_list:
			is_not_or_shared_code = True

			if block:
				reacher_cnt = self.get_if_reachers_count(block)
				is_not_or_shared_code = (reacher_cnt == 1) or (reacher_cnt != len(list(block.reachers)))

			if (min_distance is None or dist < min_distance) and block and is_not_or_shared_code:
				min_distance = dist
				closest_block = block

		return closest_block, min_distance

	def get_if_reachers_count(self, block):
		count = 0
		lst = list(block.reachers)
		for index in xrange(len(lst)):
			if self.get_block_type(lst[index]) == 'IF':
				count += 1
		return count

	def get_block_type(self, block):
		"""
		Get the type of the block.

		:param block: The block.
		:type block: BasicBlock
		:return: Whether the block is normal ("NORMAL"), loop ("LOOP") or if ("IF").
		:rtype: str
		"""
		last_instruction = block.asm_instructions[-1]

		if last_instruction.operator not in self._conditional_jumps:
			return 'NORMAL'

		target_address = int(last_instruction.operands[0], 16)

		if target_address > block.start_addr:
			return 'IF'

		return 'LOOP'

	def get_conditional_statement(self, block, invert=False):
		operator = self._conditional_jumps[block.asm_instructions[-1].operator]
		cmp_condition = block.asm_instructions[-2]
		lval = self.get_value(cmp_condition.operands[0], cmp_condition)
		rval = self.get_value(cmp_condition.operands[1], cmp_condition)
		sign = ''
		if invert:
			sign = '!'
		return sign + '(' + (' '.join([lval, operator, rval])) + ')'

	def get_if_statement(self, block, invert=False, indent_level = 0):
		return '\n'+ ' ' * 4 * indent_level + 'if ( {} )\n'.format(self.get_conditional_statement(block, invert)) + ' ' * 4 * indent_level+'{\n'

	def get_while_statement(self, block, invert=False, indent_level = 0):
		return '\n'+  ' ' * 4 * indent_level + 'while ( {} )\n'.format(self.get_conditional_statement(block, invert)) + ' ' * 4 * indent_level + '{\n'

	@staticmethod
	def get_else_statement(indent_level = 0):
		return ' ' * 4 * indent_level + 'else\n' + ' ' * 4 * indent_level + '{\n'

	def calculate_return_value(self):
		"""
		Using the already-known return type, we calculate the return value!
		"""
		if self._return_type == '':
			raise Exception('Error: return type not calculated yet!\n')

		mapping = {'DWORD': 'eax', 'QWORD': 'rax', 'WORD': 'ax', 'BYTE': 'al'}
		if self._return_type in ['float', 'double']:  # Accessing xmm0 to get return value
			return_value = self.get_value('xmm0', None)
		else:
			return_value = self.get_value(mapping[self._return_type], None)

		self._return_value = return_value
		return return_value

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

		'''
			1) If RAX was the last `mov` destination, returns the type given to RAX.
			2) If xmm0 was last `mov` destination, it's either `float` or either `double`, depends if it was `sd` 
				or `ss` operation.

			So, first thing we do is to detect if the latest one was RAX or XMM0
		'''

		xmm0_or_rax_found = False  # if we find RAX/XMM0, we set this flag!
		for inst in instructions:
			if len(inst.operands) > 1 and \
					self._registers_manager.is_register(inst.operands[0]) and \
					self._registers_manager.get_register_family(inst.operands[0]) == 'rax' and \
					not xmm0_or_rax_found:
				src = inst.operands[1]
				return_type = self.get_english_size(
					src if not self._registers_manager.is_register(src) else self.get_value(src, inst))
				self._return_type = return_type
				return return_type

			if len(inst.operands) > 1 and inst.operands[0] == 'xmm0' and not xmm0_or_rax_found:
				return_type = self.precision_to_type(self.get_precision(inst))
				self._return_type = return_type
				return return_type

	@staticmethod
	def get_precision(instruction):
		operator = instruction.operator
		if operator.endswith('sd'):
			return 'double'
		elif operator.endswith('ss'):
			return 'single'
		else:
			raise Exception('Invalid instruction: Does not imply Float/Double : %s' % instruction)

	@staticmethod
	def precision_to_type(precision):
		if precision == 'double':
			return 'double'

		elif precision == 'single':
			return 'float'

		else:
			raise Exception('Invalid precision: Does not imply Float/Double: %s' % precision)

	def get_value(self, var, instruction):
		"""
		Get the value of the variable.
		:param var: The variable name (can be a stack address, register name or a number).
		:type var: str
		:return: The variable name.
		:rtype: str
		"""
		if is_int(var):
			# The variable is a number
			return var

		elif self._registers_manager.is_register(var):
			# The variable is a register
			if var in self._reg_state_dict:
				return self._reg_state_dict[var]
			elif self._registers_manager.get_register_family(var) in self._reg_state_dict:
				return self._reg_state_dict[self._registers_manager.get_register_family(var)]
			else:
				return var

		elif self.is_global_var(var):
			target_addr = instruction._comment_address
			target_prefix = self.get_english_size(var).lower()
			target = target_prefix + '_' +hex(target_addr)[2:]
			return target

		else:
			# The variable is a stack address
			return self._stack_frame_state[var].value if var in self._stack_frame_state else var

	def set_value(self, var, value, instruction):
		if self._registers_manager.is_register(var):
			register = self._registers_manager.get_register(var)
			self._reg_state_dict[register.name] = value

			register_faily = self._registers_manager.get_family(register.family)

			for cur_reg in register_faily:
				if register.size > int(cur_reg.size) and cur_reg.name in self._reg_state_dict:
					del self._reg_state_dict[cur_reg.name]
		
		elif self.is_global_var(var):
			target_addr = instruction._comment_address
			target_prefix = self.get_english_size(var).lower()
			target = target_prefix + '_'+hex(target_addr)[2:]
			self._global_state_dict[target] = value
		
		else:
			if var in self._stack_frame_state:
				self._stack_frame_state[var] = self._stack_frame_state[var]._replace(value=value)
			else:
				self._stack_frame_state[var] = StackEntry(value=value, type=None)
	
	def is_global_var(self, var):
		return self._config_parser.get(*PC_REG_OPTION_PATH) in var

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
		if self._registers_manager.is_register(value):
			register = self._registers_manager.get_register(value)
			if register.size == 128:
				return 128
			elif register.size == 64:
				return 64
			elif register.size == 32:
				return 32
			elif register.size == 16:
				return 16
			else:
				return 8
		
		elif is_int(value, 16):
			return self.get_const_size(value)
		
		else:
			size = value.split(' ')[0]
			
			if size == 'BYTE':
				return 8
			elif size == 'WORD':
				return 16
			elif size == 'DWORD':
				return 32
			elif size == 'QWORD':
				return 64
			else:
				raise Exception('Invalid size in dst/src of an instruction, value: %s ' % value)

	def get_const_size(self, value):
		int_val = int(value, 16)
		if int_val < 0x100:
			return 8
		elif int_val < 0x10000:
			return 16
		elif int_val < 0x100000000:
			return 32
		else:
			return 64

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
		dst = self.asm_instruction_parser.handle_instruction(inst)

		if dst is not None and not self._registers_manager.is_register(dst) and make_c_code:
			self.write_c_inst(dst, inst)

	def write_c_inst(self, mem_var, inst):
		c_inst = mem_var + ' = ' + self.get_value(mem_var, inst) + ';'
		self._c_code.append(c_inst)
		self.set_value(mem_var, mem_var, inst)

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
		if is_int(stack_element) or self._registers_manager.is_register(stack_element):
			raise Exception('Error: Invalid stack element\n')
		return stack_element.split(' ')[0]

	def set_type(self, stack_element, element_type):
		if is_int(stack_element) or self._registers_manager.is_register(stack_element):
			raise Exception('Error: Invalid stack element\n')

		if stack_element in self._stack_frame_state:
			self._stack_frame_state[stack_element] = self._stack_frame_state[stack_element]._replace(type=element_type)
		else:
			self._stack_frame_state[stack_element] = StackEntry(value=stack_element, type=element_type)

	def init_parameters(self):
		"""
		Parse the function's arguments based on the function's content.
		"""
		last_init_index = 2
		for inst in self._instructions[2:]:
			# if inst.does_read_from_stack() and not (inst.does_read_args_from_stack() or inst.reg_to_reg() :
			# reads from local variables
			if not (inst.is_mov_reg_to_reg() or inst.is_mov_reg_to_stack()) and inst.is_relevant():
				last_init_index -= 1
				break

			last_init_index += 1

		for i in xrange(2, last_init_index + 1):
			self.update_state_dicts_by_inst(i)

		param_idx = 0
		for stack_element in self.sorted_stack_frame():
			#import pdb; pdb.set_trace()
			param_idx += 1
			# stack_element is in the stack frame && looks like: `DWORD PTR [rbp-0x24]`.
			# value is the value stored in that stack frame location
			element_type = self.get_type(stack_element)
			param_reg = self.get_value(stack_element, None)
			
			param_name = "param{}".format(param_idx)
			self._parameters.append((param_name, element_type, param_reg))
			self.set_value(stack_element, param_name, None)

			self.set_type(stack_element, element_type)

		self._curr_index = last_init_index + 1
