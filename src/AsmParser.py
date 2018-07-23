import pwn
import re

'''
[!] Weekly tasks (21.07.2018):
    
    [*] Shahaf - [1] Adding more assembly instruction handling. (div, idiv, cvtsi2sd ... )
                 [?] Keeping track of variable types.
    
    [*] Jonathan - [1] Detecting return value type && value (assuming the function's parsing is valid)
    
'''

REGISTER_LIST = []
REGISTERS_128 = []
REGISTERS_64 = []
REGISTERS_32 = []
REGISTERS_16 = []
REGISTERS_8 = []

for reg in ['ax', 'bx', 'cx', 'dx', 'si', 'di', 'sp', 'bp']:
    REGISTER_LIST.append('r'+reg)  # 8 bytes
    REGISTERS_64.append('r'+reg)
    REGISTER_LIST.append('e'+reg)  # 4 bytes
    REGISTERS_32.append('e'+reg)
    REGISTER_LIST.append(reg)      # 2 bytes
    REGISTERS_16.append(reg)
    REGISTER_LIST.append(reg+'l' if 'x' not in reg else reg.replace('x', 'l'))  # 1 byte
    REGISTERS_8.append(reg+'l' if 'x' not in reg else reg.replace('x', 'l'))

for i in xrange(8, 16):
    REGISTER_LIST.append('r'+str(i))      # QWORD ; 8 BYTES
    REGISTERS_64.append('r'+str(i))
    REGISTER_LIST.append('r'+str(i)+'d')  # DWORD ; DOUBLE WORD; 4 BYTES
    REGISTERS_32.append('r'+str(i)+'d')
    REGISTER_LIST.append('r'+str(i)+'w')  # WORD  ; 2 BYTES
    REGISTERS_16.append('r'+str(i)+'w')
    REGISTER_LIST.append('r'+str(i)+'b')  # BYTE  ; BYTE
    REGISTERS_8.append('r'+str(i)+'b')

for i in xrange(0, 16):
    REGISTER_LIST.append('xmm'+str(i)) # XMM registers
    REGISTERS_128.append('xmm'+str(i))


def is_register(arg):
    return arg in REGISTER_LIST

def get_register(partial_reg):
    if partial_reg in ['al','ax','eax','rax']:
        return 'rax'
    elif partial_reg in ['bl','bx','ebx','rbx']:
        return 'rbx'
    elif partial_reg in ['cl','cx','ecx','rcx']:
        return 'rcx'
    elif partial_reg in ['dl','dx','edx','rdx']:
        return 'rdx'
    elif partial_reg in ['sil','si','esi','rsi']:
        return 'rsi'
    elif partial_reg in ['dil','di','edi','rdi']:
        return 'rdi'
    
    for i in xrange(8,16):
        if partial_reg in ['r'+str(i)+'b', 'r'+str(i)+'w', 'r'+str(i)+'d', 'r'+str(i)]:
            return 'r'+str(i)
    
    raise Exception('Invalid register %s\n' % partial_reg)

def is_int(s):
    try:
        int(s)
        return True
    except ValueError:
        return False

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
    
    def decompile(self):
        self.init_parameters()
        self.make_c_code()
    
    def __str__(self):
        result  = 'Function name: %s\n' % self._name
        result += 'Function address: %s\n' % hex(self._address)
        result += 'Function size: %d\n' % self._size
        result += 'Function parameters: %s\n' % ','.join(self._parameters)
        result += 'Content:\n%s' % self._content
        result += '\n'+'-'*100+'\n'
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
    
    def get_size(self, value):
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
        while self._curr_index < len(self._instructions)-1:
            self.update_state_dicts_by_inst(self._curr_index+1, True)
            self._curr_index += 1
            
            
    def update_state_dicts_by_inst(self, ind, make_c_code=False):
        """
        Process the instruction and update the state dicts according to it.

        NOTE:
            - We haven't handled access to global variables / addresses.

        :param ind: The index of the instruction in the function's instructions list
        :type ind: int
        :return: None
        """
        inst = self._instructions[ind]
        dst = None

        if len(inst.operands) >=1 and ('rsp' == inst.operands[0] or 'rbp' == inst.operands[0]):
            # Ignoring these
            return
        if inst.operator.startswith('mov'):
            dst, src = inst.operands[0], inst.operands[1]
            if is_register(src):
                value = self._reg_state_dict[get_register(src)] if get_register(src) in self._reg_state_dict else get_register(src)
            else:
                value = self._stack_frame_state[src] if src in self._stack_frame_state else src
            if is_register(dst):
                self._reg_state_dict[get_register(dst)] = value
            else:
                self._stack_frame_state[dst] = value

        elif inst.operator == 'add' or inst.operator == 'adc' or inst.operator == 'adox' or inst.operator == 'adcx':
            dst, src = inst.operands[0], inst.operands[1]

            if is_register(src):
                value =  self._reg_state_dict[get_register(src)] if get_register(src) in self._reg_state_dict else get_register(src)
            else:
                value =  self._stack_frame_state[src] if src in self._stack_frame_state else src

            if is_register(dst):
                self._reg_state_dict[get_register(dst)] = '(' + self._reg_state_dict[get_register(dst)] + ')+' + value
            else:
                self._stack_frame_state[dst] = '(' + self._stack_frame_state[dst] + ')+' + value

        elif inst.operator == 'sub':
            dst, src = inst.operands[0], inst.operands[1]

            if is_register(src):
                value =  self._reg_state_dict[get_register(src)] if get_register(src) in self._reg_state_dict else get_register(src)
            else:
                value =  self._stack_frame_state[src] if src in self._stack_frame_state else src

            if is_register(dst):
                self._reg_state_dict[get_register(dst)] = '(' + self._reg_state_dict[get_register(dst)] + ')-' + value
            else:
                self._stack_frame_state[dst] = '(' + self._stack_frame_state[dst] + ')-' + value

        elif inst.operator == 'mul' or inst.operator == 'imul':
            if len(inst.operands) == 1:
                multiplier = inst.operands[0]
                size = self.get_size(multiplier)

                if is_register(multiplier):
                    multiplier_value = self._reg_state_dict[get_register(multiplier)] if get_register(multiplier) in self._reg_state_dict else get_register(multiplier)
                else:
                    multiplier_value = self._stack_frame_state[multiplier] if multiplier in self._stack_frame_state else multiplier

                if size == 8:
                    self._reg_state_dict[get_register('ax')] = self._reg_state_dict[get_register('al')] + '*' + multiplier_value

                elif size == 16:
                    self._reg_state_dict[get_register('dx')] = 'HIWORD('+self._reg_state_dict[get_register('ax')] + '*' + multiplier_value +')'
                    self._reg_state_dict[get_register('ax')] = 'LOWORD('+self._reg_state_dict[get_register('ax')] + '*' + multiplier_value +')'

                elif size == 32:
                    self._reg_state_dict[get_register('edx')] = 'HIDWORD('+self._reg_state_dict[get_register('eax')] + '*' + multiplier_value +')'
                    self._reg_state_dict[get_register('eax')] = 'LODWORD('+self._reg_state_dict[get_register('eax')] + '*' + multiplier_value +')'

                elif size == 64:
                    self._reg_state_dict['rdx'] = 'HIQWORD('+self._reg_state_dict['rax'] + '*' + multiplier_value +')'
                    self._reg_state_dict['rax'] = 'LOQWORD('+self._reg_state_dict['rax'] + '*' + multiplier_value +')'

            elif len(inst.operands) == 2:
                dst, src = inst.operands[0], inst.operands[1]
                size1 = self.get_size(dst)
                size2 = self.get_size(src)
                assert size1 == size2

                if is_register(src):
                    value =  self._reg_state_dict[get_register(src)] if get_register(src) in self._reg_state_dict else get_register(src)
                else:
                    value =  self._stack_frame_state[src] if src in self._stack_frame_state else src

                if is_register(dst):
                    self._reg_state_dict[get_register(dst)] = '(' + self._reg_state_dict[get_register(dst)] + ')*' + value
                else:
                    self._stack_frame_state[dst] = '(' + self._stack_frame_state[dst] + ')*' + value
        elif inst.operator == 'shl' or inst.operator == 'sal':
            dst = inst.operands[0]
            if len(inst.operands) == 1:
                multiply_by = 2
            else:
                power_arg = inst.operands[1]
                if is_int(power_arg):
                    multiply_by = 2 ** int(power_arg)
                elif is_register(power_arg):
                    multiply_by = self._reg_state_dict[get_register(power_arg)] if get_register(power_arg) in self._reg_state_dict else get_register(power_arg)
                else:
                    multiply_by = self._stack_frame_state[power_arg] if power_arg in self._stack_frame_state else power_arg

            if is_register(dst):
                self._reg_state_dict[get_register(dst)] += '*' + multiply_by
            else:
                self._stack_frame_state[dst] += '*' + multiply_by
        elif inst.operator == 'shr' or inst.operator == 'sar':
            dst = inst.operands[0]
            if len(inst.operands) == 1:
                multiply_by = 2
            else:
                power_arg = inst.operands[1]
                if is_int(power_arg):
                    multiply_by = 2 ** int(power_arg)
                elif is_register(power_arg):
                    multiply_by = self._reg_state_dict[get_register(power_arg)] if get_register(power_arg) in self._reg_state_dict else get_register(power_arg)
                else:
                    multiply_by = self._stack_frame_state[power_arg] if power_arg in self._stack_frame_state else power_arg

            if is_register(dst):
                self._reg_state_dict[get_register(dst)] += '/' + multiply_by
            else:
                self._stack_frame_state[dst] += '/' + multiply_by
        elif inst.operator == 'xor':
            dst, src = inst.operands[0], inst.operands[1]

            if is_register(src):
                value = self._reg_state_dict[get_register(src)] if get_register(src) in self._reg_state_dict else get_register(src)
            else:
                value = self._stack_frame_state[src] if src in self._stack_frame_state else src

            if is_register(dst):
                self._reg_state_dict[get_register(dst)] = '(' + self._reg_state_dict[get_register(dst)] + ')^' + value
            else:
                self._stack_frame_state[dst] = '(' + self._stack_frame_state[dst] + ')^' + value
        elif inst.operator == 'and':
            dst, src = inst.operands[0], inst.operands[1]

            if is_register(src):
                value = self._reg_state_dict[get_register(src)] if get_register(src) in self._reg_state_dict else get_register(src)
            else:
                value = self._stack_frame_state[src] if src in self._stack_frame_state else src

            if is_register(dst):
                self._reg_state_dict[get_register(dst)] = '(' + self._reg_state_dict[get_register(dst)] + ')&' + value
            else:
                self._stack_frame_state[dst] = '(' + self._stack_frame_state[dst] + ')&' + value
        elif inst.operator == 'or':
            dst, src = inst.operands[0], inst.operands[1]

            if is_register(src):
                value = self._reg_state_dict[get_register(src)] if get_register(src) in self._reg_state_dict else get_register(src)
            else:
                value = self._stack_frame_state[src] if src in self._stack_frame_state else src

            if is_register(dst):
                self._reg_state_dict[get_register(dst)] = '(' + self._reg_state_dict[get_register(dst)] + ')|' + value
            else:
                self._stack_frame_state[dst] = '(' + self._stack_frame_state[dst] + ')|' + value
        elif inst.operator == 'not':
            dst = inst.operands[0]

            if is_register(dst):
                self._reg_state_dict[get_register(dst)] = '~(' + self._reg_state_dict[get_register(dst)] + ')'
            else:
                self._stack_frame_state[dst] = '~(' + self._stack_frame_state[dst] + ')'

        if dst is not None and not is_register(dst) and make_c_code:
            self.write_c_inst(dst)
            
            # ======================================================================================================#
            # > Finish handling the state dicts for `MOV` operator and add cases for other basic operators          #
            # > Checking CAPSTONE/KEYSTONE may be interesting for instruction parsing/handling.                     #
            # ======================================================================================================#
    
    def write_c_inst(self,mem_var):
        c_inst = mem_var +' = '+self._stack_frame_state[mem_var]+';'
        self._c_code.append(c_inst)
        self._stack_frame_state[mem_var] = mem_var

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
        positive_idx.sort(key = lambda x : int(x.split('+')[-1][2:-1], 16), reverse = True)
        
        # Sort from lowest highest negative to lowest
        negative_idx.sort(key = lambda x : int(x.split('-')[-1][2:-1], 16), reverse = False)

        return positive_idx + negative_idx

    def init_parameters(self):
        """
        Parse the function's arguments based on the function's content.
        
        :return: None
        """
        last_init_index = 0
        for inst in self._instructions:
            if inst.does_read_from_stack() and not inst.does_read_args_from_stack(): # reads from local variables
                last_init_index -= 1
                break
            
            last_init_index +=1

        for i in xrange(2, last_init_index+1):
            inst = self._instructions[i]
            self.update_state_dicts_by_inst(i)
            # ==================================================================================================#
            # > Continue updating state dicts using a the function "update_state_dicts_by_inst".                #
            # > Analyze the function's arguments.                                                               #
            # ==================================================================================================#
        
        for stack_element in self.sorted_stack_frame():
            # stack_element is in the stack frame && looks like: `DWORD PTR [rbp-0x24]`.
            # value is the value stored in that stack frame location
            self._parameters.append(stack_element.split(' ')[0])

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
        if comment_address != '':	# In case of addresses in the binary file
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
    func = AsmFunction(TestFile, "with_locals")
    func.decompile()
    print str(func)

