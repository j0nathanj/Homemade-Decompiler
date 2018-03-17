import pwn
import re


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
        func = self._file.functions[func_name]
        return func.address, func.size

    def get_function(self, func_name):
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


class AsmInstruction(object):
    def __init__(self, line):
        """
        Initiate the assembly instruction line address, command and comment address.

        If the command line doesn't contain a command, an exception is raised.

        :param line: The command line according to pwnlib.disasm output format
        :type line: str
        """
        command_pattern = ' *([0-9a-f]+): *(?:[0-9a-f]{2} ){1,7} *(.+)'
        if not re.match(command_pattern, line):
            raise InvalidInstructionLineException(line, 'Invalid instruction pattern')

        temp_line = re.sub(command_pattern, '\\1:\\2', line)

        address_str, self._command = temp_line.split(':')
        self._address = int('0x' + address_str, 16)
        self._command = self._command.strip()
        if '# 0x' in line:  # In case of addresses in the binary file
            self._comment_address = int('0x' + line.split('# 0x')[-1], 16)
        else:
            self._comment_address = None


class InvalidInstructionLineException(Exception):
    def __init__(self, instruction_line, reason=None):
        self._instruction_line = instruction_line
        self._reason = reason

    def __str__(self):
        s = "The instruction '{}' is invalid"
        if self._reason:
            s += " due to the reason '{}'"
        return s


if __name__ == '__main__':
    params = '''  400527:       48 89 e5                mov    rbp,rsp
  40052a:       48 83 ec 10             sub    rsp,0x10
  40052e:       c7 45 f4 05 00 00 00    mov    DWORD PTR [rbp-0xc],0x5
  400535:       c7 45 f8 07 00 00 00    mov    DWORD PTR [rbp-0x8],0x7'''
    for l in params.split('\n'):
        try:
            print l
            ins = AsmInstruction(l)
            print "Address: {} \n Command: {}".format(ins._address, ins._command)
        except Exception as err:
            print err
