import pwn
import re


class AsmFunction(object):
    def __init__(self, src_file, function_name):
        """
        Initiate the assembly function file, name, address, size and instructions.
        :param src_file: The ELF file from which to take the function
        :param function_name: The function name

        :type src_file: str
        :type function_name: str
        """
        self._src_file = src_file
        self._name = function_name
        self._address, self._size, self._content = self.get_func_by_name(src_file, function_name)
        self._instructions = self.func_content_to_instruction_arr(self._content)

    @staticmethod
    def get_func_by_name(elf_file, func_name):
        """
        Get the function's address, size and instructions (as string).
        :param elf_file: The ELF file from which to take the function
        :param func_name: The function name

        :type elf_file: str
        :type func_name: str

        :return: function address, function size, function instructions
        :rtype: tuple(int, int, str)
        """
        e = pwn.ELF(elf_file)
        func = e.functions[func_name]
        return func.address, func.size, e.disasm(func.address, func.size)

    @staticmethod
    def func_content_to_instruction_arr(func_content):
        """
        Convert the instructions string into a list of InstructionLine
        :param func_content: The instructions

        :type func_content: str

        :return: The corresponding list of InstructionLine
        :rtype: list[InstructionLine]
        """
        instructions = []
        for line in func_content.split('\n'):
            try:
                inst = InstructionLine(line)
                instructions.append(inst)
            except InvalidInstrucionLineException as err:
                print err
        return instructions


class InstructionLine(object):
    def __init__(self, line):
        """
        Initiate the assembly instruction line address, command and comment address.

        If the command line doesn't contain a command, an exception is raised.
        :param line: The command line according to pwnlib.disasm output format

        :type line: str
        """
        command_pattern = ' *([0-9a-f]+): *(?:[0-9a-f]{2} ){1,7} *(.+)'
        if not re.match(command_pattern, line):
            raise InvalidInstrucionLineException(line, 'Invalid instruction pattern')

        temp_line = re.sub(command_pattern, '\\1:\\2', line)

        self._address, self._command = temp_line.split(':')
        self._address = int('0x' + self._address, 16)
        self._command = self._command.strip()
        if '# 0x' in line:  # In case of addresses in the binary file
            self._comment_address = int('0x' + line.split('# 0x')[-1], 16)
        else:
            self._comment_address = None


class InvalidInstrucionLineException(Exception):
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
            ins = InstructionLine(l)
            print "Address: {} \n Command: {}".format(ins._address, ins._command)
        except Exception as err:
            print err
