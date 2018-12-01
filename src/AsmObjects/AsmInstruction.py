import re


class AsmInstruction(object):
    def __init__(self, line, index, registers_manager):
        """
        Initiate the assembly instruction line address, command and comment address.

        If the command line doesn't contain a command, an exception is raised.

        :param line: The command line according to pwnlib.disasm output format
        :type line: str
        """
        self.index = index
        command_pattern = ' *([0-9a-f]+): *(?:[0-9a-f]{2} ){1,7} *([^ ]+)( *(?:[^,]+(?:,[^,]+)?)?)( *(?:# 0x.+)?)'
        if not re.match(command_pattern, line):
            raise InvalidInstructionLineException(line, 'Invalid instruction pattern')

        temp_line = re.sub(command_pattern, '\\1:\\2:\\3:\\4', line)

        address_str, self.operator, self.operands, comment_address = temp_line.split(':')
        self.operands = self.operands.strip().split(',') if self.operands.strip() != '' else []
        self.address = int('0x' + address_str, 16)
        if comment_address != '':  # In case of addresses in the binary file
            self._comment_address = int(''.join(comment_address[2:]), 16)
        else:
            self._comment_address = None

        self._registers_manager = registers_manager

    def __str__(self):
        return self.operator + ' ' + ','.join(self.operands)

    def does_read_from_stack(self):
        """
        Check if the instruction reads from the stack.
        :return: True if the instruction reads from the stack
        :rtype: bool
        """
        return len(self.operands) == 2 and '[rbp' in self.operands[1] and ']' in self.operands[1]

    def does_read_args_from_stack(self):
        """
        Check if the instruction reads a function argument (function parameter).
        :return: True if the instruction reads a function argument
        :rtype: bool
        """
        return self.does_read_from_stack() and '[rbp+' in self.operands[1]

    def is_mov(self):
        return self.operator.startswith('mov')

    def is_mov_reg_to_reg(self):
        return self.is_mov() and self._registers_manager.is_register(self.operands[0]) \
               and self._registers_manager.is_register(self.operands[1])

    def is_mov_reg_to_stack(self):
        return self.is_mov() and not (self._registers_manager.is_register(self.operands[0])) \
               and self._registers_manager.is_register(self.operands[1])

    def is_relevant(self):
        if len(self.operands) == 2:
            return not (self.operands[0] == 'rsp' or self.operands[1] == 'rsp')
        elif len(self.operands) == 1:
            return not (self.operands[0] == 'rsp')
        return True


class InvalidInstructionLineException(Exception):
    def __init__(self, instruction_line, reason=None):
        self._instruction_line = instruction_line
        self._reason = reason

    def __str__(self):
        s = "The instruction '{}' is invalid"
        if self._reason:
            s += " due to the reason '{}'"
        return s.format(self._instruction_line, self._reason)
