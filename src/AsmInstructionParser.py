from AsmParser import AsmFunction


class AsmInstructionParser:
    def __init__(self, asm_function):
        """
        Initiate the object's properties
        :param asm_function: The Asm Function object
        :type asm_function: AsmFunction
        """
        self._asm_function = asm_function

    def _mov_inst(self, dst, src):
        src_value = self._asm_function.get_value(src)
        self._asm_function.set_value(dst, src_value)

    def _generic_instruction(self, dst, src, operator, is_use_parentheses=True):
        """
        A generic handler for instructions, it used for instructions which consist of 2 operands: dst and src,
        and the output is as follows : dst = dst operator src (operator can be +,-,*...)

        :param dst: The destination operand
        :param src: The source operand
        :param operator: The action operator (must be an operator known in the C language)
        :param is_use_parentheses: A flag whether to use parentheses on the operands' values
        :type dst: str
        :type src: str
        :type operator: str
        :type is_use_parentheses: bool
        :return: None
        """
        src_value = self._asm_function.get_value(src)
        dst_value = self._asm_function.get_value(dst)

        if is_use_parentheses:
            final_value = '(' + dst_value + ')' + operator + '(' + src_value + ')'
        else:
            final_value = dst_value + operator + src_value

        self._asm_function.set_value(dst, final_value)

    def _add_inst(self, dst, src):
        self._generic_instruction(dst, src, '+', False)

    def _sub_inst(self, dst, src):
        self._generic_instruction(dst, src, '-', False)

    def _mul_inst_2_operands(self, dst, src):
        self._generic_instruction(dst, src, '*')

    def _mul_inst_1_operand(self, multiplier):
        size = self._asm_function.get_size(multiplier)
        src_value = self._asm_function.get_value(multiplier)

        if size == 8:
            multiplied_value = self._asm_function.get_value('al')
            self._asm_function.set_value('ax', '(' + multiplied_value + ')*(' + src_value + ')')

        elif size == 16:
            multiplied_value = self._asm_function.get_value('ax')
            self._asm_function.set_value('dx', 'HIWORD((' + multiplied_value + ')*(' + src_value + '))')
            self._asm_function.set_value('ax', 'LOWORD((' + multiplied_value + ')*(' + src_value + '))')

        elif size == 32:
            multiplied_value = self._asm_function.get_value('eax')
            self._asm_function.set_value('edx',
                                         'HIDWORD((' + multiplied_value + ')*(' + src_value + '))')
            self._asm_function.set_value('eax',
                                         'LODWORD((' + multiplied_value + ')*(' + src_value + '))')

        elif size == 64:
            multiplied_value = self._asm_function.get_value('rax')
            self._asm_function.set_value('rdx',
                                         'HIQWORD((' + multiplied_value + ')*(' + src_value + '))')
            self._asm_function.set_value('rax',
                                         'LOQWORD((' + multiplied_value + ')*(' + src_value + '))')

    def _shl_inst(self, dst, src='1'):
        self._generic_instruction(dst, src, '<<')

    def _shr_inst(self, dst, src='1'):
        self._generic_instruction(dst, src, '>>')

    def _xor_inst(self, dst, src):
        self._generic_instruction(dst, src, '^')

    def _and_inst(self, dst, src):
        self._generic_instruction(dst, src, '&')

    def _or_inst(self, dst, src):
        self._generic_instruction(dst, src, '|')

    def _not_inst(self, dst):
        self._asm_function.set_value(dst, '~(' + self._asm_function.get_value(dst) + ')')

    def handle_instruction(self, inst):
        """
        Handle an instruction and update the function's register and memory trackings according to it.

        :param inst: The instruction
        :type inst: AsmInstruction
        :return: The destination of the instruction (if there is one)
        :rtype: str
        """
        dst = None

        if len(inst.operands) >= 1 and ('rsp' == inst.operands[0] or 'rbp' == inst.operands[0]):
            # Ignoring these
            return

        if inst.operator.startswith('mov'):
            dst, src = inst.operands[0], inst.operands[1]
            self._mov_inst(dst, src)

        elif inst.operator == 'add' or inst.operator == 'adc' or inst.operator == 'adox' or inst.operator == 'adcx':
            dst, src = inst.operands[0], inst.operands[1]
            self._add_inst(dst, src)

        elif inst.operator == 'sub':
            dst, src = inst.operands[0], inst.operands[1]
            self._sub_inst(dst, src)

        elif inst.operator == 'mul' or inst.operator == 'imul':
            if len(inst.operands) == 1:
                multiplier = inst.operands[0]
                self._mul_inst_1_operand(multiplier)
            elif len(inst.operands) == 2:
                dst, src = inst.operands[0], inst.operands[1]
                self._mul_inst_2_operands(dst, src)

        elif inst.operator == 'shl' or inst.operator == 'sal':
            dst = inst.operands[0]
            src = None
            if len(inst.operands) > 1:
                src = inst.operands[1]
            self._shl_inst(dst, src)

        elif inst.operator == 'shr' or inst.operator == 'sar':
            dst = inst.operands[0]
            src = None
            if len(inst.operands) > 1:
                src = inst.operands[1]
            self._shr_inst(dst, src)

        elif inst.operator == 'xor':
            dst, src = inst.operands[0], inst.operands[1]
            self._xor_inst(dst, src)

        elif inst.operator == 'and':
            dst, src = inst.operands[0], inst.operands[1]
            self._add_inst(dst, src)

        elif inst.operator == 'or':
            dst, src = inst.operands[0], inst.operands[1]
            self._or_inst(dst, src)

        elif inst.operator == 'not':
            dst = inst.operands[0]
            self._not_inst(dst)

        return dst
