class BasicBlock(object):
    """
    Represent a basic block.
    """

    def __init__(self, start_addr, end_addr, asm_instructions, asm_function, registers_manager):
        """
        :param start_addr: The start address of the block.
        :type start_addr: int
        :param end_addr: The end address of the block.
        :type end_addr: int
        :param asm_instructions: The instruction of the block.
        :type asm_instructions: list[src.AsmObjects.AsmInstruction.AsmInstruction]
        :param asm_function: The ASM function.
        :type asm_function: src.AsmObjects.AsmFunction.AsmFunction
        :param registers_manager: A registers manager.
        :type registers_manager: src.AsmObjects.RegistersManager.RegistersManager
        """
        self.start_addr = start_addr
        self.end_addr = end_addr
        self.asm_instructions = asm_instructions
        self.c_code = []
        self.asm_function = asm_function
        self.block_map = None
        self.reachers = set([])
        self._registers_manger = registers_manager

    def decompile_block(self):
        curr_index = 0
        while curr_index < len(self.asm_instructions):
            self.update_state_dicts_by_inst(curr_index, True)
            curr_index += 1

    def update_state_dicts_by_inst(self, ind, make_c_code=False):
        """
        Process the instruction and update the state dicts according to it.

        NOTE:
            - We haven't handled access to global variables / addresses.

        :param ind: The index of the instruction in the function's instructions list
        :type ind: int
        :param make_c_code: A flag indicating whether the asm instruction should also be translated to a C instruction
            (if possible)
        :type make_c_code: bool
        """
        inst = self.asm_instructions[ind]
        dst = self.asm_function.asm_instruction_parser.handle_instruction(inst)

        if dst is not None and not self._registers_manger.is_register(dst) and make_c_code:
            self.write_c_inst(dst)

    def write_c_inst(self, mem_var):
        c_inst = mem_var + ' = ' + self.asm_function.get_value(mem_var) + ';'
        self.c_code.append(c_inst)
        self.asm_function.set_value(mem_var, mem_var)
