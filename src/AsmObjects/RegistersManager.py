from src.Errors import BaseDecompilerError

REGISTERS_SECTION_NAME = "REGISTERS"


class Register(object):
    def __init__(self, reg_name, reg_family, reg_size):
        """
        :param reg_name: The register name.
        :type reg_name: str
        :param reg_family: The register family - the biggest containing register of this register
            (for example, the register family of rax,eax,ax,ah and al is rax)
        :type reg_family: str
        :param reg_size: The register size.
        :type reg_size: int
        """
        self.name = reg_name
        self.family = reg_family
        self.size = reg_size


class RegistersManager(object):
    def __init__(self, config_parser):
        """
        :param config_parser: The config file parser.
        :type config_parser: ConfigParser.ConfigParser
        """

        self._config_parser = config_parser

        self._all_registers = {}
        self.registers_128 = []
        self.registers_64 = []
        self.registers_32 = []
        self.registers_16 = []
        self.registers_8 = []

    def _get_registers_from_config(self):
        for reg_name, value in self._config_parser.items(REGISTERS_SECTION_NAME):
            reg_family, reg_size = value.split(",")
            reg_size = int(reg_size)
            self._all_registers[reg_name] = Register(reg_name, reg_family, reg_size)

    def is_register(self, name):
        """
        Check if the name is a valid register name.
        :param name: The name.
        :type name: str
        :return: True if the name is a valid register name, otherwise false.
        :rtype: bool
        """
        return name in self._all_registers

    def get_register(self, reg_name):
        """
        Get the register object.
        :param reg_name: The register name.
        :type reg_name: str
        :return: The register object.
        :rtype: Register
        """
        try:
            return self._all_registers[reg_name]
        except KeyError:
            raise RegisterNotExistsError(reg_name)

    def get_register_family(self, reg_name):
        """
        Get the register family.
        :param reg_name: The register name.
        :type reg_name: str
        :return: The register family.
        :rtype: str
        """
        return self.get_register(reg_name).family

    def get_family(self, family):
        """
        Get all the registers in the register family.
        :param family: The register family.
        :type family: str
        :return: All the registers in the register family.
        :rtype: list[Register]
        """
        registers = []

        for _, reg in self._all_registers:
            if reg.family == family:
                registers.append(reg)

        return registers


class RegisterNotExistsError(BaseDecompilerError):
    """
    An error to describe that a register doesn't exist.
    """

    def __init__(self, reg_name):
        """
        :param reg_name: The register name.
        :type reg_name: str
        """
        super(RegisterNotExistsError, self).__init__(reg_name)
        self.reg_name = reg_name

    def __str__(self):
        return "The register '{}' doesn't exist".format(self.reg_name)
