import os
from ConfigParser import SafeConfigParser

from src.AsmObjects.AsmFile import AsmElfFile
from src.AsmObjects.AsmFunction import AsmFunction

CONFIG_FILE_PATH = os.path.join(os.path.dirname(__file__), "config.ini")


def main():
    config_parser = SafeConfigParser()
    config_parser.read(CONFIG_FILE_PATH)

    test_file = AsmElfFile("calling_convention_chk")
    func = AsmFunction(test_file, "complex_if", config_parser)
    func.decompile()
    print str(func)


if __name__ == '__main__':
    main()
