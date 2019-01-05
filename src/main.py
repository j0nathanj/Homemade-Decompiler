import os
from ConfigParser import SafeConfigParser

from AsmObjects.AsmFile import AsmElfFile
from AsmObjects.AsmFunction import AsmFunction

CONFIG_FILE_PATH = os.path.join(os.path.dirname(__file__), "config.ini")
'''
	TODO list: (22/12/2018)
		1) Handle pointers access
		2) Prettify the code

'''


def main():
	config_parser = SafeConfigParser()
	config_parser.read(CONFIG_FILE_PATH)

	test_file = AsmElfFile("calling_convention_chk")
	func = AsmFunction(test_file, "complex_if", config_parser)
	func.decompile()
	print str(func)


if __name__ == '__main__':
	main()
