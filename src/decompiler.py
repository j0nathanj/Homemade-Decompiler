import os
from ConfigParser import SafeConfigParser

from AsmObjects.AsmFile import AsmElfFile
from AsmObjects.AsmFunction import AsmFunction
import argparse

CONFIG_FILE_PATH = os.path.join(os.path.dirname(__file__), "config.ini")


def parse_args():
	args_parser = argparse.ArgumentParser()
	args_parser.add_argument("input_file", help="File that contains the function to decompile")
	args_parser.add_argument("input_function", help="Function to decumpile")
	args_parser.add_argument("--output", "-o", default=None, help="Output file (defaults to stdout)")

	args = args_parser.parse_args()
	return args.input_file, args.input_function, args.output 


def main():
	input_file, input_function, output = parse_args()
	config_parser = SafeConfigParser()
	config_parser.read(CONFIG_FILE_PATH)

	test_file = AsmElfFile(input_file)
	func = AsmFunction(test_file, input_function, config_parser)
	func.decompile()
	if output:
		with open(output, "w") as f:
			f.write(str(func))
	else:
		print str(func)


if __name__ == '__main__':
	main()
