from optparse import OptionParser
import sys

def handle_command_line_options():
	global cmd_options, input_file, salt

	usage_str = "vhdl_obfuscate [-d] input_file salt"

	parser = OptionParser()
	parser.add_option("-d", "--debug", action="store_true", dest="debug", default=False, help="enable debug messages")
	parser.usage = usage_str

	(cmd_options, args) = parser.parse_args()

	if len(args) != 2:
		print("Usage: {}".format(usage_str))
		exit()
	else:
		input_file = args[0]
		salt = args[1]

handle_command_line_options()
