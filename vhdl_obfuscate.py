from optparse import OptionParser
import hashlib
import sys

reserved_words = { 	"access", "after", "alias", "all", "and", "architecture", "array", "assert", "attribute",
					"begin", "block", "body", "buffer", "bus", "case", "component", "configuration", "constant",
					"disconnect", "downto", "else", "elsif", "end", "entity", "exit", "file", "for", "function", 
					"generate", "generic", "group", "guarded", "if", "impure", "in", "inertial", "inout", "is", 
					"label", "library", "linkage", "literal", "loop", "map", "mod", "nand", "new", "next", "nor", 
					"not", "null", "of", "on", "open", "or", "others", "out", "package", "port", "postponed", 
					"procedure", "process", "pure", "range", "record", "register", "reject", "return", "rol", 
					"ror", "select", "severity", "signal", "shared", "sla",	 "sli", "sra", "srl", "subtype", 
					"then", "to", "transport", "type", "unaffected", "units", "until", "use", "variable", "wait", 
					"when", "while", "with", "xnor", "xor", "x"}

variable_name_allowed_chars = { "_" }

def handle_command_line_options():
	global cmd_options, input_file_name, salt

	usage_str = "vhdl_obfuscate [-d] input_file salt"

	parser = OptionParser()
	parser.add_option("-d", "--debug", action="store_true", dest="debug", default=False, help="enable debug messages")
	parser.usage = usage_str

	(cmd_options, args) = parser.parse_args()
	if cmd_options.debug:
		print("Enabling debug mode")

	if len(args) != 2:
		print("Usage: {}".format(usage_str))
		exit()
	else:
		input_file_name = args[0]
		salt = args[1]

def generate_key_sub_dictionary():
	global cmd_options, input_file_name, salt
	global key_sub_dict

	input_file = open(input_file_name, 'r')

	key_sub_dict = {}
	n=0
	while True:
		n += 1
		line = input_file.readline()
		if line == '':
			if cmd_options.debug:
				print("Reached EOF, number of lines: {}".format(n))
			break

		if len(line) >= 2:
			if line[:2] == "--":
				if cmd_options.debug:
					print("Line number {} is comment line".format(n))
				continue

		word=""
		in_str=False
		for c in line:
			if c == "\"":
				in_str = not in_str
				continue
			if in_str:
				continue

			if (c >= 'a') and (c <= 'z'):
				word += c
			elif (c >= 'A') and (c <= 'Z'):
				word += c
			elif variable_name_allowed_chars.__contains__(c):
				word += c
			elif (len(word) != 0) and (c >= '0') and (c <= '9'):
				word += c
			else:
				if len(word) != 0:
					if reserved_words.__contains__(word.lower()) == False:
						if key_sub_dict.__contains__(word) == False:
							key_sub_dict[word] = hashlib.sha256(bytes(word, 'UTF-8') + bytes(salt, 'UTF-8')).hexdigest()

							if cmd_options.debug:
								print("Found new word: {}, hash: {}".format(word, key_sub_dict[word]))
				word=""

handle_command_line_options()
generate_key_sub_dictionary()