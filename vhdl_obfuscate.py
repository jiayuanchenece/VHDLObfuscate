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
					"when", "while", "with", "xnor", "xor", "x", "ieee", "std_logic_1164", "numeric_std", "behavioral",
					"std_logic", "unsigned", "signed", "std_logic_vector", "rising_edge"}

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

def generate_key_sub_dictionary(input_file_str):
	global cmd_options, salt
	global key_sub_dict, io_port_mapping

	input_file = open(input_file_str, 'r')

	key_sub_dict = {}
	io_port_mapping = []
	n=0
	within_io_port_mapping = True
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
		if line.lower().__contains__("architecture"):
			within_io_port_mapping = False

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
							hash_val = hashlib.sha256(bytes(word, 'UTF-8') + bytes(salt, 'UTF-8')).hexdigest()
							key_sub_dict[word] = "s_" + hash_val[:int(int(hash_val[0:2], 16)/4) + 10]
							if within_io_port_mapping:
								io_port_mapping.append(word)

							if cmd_options.debug:
								print("Found new word: {}, hash: {}".format(word, key_sub_dict[word]))
				word=""


	if cmd_options.debug:
		print("IO Ports: {}".format(io_port_mapping))

	input_file.close()

def substitue_key_for_hashes(input_file_str, output_file_str):
	global cmd_options, salt
	global key_sub_dict

	input_file = open(input_file_str, 'r')
	output_file = open(output_file_str, "w")

	n=0
	while True:
		n += 1
		line = input_file.readline()
		if line == '':
			break
		if len(line) >= 2:
			if line[:2] == "--":
				continue

		word=""
		in_str=False
		for c in line:
			if c == "\"":
				if not in_str:
					if key_sub_dict.__contains__(word):
						output_file.write(key_sub_dict[word])
					else:
						output_file.write(word)
				output_file.write(c)
				in_str = not in_str
				word=""
				continue
			if in_str:
				output_file.write(c)
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
					if key_sub_dict.__contains__(word):
						output_file.write(key_sub_dict[word])
					else:
						output_file.write(word)
				output_file.write(c)

				word=""

	input_file.close()
	output_file.close()

def remove_all_comments(input_file_str, output_file_str):
	global cmd_options, salt
	global key_sub_dict

	input_file = open(input_file_str, "r")
	output_file = open(output_file_str, "w")

	while True:
		line = input_file.readline()
		if line == '':
			break
		if len(line) >= 2:
			if line[:2] == "--":
				continue

		if line.__contains__("--"):
			comment_index = line.index("--")
			line = line[:comment_index]
			line += "\n"

		output_file.write(line)

	input_file.close()
	output_file.close()

def move_non_process_blocks_to_end(input_file_str, output_file_str):
	global cmd_options, salt
	global key_sub_dict

	input_file = open(input_file_str, "r")
	output_file = open(output_file_str, "w")

	non_proc_data=""

	after_begin=False
	in_process_block=False
	while True:
		line = input_file.readline()
		if line == '':
			break
		if len(line) >= 2:
			if line[:2] == "--":
				continue

		if line.lower().__contains__("begin"):
			after_begin = True
			output_file.write(line)
			continue

		if after_begin:
			if line.lower().__contains__("behavioral"):
				output_file.write(non_proc_data)
				output_file.write("\n")
				output_file.write(line)
				break
			if line.__contains__("process"):
				in_process_block = not in_process_block
				if not in_process_block:
					output_file.write(line)
					continue
			if in_process_block:
				output_file.write(line)
				continue

			non_proc_data += line
		else:
			output_file.write(line)

	input_file.close()
	output_file.close()

def swap_process_blocks(input_file_str, output_file_str):
	global cmd_options, salt
	global key_sub_dict

	num_process_blocks, line_start_indexes, line_stop_indexes = get_num_of_process_blocks(input_file_str)
	proc_block_order = get_process_block_ordering(salt, num_process_blocks)

	input_file = open(input_file_str, "r")
	output_file = open(output_file_str, "w")
	process_block=0
	in_process_block=False
	while True:
		line = input_file.readline()
		if line == '':
			break
		if len(line) >= 2:
			if line[:2] == "--":
				continue

		if line.__contains__("process"):
			if not in_process_block:
				swap_process_block_start = line_start_indexes[proc_block_order[process_block]]
				swap_process_block_stop = line_stop_indexes[proc_block_order[process_block]]
				input_file2 = open(input_file_str, 'r')
				i = 1
				while i < swap_process_block_start:
					input_file2.readline()
					i += 1
				while i <= swap_process_block_stop:
					output_file.write(input_file2.readline())
					i += 1
				input_file2.close()
				process_block += 1

			in_process_block = not in_process_block

		elif not in_process_block:
			output_file.write(line)

	input_file.close()
	output_file.close()

def get_process_block_ordering(salt, num_process_blocks):

	order = [""]*num_process_blocks

	i = 0
	xor_c = 0
	ordering_hash = hashlib.sha512(bytes(salt, 'UTF-8')).hexdigest()
	ordering_hash += hashlib.sha512(bytes(salt[::-1], 'UTF-8')).hexdigest()
	ordering_hash += hashlib.sha512(bytes(salt+salt[::-1], 'UTF-8')).hexdigest()
	ordering_hash += hashlib.sha512(bytes(salt[::-1]+salt, 'UTF-8')).hexdigest()
	for c in ordering_hash:
		xor_c += ord(c)
		if xor_c >= num_process_blocks:
			xor_c %= num_process_blocks
		if order.__contains__(xor_c) == False:
			order[i] = xor_c
			i += 1
		if i >= num_process_blocks:
			break

	if i < num_process_blocks:
		raise ValueError("Unable to create process block ordering (max={}) from salt: {}".format(num_process_blocks, ordering_hash))

	if cmd_options.debug:
		print("Generated process block ordering: {}".format(order))

	return order

def get_num_of_process_blocks(input_file_str):
	global cmd_options, salt
	global key_sub_dict

	input_file = open(input_file_str, "r")

	num_process_blocks=0
	line_start_indexes=[]
	line_stop_indexes=[]
	in_process_block=False
	line_num=0
	while True:
		line = input_file.readline()
		if line == '':
			break
		if len(line) >= 2:
			if line[:2] == "--":
				continue
		line_num+=1

		word=""
		for c in line:
			if len(word) < 7:
				word += c
				continue
			else:
				if word == "process":
					num_process_blocks += 1
					if in_process_block:
						line_stop_indexes.append(line_num)
					else:
						line_start_indexes.append(line_num)

					in_process_block = not in_process_block

				word = word[1:7]
				word += c

	if cmd_options.debug:
		print("Found number of process blocks: {}".format(int(num_process_blocks/2)))
		print("Found start indexes: {}".format(line_start_indexes))
		print("Found stop indexes: {}".format(line_stop_indexes))

	input_file.close()

	return int(num_process_blocks/2), line_start_indexes, line_stop_indexes

def merge_process_blocks(input_file_str, output_file_str):
	global cmd_options, salt
	global key_sub_dict

	input_file = open(input_file_str, "r")
	output_file = open(output_file_str, "w")

	merge_hash = hashlib.sha512(bytes("hailhydra", 'UTF-8') + bytes(salt, 'UTF-8')).hexdigest()

	if cmd_options.debug:
		print("Merge hash: {}".format(merge_hash))

	i=0
	after_begin=False
	in_process_block=False
	while True:
		line = input_file.readline()
		if line == '':
			break
		if len(line) >= 2:
			if line[:2] == "--":
				continue
		if line.lower().__contains__("begin"):
			after_begin = True
			output_file.write(line)
			continue

		if after_begin:
			if line.lower().__contains__("behavioral"):
				output_file.write("\n")
				output_file.write(line)
				break
			if not in_process_block:
				if line.lower().__contains__("process"):
					process_trigger = line.lower().replace("process", "")
					process_trigger = process_trigger.lower().replace("(", "")
					process_trigger = process_trigger.lower().replace(")", "")
					process_trigger = process_trigger.lower().replace("\t", "")
					in_process_block = True
					output_file.write(line)
					continue
				output_file.write(line)
			if in_process_block:
				if line.lower().__contains__("end process"):	
					in_process_block = False
					if int(merge_hash[i], 16) >= 7: 
						if cmd_options.debug:
							print("Merging")
						line = input_file.readline()
						if line.lower().__contains__("process"):
							process_trigger_next = line.lower().replace("process", "")
							process_trigger_next = process_trigger_next.lower().replace("(", "")
							process_trigger_next = process_trigger_next.lower().replace(")", "")
							process_trigger_next = process_trigger_next.lower().replace("\t", "")
							if process_trigger == process_trigger_next:
								while True:
									if line.lower().__contains__("begin"):
										line = line.lower().replace("begin", "")
										output_file.write(line)
										break
									line = input_file.readline()
								in_process_block = True # We are now in a process block
							else:
								if cmd_options.debug:
									print("Merging failed {} != {}, line={}".format(process_trigger, process_trigger_next, line))
								output_file.write("\tend process;\n")
								output_file.write(line)
								continue
						else:
							output_file.write("\tend process;\n")
							output_file.write(line)
							continue
					else:
						output_file.write(line)
					
					i += 1
					if i >= 512:
						i = 0
				else:
					output_file.write(line)
		else:
			output_file.write(line)

	input_file.close()
	output_file.close()

def obfusticate_key_words(input_file_str, output_file_str):
	global cmd_options, salt
	global key_sub_dict

	input_file = open(input_file_str, "r")
	output_file = open(output_file_str, "w")

	keyword_hash = hashlib.sha512(bytes("r.stallman", 'UTF-8') + bytes(salt, 'UTF-8')).hexdigest()

	i=0
	after_begin=False
	while True:
		line = input_file.readline()
		if line == '':
			break
		if len(line) >= 2:
			if line[:2] == "--":
				continue

		if line.lower().__contains__("begin"):
			after_begin = True
			output_file.write(line)
			continue

		if after_begin:
			if line.lower().__contains__("behavioral"):
				output_file.write("\n")
				output_file.write(line)
				break

			if line.lower().__contains__("process"):
				if not line.lower().__contains__("end"):
					process_trigger = line.lower().replace("process", "")
					process_trigger = process_trigger.replace("begin", "")
					process_trigger = process_trigger.replace("(", "")
					process_trigger = process_trigger.replace(")", "")
					process_trigger = process_trigger.replace("\n", "")
					process_trigger = process_trigger.replace("\t", "")
					process_trigger = process_trigger.replace(" ", "")
			
			if line.lower().__contains__("rising_edge"):
				if int(keyword_hash[i], 16) >= 7:
					if cmd_options.debug:
						print("Replacing rising_edge")
					output_file.write("\t\tif "+process_trigger+"'event and "+process_trigger+"='1' then\n")
				else:
					output_file.write(line)

				i += 1
				if i >= 512:
					i = 0
			else:
				output_file.write(line)
		else:
			output_file.write(line)


def remove_whitespace(input_file_str, output_file_str):
	global cmd_options, salt
	global key_sub_dict

	input_file = open(input_file_str, "r")
	output_file = open(output_file_str, "w")

	file_contents = input_file.read()
	prev_char = ''
	num_chars = 0
	for c in file_contents:
		if c == '\n':
			if prev_char != ' ':
				output_file.write(' ')
				prev_char = ' '
				num_chars += 1
		elif c == '\r':
			if prev_char != ' ':
				output_file.write(' ')
				prev_char = ' '
				num_chars += 1
		elif c == '\t':
			if prev_char != ' ':
				output_file.write(' ')
				prev_char = ' '
				num_chars += 1
		elif c == ' ':
			if prev_char != ' ':
				output_file.write(' ')
				prev_char = ' '
				num_chars += 1
		else:
			output_file.write(c)
			prev_char = c
			num_chars += 1

		if num_chars > 200:
			if c == ';':
				output_file.write('\n')
				num_chars = 0

	input_file.close()
	output_file.close()

def generate_encapsulation_file():
	global io_port_mapping, key_sub_dict
	global cmd_options, input_file_name, salt

	input_file = open(input_file_name, "r")
	output_file = open(input_file_name[:-4]+"_encap.vhd", "w")

	while True:
		line = input_file.readline()
		if line == '':
			break
		if len(line) >= 2:
			if line[:2] == "--":
				continue

		output_file.write(line)
		if line.lower().__contains__("architecture"):
			output_file.write("\n")
			break

	start_print = False
	input_file2 = open(input_file_name[:-4]+"_pass1.vhd", "r")
	while True:
		line = input_file2.readline()
		if line == '':
			break
		if len(line) >= 2:
			if line[:2] == "--":
				continue

		if line.lower().__contains__("entity"):
			line = line.lower().replace("entity", "component")
			start_print = True
		if line.lower().__contains__("end"):
			output_file.write("end component;\n")
			break
		if start_print:
			output_file.write(line)

	output_file.write("\n")
	output_file.write("begin\n")
	output_file.write("\n")

	start_print = False
	input_file2.seek(0)
	n=0
	while True:
		line = input_file2.readline()
		if line == '':
			break
		if len(line) >= 2:
			if line[:2] == "--":
				continue

		if line.lower().__contains__("entity"):
			line = line.lower().replace("entity", "inst : ")
			line = line.lower().replace("is", "")
			output_file.write(line)
			start_print = True
			continue
		if line.lower().__contains__("end"):
			output_file.write(");\n")
			break
		line = line.lower().replace("port", "port map")

		line_is_only_blank = True
		for c in line.lower():
			if c == '\t':
				continue
			if c == ' ':
				continue
			if c == '\n':
				continue
			line_is_only_blank = False
			break
		if line_is_only_blank:
			continue

		try:
			if n != 0:
				new_line = ",\n"
			else:
				new_line = ""
			index_of_colon = line.index(":")
			new_line += line[:index_of_colon]
			new_line += " => "
			new_line += io_port_mapping[n+1]
			n += 1
			if start_print:
				output_file.write(new_line)
		except Exception:
			if start_print:
				output_file.write(line)

	output_file.write("\nend Behavioral;")

	input_file.close()
	input_file2.close()
	output_file.close()

if __name__ == '__main__':
	handle_command_line_options()
	generate_key_sub_dictionary(input_file_name)
	substitue_key_for_hashes(input_file_name, input_file_name[:-4]+"_pass0.vhd")
	remove_all_comments(input_file_name[:-4]+"_pass0.vhd", input_file_name[:-4]+"_pass1.vhd")
	move_non_process_blocks_to_end(input_file_name[:-4]+"_pass1.vhd", input_file_name[:-4]+"_pass2.vhd")
	swap_process_blocks(input_file_name[:-4]+"_pass2.vhd", input_file_name[:-4]+"_pass3.vhd")
	merge_process_blocks(input_file_name[:-4]+"_pass3.vhd", input_file_name[:-4]+"_pass4.vhd")
	obfusticate_key_words(input_file_name[:-4]+"_pass4.vhd", input_file_name[:-4]+"_pass5.vhd")
	remove_whitespace(input_file_name[:-4]+"_pass5.vhd", input_file_name[:-4]+"_pass6.vhd")
	generate_encapsulation_file()