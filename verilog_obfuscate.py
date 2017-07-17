from optparse import OptionParser
import hashlib
import sys
import os

reserved_words = {"always", "and", "assign", "automatic",
				 "begin", "buf", "bufif0","bufif1",
				 "case", "casex", "casez", "cell", "cmos", "config",
				 "deassign", "default", "defparam", "design", "disable",
				 "edge", "else", "end", "endcase", "endconfig", "endfunction", "endgenerate", "endmodule", "endprimitive", "endspecify","endtable","endtask","event",
				 "for", "force", "forever", "fork", "function", "generate", "genvar", "highz0","highz1",
				 "if", "ifnone","incdir","include","initial","inout","input","instance","integer",
				 "join", "large", "liblist","library","localparam","macromodule","medium","module","nand","negedge","nmos",
				 "nor", "noshowcancelled", "not", "notif0","notif1","or","output","parameter","pmos","posedge","primitive",
				 "pull0","pull1","pulldown","pullup","pulsestyle_onevent","pulsestyle_ondetect","remos","real","realtime",
				 "reg","release","repeat","rnmos","rpmos","rtran","rtranif0","rtranif1","scalared","showcancelled","signed",
				 "small","specify","specparam","strong0","strong1","supply0","supply1","table","task","time","tran","tranif0",
				 "tranif1","tri","tri0","tri1","triand","trior","trireg","unsigned","use", "vectored", "wait","wand","weak0",
				 "weak1","while","wire","wor","xnor","xor",

				 "`include", "`define", "`undef", "`ifdef", "`elsif", "`else", "`endif", "`ifndef", "`timescale", "`celldefine", "`endcelldefine", "`default_nettype",
				 "`resetall", "`line", "`unconnected_drive", "`unconnected_drive", "`nounconnected_drive","`default_decay_time",
				 "`default_trireg_strength", "`delay_mode_distributed", "`delay_mode_path", "`delay_mode_unit", "`delay_mode_zero",

				 "Ts","Gs","Ms","ks","hs","das", "s", "ds", "cs", "ms", "us", "ns", "ps", "fs", "as",

				 "'b", "'h", "'d", "'o", "'sb", "'sh", "'sd", "'so"}

variable_name_allowed_chars = { "`" , "'","_"}

def handle_command_line_options():
	global cmd_options, input_file_name, salt

	usage_str = "verilog_obfuscate [-dc] input_file salt"

	parser = OptionParser()
	parser.add_option("-d", "--debug", action="store_true", dest="debug", default=False, help="enable debug messages")
	parser.add_option("-c", "--clean", action="store_true", dest="clean", default=False, help="cleanup files and exit")
	parser.usage = usage_str

	(cmd_options, args) = parser.parse_args()
	if cmd_options.debug:
		print("Enabling debug mode")
	if cmd_options.clean:
		print("Performing cleanup")
		clean(args[0])
		exit()

	if len(args) != 2:
		print("Usage: {}".format(usage_str))
		exit()
	else:
		input_file_name = args[0]
		salt = args[1]

def clean(input_file_str, i_max=0):
	
	i=0
	while True:
		file_to_remove=input_file_str[:-2]+"_pass"+str(i)+".v"
		if os.path.isfile(file_to_remove):
			os.remove(file_to_remove)
			i += 1
		else:
			return

		if i_max != 0:
			if i >= i_max:
				return

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
			if line[:2] == "//":
				if cmd_options.debug:
					print("Line number {} is comment line".format(n))
				continue
		if line.lower().__contains__("architecture"):
			within_io_port_mapping = False

		word=""
		redixFlag=False

		directiveFlag = False

		for c in line:

			if(c == "'") or (redixFlag == True):
				word = ""
				redixFlag = not redixFlag
				continue

			if(c == "*"):
				word = ""
				directiveFlag = not directiveFlag
				continue
			if(directiveFlag == True):
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
			if line[:2] == "//":
				continue

		if line.__contains__("//"):
			comment_index = line.index("//")
			line = line[:comment_index]
			line += "\n"

		output_file.write(line)

	input_file.close()
	output_file.close()

if __name__ == '__main__':
	handle_command_line_options()
	generate_key_sub_dictionary(input_file_name)
	substitue_key_for_hashes(input_file_name, input_file_name[:-2]+"_pass0.v")
	remove_all_comments(input_file_name[:-2]+"_pass0.v", input_file_name[:-2]+"_enc.v")
	clean(input_file_name)