#!/usr/bin/python3

from optparse import OptionParser
import os
import json 
import re
import importlib
import yara 

import os

#relative path
tonbi_dir = os.path.dirname(__file__)
platform_dir = os.path.join(tonbi_dir, 'platform')
language_dir = os.path.join(tonbi_dir, 'language')
plugin_dir = os.path.join(tonbi_dir, 'plugin')

#default 3+3, 6lines will show you
DEFAULT_LINES = 3 
#one line can't limit 500 ascii characters
LIMIT_LINE_LEN = 1024 
#basic ignore image files 
DEFAULT_IGNORE = [ "jpg", "png", "jpeg", "ico", "gif", "tif" , "tiff", "bmp" ] 
#default knowledge based database file 
KBDB_FILE = "kbdb.json"
YARA_EXT = "yar"

class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'


def debug_print(str):
	if config.debug_mode : 
		print( str) 


class Config : 
	debug_mode = 0 
	config_file =""
	source_directory = ""
	platform_name = ""
	template_name = "" 
	language = ""
	head_count = DEFAULT_LINES 
	tail_count = DEFAULT_LINES 
	output = ""
	plugins = []
	ignore_files = [] 
	ignore_dirs = [] 


class Plugin:
	dic = dict()
	objs = dict() 
'''
class MyPlugin :
    def init(self):
        # firstly loaded 
    def audit(self, line, lines, output):
        # called by every line 
    def finish(self)
        # please clear all resource 
'''


class Kbdb :
	dic = "" 

class Yara : 
	platform_rules = "" 
	language_rules = ""

class Output :
	list = [] 

class AuditItem:
	output = ""
	lines = ""
	line = ""
	i = 0 
	filename = "" 


config = Config() 
kbdb = Kbdb() 
plugin = Plugin() 
output = Output()
myyara = Yara() 


def prepare_output():
	if(config.output):
		if( os.path.exists( config.output)):
			os.remove(config.output)


def check_config():
    print("check configuration") 


def load_config():
	print("load config setting ")
	with open ( config.config_file ) as f:
		config_dic = json.load(f)
		debug_print(config_dic) 
		# TODO set config dic 
		config.source_directory = config_dic["source_directory"] 
		config.platform_name = config_dic["platform_name"] 
		config.language = config_dic["language"]
		config.head_count = config_dic["head_count"] 
		config.tail_count = config_dic["tail_count"] 
		config.ignore_files = config_dic["ignore_files"]

		if(config_dic["template_name"]) :
			config.template_name = config_dic["template_name"] 

		if(config_dic["output"]):
			config.output = config_dic["output"] 
		
		if(config_dic["plugins"]):
			config.plugins = config_dic["plugins"] 
		
		if(config_dic["ignore_dirs"]):
			config.ignore_dirs = config_dic["ignore_dirs"]

	debug_print("config_dic")
	
        
def kbdb_load_platform() :
	print ("load platform ..." )
	filename = "./platform/" + config.platform_name + "/" + KBDB_FILE
	with open( filename  ) as f : 
		kbdb.dic = json.load(f) 
		debug_print(kbdb.dic) 

  
def yara_load_platform() :
	print ("load platform ..." )
	rulefile = config.platform_name + "." + YARA_EXT
	filename = os.path.join(platform_dir, rulefile)
	with open( filename  ) as f : 
		myyara.platform_rules = yara.compile(filepath=filename)
		debug_print(myyara.platform_rules) 

def yara_load_language() :
	print ("load language ..." )
	rulefile = config.language + "." + YARA_EXT
	filename = os.path.join(language_dir, rulefile)
	with open( filename  ) as f : 
		myyara.language_rules = yara.compile(filepath=filename)
		debug_print(myyara.language_rules) 


def kbdb_add_vulnerability(filename, lines, item, match):
	vulnerability = ""
	vulnerability += "==================================================\n" 
	vulnerability += "vulnerability : " + item["vulnerability"] + "\n"  
	vulnerability += "description : " + item["description"]  + "\n" 
	if (config.debug_mode):
		vulnerability += "vulnerability : " + match[0] + "\n"  
	vulnerability += "reference : " + item["reference"]  + "\n" 
	vulnerability += "filename : " + filename  + "\n" 
	vulnerability += "=================================================\n" 
	vulnerability += lines + "\n"
	output.list.append(vulnerability)


def yara_add_vulnerability(filename, lines, matches):
	if (type(matches) is list ): # maches returns list  
		match = matches[0]
	else:
		match = matches 

	length, variable, m_string = match.strings[0]
	pattern = str(m_string, 'utf-8')

	vulnerability = ""
	vulnerability += "==================================================\n" 
	vulnerability += "filename : " + filename  + "\n" 
	vulnerability += "vulnerability : " +  match.rule + "\n"  
	vulnerability += "matches : " + pattern + "\n" 
	if (config.debug_mode):
		vulnerability += "vulnerability : " + match.rule + "\n"  
	if match.tags: 
		vulnerability += "tag : " + match.tags[0] + "\n" 
	vulnerability += "=================================================\n" 
	vulnerability += lines + "\n"
	output.list.append(vulnerability)

def print_output():
	if ( config.output) : 
		with open(config.output, "a") as f : 
			for  vul in Output.list :
				f.write( vul) 
			f.close()	
	else:
		for vul in Output.list :
			print(vul) 
			

def import_path(path):
	#module_name = os.path.basename(path).replace('-', '_')
	module_name = os.path.basename(path)
	spec = importlib.util.spec_from_loader(
		module_name,
		importlib.machinery.SourceFileLoader(module_name, path)
	)
	module = importlib.util.module_from_spec(spec)
	spec.loader.exec_module(module)
	#sys.modules[module_name] = module
	return module


def load_plugin() : 
	print ("load plugins ..." )
	
	# python 3.5~ 
	if config.plugins : 
		for p in config.plugins :
			if p : 
				pluginfile = p + ".py"
				plugindir = os.path.join(plugin_dir, p)
				plugin_filename = os.path.join(plugindir, pluginfile)
				plugin.dic[p] = import_path(plugin_filename)
			
				# myplugin = plugin.dic["myplugin"].MyPlugin()
				# myplugin.init() 
				plugin.objs[p] = plugin.dic[p].MyPlugin() # class MyPlugin() 
				plugin.objs[p].init() # MyPlugin.init()		


def unload_plugin():
	if config.plugins : 
		for p in config.plugins :
			if p : 
				plugin.objs[p].finish() # MyPlugin.finish()	


def start_audit() : 
	print("start audit ...") 
	walk_around( config.source_directory) 


def sequence_find( line, keyword_array):
	n = 0
	found_count =0 
	keyword_count = len(keyword_array) 
	debug_print("search word = " + str(keyword_count) ) 
	for key in keyword_array : 
		n = line.find( key, n ) 
		if ( n == -1 ): # not found 
			return False 
		else : #found 
			found_count = found_count+1

	if ( keyword_count == found_count ):
			return True 
	else:
		return False 
	

def scrap_lines(line, datafile, i):
	lines =""
	head_n = i-config.head_count
	tail_n = i+config.tail_count+1

	if head_n > 0 :
		if tail_n < len(datafile) :
			j = head_n 
			for x in datafile[head_n:tail_n] : 
				lines += str(j) + ": " +  x 
				j =j +1 
		else :
			tail_n = len(datafile)
			j = head_n 
			for x in datafile[head_n:tail_n] : 
				lines += str(j) + ": " +  x 
				j =j +1
	else :
		head_n = 0 
		j = head_n 
		for x in datafile[head_n:tail_n] : 
			lines += str(j) + ": " +  x 
			j =j +1
		#lines += str(i) + ": " + line 
	
	return lines 


def kbdb_audit( filename) :
	print("audit file with kbdb : " + filename ) 
	try: 
		with open( filename, errors='replace' ) as f :
			i = 0
			lines = ""
			datafile = f.readlines()
			audititem = AuditItem() 
			audititem.output = output
			AuditItem.filename = filename 
			
			for line in datafile :
				#1. general platform kbdb search
				for item in kbdb.dic["items"] : 
					debug_print("json escape : " + item["keyword"])
					#if any(x in line for x in item["keyword"]):
					#if(sequence_find(line, item["keyword"])):
					key = item["keyword"]
					#key = key.replace('\\\\','\\')
					#debug_print("json escaped: " + key)
					match = re.search(key, line)
					if match:
						head_n = i-config.head_count
						tail_n = i+config.tail_count+1

						if ( head_n > 0 and tail_n < len(datafile) ):
							j = head_n 
							for x in datafile[head_n:tail_n] : 
								lines += str(j) + ": " + x
								j =j +1 
						else : 
							lines += str(i) + ": " + line 

						kabdb_add_vulnerability(filename, lines, item, match) 
						lines = ""
				#2. plugin search 
				for p in config.plugins :
					audititem.lines = scrap_lines(line, datafile,i)
					audititem.line = line 
					audititem.i = i 
					
					plugin.objs[p].audit(audititem) # MyPlugin.audit()	
					
				i = i+1 
	except IOError:
		print ("Could not read file:", filename)




def yara_audit( filename) :
	print("audit file with yara : " + filename ) 
	try: 
		with open( filename, errors='replace' ) as f :
			i = 0
			lines = ""
			datafile = f.readlines()
			audititem = AuditItem() 
			audititem.output = output
			AuditItem.filename = filename 
			
			for line in datafile :
				#0. give up when its length is over 500 characters cause cpu goes bust
				if (len(line) > LIMIT_LINE_LEN ):
					print("failed to analysis : one line is too long ... ")
					continue 
				
				#1. platform yara search
				matches = myyara.platform_rules.match(data=line)
				if matches:
					lines = scrap_lines(line, datafile,i)
					yara_add_vulnerability(filename, lines, matches) 
					lines = ""

				#1. language  yara search
				matches = myyara.language_rules.match(data=line)
				if matches:
					lines = scrap_lines(line, datafile,i)
					yara_add_vulnerability(filename, lines, matches) 
					lines = ""
				
				#3. plugin search 
				if config.plugins : 
					for p in config.plugins :
						if p : 
							audititem.lines = scrap_lines(line, datafile,i)
							audititem.line = line 
							audititem.i = i 
							
							plugin.objs[p].audit(audititem) # MyPlugin.audit()	
					
				i = i+1 
	except IOError:
		print ("Could not read file:", filename)





def walk_around(dirname):
	for (path, dirs, files) in os.walk(dirname):
		if (config.ignore_dirs):
			dirs[:] = [d for d in dirs if d not in config.ignore_dirs]

		for filename in files:
			full_filename = os.path.join(path, filename) 
			(base, ext ) = os.path.splitext( full_filename ) 
			if(config.ignore_files):
				exclude_exts = config.ignore_files 
			else:
				exclude_exts = DEFAULT_IGNORE

			if any(x in ext for x in exclude_exts):
				continue 
			else : # start audit 
				debug_print(full_filename) 
				#kbdb_audit(full_filename)
				yara_audit(full_filename)


	
def main():
	usage = "usage: %prog [options] arg"
	parser = OptionParser(usage)

	parser.add_option("-c", "--config", dest="config", metavar="CONFIG", help="use config file config.json")
	parser.add_option("-d", "--directory", dest="directory", metavar="DIR", help="source code directory")
	parser.add_option("-p", "--platform", dest="platform", metavar="PLATFORM", help="platform name ex) laravel ")
	parser.add_option("-t", "--template", dest="template", metavar="TEMPLATE", help="template name ex) twig")
	parser.add_option("-l", "--language", dest="language", metavar="LANGUAGE", help="language name ex) php")
	parser.add_option("--head",  type="int", dest="head", help="show previous <num> lines")
	parser.add_option("--tail",  type="int", dest="tail", help="show below <num> lines")
	parser.add_option("-D", "--debug", dest="debug", help="verbose mode", action="store_true")
	parser.add_option("-o",  "--output", dest="output", metavar="OUTPUT", help="save result into file")

	(options, args) = parser.parse_args()

	if( options.debug ):
 		config.debug_mode = True 

	if (options.config): 
		config.config_file = options.config 
		load_config()

	else : 
		if (options.directory):
				config.source_directory = options.directory 
		else:
				parser.error("app source directory not defined")

		if (options.platform):
				config.platform_name = options.platform 
		else :
				parser.error("app platform name not defined")  

		
		if (options.language):
				config.language = options.language 
		else :
				parser.error("app language name not defined")  

		if (options.template):
				config.template_name = options.template 

		if (options.output):
				config.output = options.output 


		if (options.head):
				config.head_count = options.head 

		if (options.tail):
				config.tail_count = options.tail 

	check_config() 

	#kbdb_load_platform()
	yara_load_platform() 

	yara_load_language()

	load_plugin() 

	prepare_output()

	start_audit() 

	print_output()

	unload_plugin() 

if __name__ == "__main__":
    main()
