#!/usr/bin/python3

from optparse import OptionParser
from optparse import OptionGroup
import os
import json 
import re
import importlib
import yara 
import os
import logging, sys

logging.basicConfig(stream=sys.stderr, level=logging.DEBUG)

#relative path
tonbi_dir = os.path.dirname(__file__)
platform_dir = os.path.join(tonbi_dir, 'platform')
language_dir = os.path.join(tonbi_dir, 'language')
view_dir = os.path.join(tonbi_dir, 'view')
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

# debug_print() will be deprecated 
def debug_print(str):
	if config.debug_mode : 
		print('DEBUG: ', str) 


class Config : 
	debug_mode = False 
	config_file =""
	source_directory = ""
	platform_name = ""
	view_name = "" 
	language = ""
	head_count = DEFAULT_LINES 
	tail_count = DEFAULT_LINES 
	output = ""
	plugins = []
	ignore_files = [] 
	ignore_dirs = [] 
	exclude = [] 


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
	view_rules = "" 

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


# create logger
logger = logging.getLogger('tonbi')
logger.setLevel(logging.WARNING)
ch = logging.StreamHandler()
ch.setLevel(logging.DEBUG)
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
ch.setFormatter(formatter)
logger.addHandler(ch)
#logger.debug('debug message')


def prepare_output():
	if(config.output):
		if( os.path.exists( config.output)):
			os.remove(config.output)


def check_config():
	print("check configuration...")
	


def load_config():
	print("load config setting ")
	with open ( config.config_file ) as f:
		config_dic = json.load(f)
		logger.debug('config_dic(json): %r', config_dic) 
		
		# TODO set config dic 
		config.source_directory = config_dic["source_directory"] 
		config.platform_name = config_dic["platform_name"] 
		config.language = config_dic["language"]
		config.head_count = config_dic["head_count"] 
		config.tail_count = config_dic["tail_count"] 
		config.ignore_files = config_dic["ignore_files"]

		if(config_dic["view_name"]) :
			config.view_name = config_dic["view_name"] 

		if(config_dic["output"]):
			config.output = config_dic["output"] 
		
		if(config_dic["plugins"]):
			config.plugins = config_dic["plugins"] 
		
		if(config_dic["ignore_dirs"]):
			config.ignore_dirs = config_dic["ignore_dirs"]

		if(config_dic["exclude"]):
			config.exclude = config_dic["exclude"]

	logger.debug("config(class): %s", config)
	
        
def kbdb_load_platform() :
	print ("load platform ..." )
	filename = "./platform/" + config.platform_name + "/" + KBDB_FILE
	with open( filename  ) as f : 
		kbdb.dic = json.load(f) 
		logger.debug(kbdb.dic) 

  
def yara_load_platform() :
	print ("load platform ..." )
	rulefile = config.platform_name + "." + YARA_EXT
	filename = os.path.join(platform_dir, rulefile)
	with open( filename  ) as f : 
		myyara.platform_rules = yara.compile(filepath=filename)
		logger.debug('platform_rules: %r', myyara.platform_rules) 

def yara_load_language() :
	print ("load language ..." )
	rulefile = config.language + "." + YARA_EXT
	filename = os.path.join(language_dir, rulefile)
	with open( filename  ) as f : 
		myyara.language_rules = yara.compile(filepath=filename)
		logger.debug('language_rules: %r', myyara.language_rules) 

def yara_load_view() :
	if config.view_name == "" :
		return 
		
	print ("load view ..." )
	rulefile = config.view_name + "." + YARA_EXT
	filename = os.path.join(view_dir, rulefile)
	with open( filename  ) as f : 
		myyara.view_rules = yara.compile(filepath=filename)
		logger.debug('view_rules: %r', myyara.view_rules) 


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

	
	#exclude some vulnerabilities 
	for vulname in config.exclude:
		if vulname == match.rule:
			logger.debug("EXCLUDE %s, %s", vulname, str(config.exclude))
			return 
	
	length, variable, m_string = match.strings[0]
	pattern = str(m_string, 'utf-8')

	vulnerability = ""
	vulnerability += "==================================================\n" 
	vulnerability += "filename : " + filename  + "\n" 
	vulnerability += "vulnerability : " +  match.rule + "\n"  
	vulnerability += "matches : " + pattern + "\n" 
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
	logger.debug("search word = %s", str(keyword_count) ) 
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
					logger.debug("json escape : %s", item["keyword"])
					#if any(x in line for x in item["keyword"]):
					#if(sequence_find(line, item["keyword"])):
					key = item["keyword"]
					#key = key.replace('\\\\','\\')
					#logger.debug("json escaped: " + key)
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
	print("[%s][%s][%s] : " %(config.language, config.platform_name, config.view_name) + filename ) 
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

				#2. language  yara search
				matches = myyara.language_rules.match(data=line)
				if matches:
					lines = scrap_lines(line, datafile,i)
					yara_add_vulnerability(filename, lines, matches) 
					lines = ""

				#3. view  yara search
				if config.view_name != "" :
					matches = myyara.view_rules.match(data=line)
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
				logger.debug('full filename : %s', full_filename) 
				#kbdb_audit(full_filename)
				yara_audit(full_filename)


	
def main():
	usage = "usage: %prog [options] args"
	parser = OptionParser(usage)

	parser.add_option("-c", "--config", dest="config", help="set configuration file  ex) -c config.json")
	parser.add_option("-d", "--directory", dest="directory", help="set source directory ex ) -d /src")
	parser.add_option("-l", "--language", dest="language", help="set language  ex) -l php")
	parser.add_option("-p", "--platform", dest="platform",  help="set platform  ex) -p laravel ")
	parser.add_option("-v", "--view", dest="view", help="set render or view ex) -v smarty")

	group = OptionGroup(parser, "Output Options")
	
	group.add_option("-o", "--output", dest="output", help="save result into file ex) -o output.txt")
	group.add_option("-e", "--exclude", dest="exclude", action='append', default=[], help="exclude some vulnerability ex) -e 'sql_injection'" ) 
	group.add_option("--head",  type="int", dest="head", help="show above lines ex) --head 5")
	group.add_option("--tail",  type="int", dest="tail", help="show below lines ex) --tail 5")
	parser.add_option_group(group)

	group = OptionGroup(parser, "Debug Options")
	group.add_option("-D", "--debug", dest="debug", help="debug mode output of dbg_print", action="store_true")
	parser.add_option_group(group)
	

	(options, args) = parser.parse_args()

	if( options.debug ):
		config.debug_mode = True
		logger.setLevel(logging.DEBUG)

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

		if (options.view):
				config.view_name = options.view 

		if (options.output):
				config.output = options.output 


		if (options.head):
				config.head_count = options.head 

		if (options.tail):
				config.tail_count = options.tail 

		if(options.exclude):
				logger.debug("EXCLUDE %s", str(options.exclude))
				config.exclude = options.exclude 



	check_config() 

	#kbdb_load_platform()
	yara_load_platform() 

	yara_load_language()

	yara_load_view() 

	load_plugin() 

	prepare_output()

	start_audit() 

	print_output()

	unload_plugin() 

if __name__ == "__main__":
    main()
