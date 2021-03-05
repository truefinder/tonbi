from optparse import OptionParser
import os
import json 
import re
import importlib

#default 3+3, 6lines will show you
DEFAULT_LINES = 3 
#basic ignore image files 
DEFAULT_IGNORE = [ "jpg", "png", "jpeg", "ico", "gif", "tif" , "tiff", "bmp" ] 
#default knowledge based database file 
KBDB_FILE = "kbdb.json"

def debug_print(str):
	if config.debug_mode : 
		print( str) 

class Config : 
	debug_mode = 0 
	config_file =""
	source_directory = ""
	platform_name = ""
	template_name = "" 
	head_count = DEFAULT_LINES 
	tail_count = DEFAULT_LINES 
	output = ""
	plugins = []
	ignore_files = [] 

class Plugin:
	dic = dict()
	objs = dict() 

class Kbdb :
	dic = "" 


class Output :
	list = [] 


config = Config() 
kbdb = Kbdb() 
plugin = Plugin() 
output = Output()

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
		config.head_count = config_dic["head_count"] 
		config.tail_count = config_dic["tail_count"] 
		config.ignore_files = config_dic["ignore_files"]

		if(config_dic["template_name"]) :
			config.template_name = config_dic["template_name"] 

		if(config_dic["output"]):
			config.output = (config_dic["output"] )

	debug_print("config_dic")
	
        
def load_platform() :
	print ("load platform ..." )
	filename = "./platform/" + config.platform_name + "/" + KBDB_FILE
	with open( filename  ) as f : 
		kbdb.dic = json.load(f) 
		debug_print(kbdb.dic) 

def add_vulnerability(filename, lines, item, match):
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
	print ("load plugin ..." )
	
	# python 3.5~ 
	for p in config.plugins :
		plugin_filename = "./plugin/" + p + ".py"
		plugin.dic[p] = import_path(plugin_filename)
	
		# myplugin = plugin.dic["myplugin"].myplugin()
		# myplugin.init() 
		plugin.objs[p] = plugin.dic[p].myplugin()
		plugin.objs[p].init() 

		

def start_audit() : 
	print("start audit ...") 
	search( config.source_directory) 

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
	

def audit( filename) :
	print("audit file with kbdb : " + filename ) 
	with open( filename, errors='replace' ) as f :
		i = 0
		lines = ""
		datafile = f.readlines()
		for line in datafile :
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

					
					add_vulnerability(filename, lines, item, match) 
					lines = ""
			i = i+1 

def search(dirname):
	for (path, dir, files) in os.walk(dirname):
		for filename in files:
			full_filename = path + "/" + filename 
			(base, ext ) = os.path.splitext( full_filename ) 
			if(config.ignore_files):
				exclude_exts = config.ignore_files 
			else:
				exclude_exts = DEFAULT_IGNORE

			if any(x in ext for x in exclude_exts):
				continue 
			else : # start audit 
				debug_print(full_filename) 
				audit(full_filename)

	
def main():
	usage = "usage: %prog [options] arg"
	parser = OptionParser(usage)

	parser.add_option("-c", "--config", dest="config", metavar="CONFIG", help="use config file config.json")
	parser.add_option("-d", "--directory", dest="directory", metavar="DIR", help="source code directory")
	parser.add_option("-p", "--platform", dest="platform", metavar="PLATFORM", help="platform name ex) laravel ")
	parser.add_option("-t", "--template", dest="template", metavar="TEMPLATE", help="template name ex) twig")
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

		if (options.template):
				config.template_name = options.template 

		if (options.output):
				config.output = options.output 


		if (options.head):
				config.head_count = options.head 

		if (options.tail):
				config.tail_count = options.tail 

	check_config() 

	load_platform() 

	load_plugin() 

	prepare_output()

	start_audit() 

	print_output()


if __name__ == "__main__":
    main()
