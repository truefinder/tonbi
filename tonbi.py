from optparse import OptionParser
import os
import json 


DEFAULT_LINES = 3 
DEBUG = 0 

def debug_print(str):
	if DEBUG : 
		print(str) 

class Config :
	source_directory = ""
	platform_name = ""
	template_name = "" 
	head_count = 3 
	head_count = 3 

class Kbdb :
	dic = "" 

config = Config() 
kbdb = Kbdb() 

def check_config():
	print("check configuration") 

def load_platform() :
	print ("load platform ..." )
	filename = "./platform/" + config.platform_name + "/kbdb.json" 
	with open( filename ) as f : 
		kbdb.dic = json.load(f) 
		debug_print(kbdb.dic) 

def show_vulnerability(filename, line, item):
	print( "================================================") 
	print(" vulnerability : " + item["vulnerability"] ) 
	print(" description : " + item["description"] ) 
	print(" reference : " + item["reference"] ) 
	print(" filename : " + filename ) 
	print( "================================================") 
	print( line ) 



def load_plugin() : 
	print ("load plugin ..." )

def start_audit() : 
	print("start audit ...") 
	search( config.source_directory) 

def audit( filename) :
	print("audit file with kbdb") 
	with open( filename ) as f :
		datafile = f.readlines()
		for line in datafile :
			for item in kbdb.dic["items"] : 
				debug_print(item["keyword"])
				if any(x in line for x in item["keyword"]):
					debug_print("found!" )
					#print(item)
					show_vulnerability(filename, line, item) 
					return True 

def search(dirname):
	for (path, dir, files) in os.walk(dirname):
		for filename in files:
			full_filename = path + "/" + filename 
			debug_print(full_filename) 
			audit(full_filename)

	
def main():
	usage = "usage: %prog [options] arg"
	parser = OptionParser(usage)

	parser.add_option("-d", "--directory", dest="directory", metavar="DIR", help="web application source code directory")
	parser.add_option("-p", "--platform", dest="platform", metavar="PLATFORM", help="platform name ex) laravel ")
	parser.add_option("-t", "--template", dest="template", metavar="TEMPLATE", help="template name ex) twitty")
	parser.add_option("--head",  type="int", dest="head", help="show previous <num> lines")
	parser.add_option("--tail",  type="int", dest="tail", help="show below <num> lines")

	(options, args) = parser.parse_args()

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
	else :
		parser.error("app template name not defined")  

	if (options.head):
		config.head_count = options.head 

	if (options.tail):
		config.tail_count = options.tail 

	check_config() 

	load_platform() 

	load_plugin() 

	start_audit() 

if __name__ == "__main__":
    main()
