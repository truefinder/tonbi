from optparse import OptionParser
import os

DEFAULT_LINES = 3 

class Config :
	source_directory = ""
	platform_name = ""
	template_name = "" 
	head_count = 3 
	head_count = 3 
		
class Vitem : 
	def __init__ (self):
		pass

class Vkbdb :
	def __init__ (self):
		pass

config = Config() 

def check_config():
	print("check configuration") 

def load_platform() :
	print ("load platform ..." )

def load_plugin() : 
	print ("load plugin ..." )

def start_audit() : 
	print("start audit ...") 
	search( config.source_directory) 

def search(dirname):
	for (path, dir, files) in os.walk(dirname):
		for filename in files:
			full_filename = path + "/" + filename 
			print(full_filename) 

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
