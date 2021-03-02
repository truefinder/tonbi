from optparse import OptionParser
import os
import json 


DEFAULT_LINES = 3 
DEBUG = 0 
EXCLUDE_EXTS = [ "jpg", "png", "jpeg", "ico", "gif", "tif" , "tiff", "bmp" ] 

def debug_print(str):
	if DEBUG : 
		print( str) 

class Config :
	source_directory = ""
	platform_name = ""
	template_name = "" 
	head_count = DEFAULT_LINES 
	tail_count = DEFAULT_LINES 
	output = ""

class Kbdb :
	dic = "" 

config = Config() 
kbdb = Kbdb() 

def prepare_output():
	if(config.output):
		if( os.path.exists( config.output)):
			os.remove(config.output)


def check_config():
	print("check configuration") 

def load_platform() :
	print ("load platform ..." )
	filename = "./platform/" + config.platform_name + "/kbdb.json" 
	with open( filename  ) as f : 
		kbdb.dic = json.load(f) 
		debug_print(kbdb.dic) 

def show_vulnerability(filename, lines, item):
	vulnerability = ""
	vulnerability += "==================================================\n" 
	vulnerability += "vulnerability : " + item["vulnerability"] + "\n"  
	vulnerability += "description : " + item["description"]  + "\n" 
	vulnerability += "reference : " + item["reference"]  + "\n" 
	vulnerability += "filename : " + filename  + "\n" 
	vulnerability += "=================================================\n" 
	vulnerability += lines + "\n" 

	if ( config.output) : 
		with open(config.output, "a") as f : 
			f.write( vulnerability) 
			f.close()
	else:
		print(vulnerability) 


def load_plugin() : 
	print ("load plugin ..." )

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
				debug_print(item["keyword"])
				#if any(x in line for x in item["keyword"]):
				if(sequence_find(line, item["keyword"])):
					head_n = i-config.head_count
					tail_n = i+config.tail_count+1

					if ( head_n > 0 and tail_n < len(datafile) ):
						j = head_n 
						for x in datafile[head_n:tail_n] : 
							lines += str(j) + ": " + x
							j =j +1 
					else : 
						lines += str(i) + ": " + line 

					
					show_vulnerability(filename, lines, item) 
			i = i+1 

def search(dirname):
	for (path, dir, files) in os.walk(dirname):
		for filename in files:
			full_filename = path + "/" + filename 
			(base, ext ) = os.path.splitext( full_filename ) 
			if any(x in ext for x in EXCLUDE_EXTS):
				continue 
			else : # start audit 
				debug_print(full_filename) 
				audit(full_filename)

	
def main():
	usage = "usage: %prog [options] arg"
	parser = OptionParser(usage)

	parser.add_option("-d", "--directory", dest="directory", metavar="DIR", help="web application source code directory")
	parser.add_option("-p", "--platform", dest="platform", metavar="PLATFORM", help="platform name ex) laravel ")
	parser.add_option("-t", "--template", dest="template", metavar="TEMPLATE", help="template name ex) twig")
	parser.add_option("--head",  type="int", dest="head", help="show previous <num> lines")
	parser.add_option("--tail",  type="int", dest="tail", help="show below <num> lines")
	parser.add_option("-o",  "--output", dest="output", metavar="OUTPUT", help="save result into file")

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

if __name__ == "__main__":
    main()
