
import re
'''
class myplugin :
    def init(self):
        # firstly loaded 
    def audit(self, line, lines, output):
        # called by every line 
    def finish(self)
        # please clear all resource 

class AuditItem:
	output = ""
	lines = ""
	line = ""
	i = 0 
	filename = "" 
'''

class myplugin:
    danger_php_functions = [
        "passthru\\(", "exec\\(", "shell_exec\\(", "phpinfo\\(", "popen\\(", "system\\("
        ]
    
    def init(self):
        print("dangerphp init")

    def audit(self,audititem):
        #print("match")
        for key in self.danger_php_functions : 
            match = re.search(key, audititem.line)
            if match : 
                vulnerability  = "==============================================\n"
                vulnerability += "dangerous php function : " + key + "\n"
                vulnerability += "filename : " + audititem.filename + "\n"
                vulnerability += "==============================================\n"
                vulnerability += audititem.lines 
                
                audititem.output.list.append(vulnerability)
                     
    def finish(self):
        print("dangerphp finish")

