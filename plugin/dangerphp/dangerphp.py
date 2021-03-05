
import re
'''
# please write class MyPlugin 
# define three functions init, audit, finish

class MyPlugin :
    def init(self):
        # firstly loaded 
    def audit(self, line, lines, output):
        # called by every line 
    def finish(self)
        # please clear all resources when finished 
''' 

class MyPlugin:
    danger_php_functions = [
        "passthru\\(", "exec\\(", "shell_exec\\(", "phpinfo\\(", "popen\\(", "system\\("
        ]
    
    def init(self):
        print("dangerphp init")


    def audit(self,audititem):
        #print("match")

        '''
        audititem (class AuditItem) parametered to your audit()     
            .line <= (string) target string 
            .i <= (int) target line number 
            .filename <= (string) target filename  
            .lines <= (string) use this reference lines when you find out something  
            .output <= (Class Output) for your result, use output.list.append("your string") 
            
        '''
        
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

