
import re
'''
# please write class MyPlugin 
# define three functions init, audit, finish

class MyPlugin :
    def init(self):
        # firstly loaded 
    def audit(self, audititem):
        # called by every line 
    def finish(self)
        # please clear all resources when finished 
''' 

class MyPlugin:
    danger_php_functions = [
        "passthru\\(", "exec\\(", "shell_exec\\(", "phpinfo\\(", "popen\\(", "system\\("
        ]
    
    regex_keys = ""

    def init(self):
        print("dangerphp init")
        filename = "./plugin/dangerphp/dangerphp.db"
        with open( filename  ) as f : 
            self.regex_keys = f.readlines()
            f.close() 
            #print(self.regex_keys)
            #input()
            

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
        for key in self.regex_keys : 
            if not (key):
                print("error no key...")
                exit 

            match = re.search( key, audititem.line)
            if match : 
                vulnerability  = "==============================================\n"
                vulnerability += "dangerous php function : " + key + "\n"
                vulnerability += "filename : " + audititem.filename + "\n"
                vulnerability += "==============================================\n"
                vulnerability += audititem.lines 
                
                audititem.output.list.append(vulnerability)
                break; 
                     
    def finish(self):
        print("dangerphp finish")

