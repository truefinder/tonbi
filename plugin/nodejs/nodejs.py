import re
import yara 

DEFAULT_YARA_RULE = "./plugin/nodejs/nodejs_danger_functions.rule"

class MyPlugin:
    
    rules = ""
    def init(self):
        print("nodejs plugin init")
        self.rules = yara.compile(filepath=DEFAULT_YARA_RULE)
            

    def audit(self,audititem):

        '''
        audititem (class AuditItem) parametered to your audit()     
            .line <= (string) target string 
            .i <= (int) target line number 
            .filename <= (string) target filename  
            .lines <= (string) use this reference lines when you find out something  
            .output <= (Class Output) for your result, use output.list.append("your string") 
            
        '''
        match = self.rules.match(data=audititem.line)
        if match :
            vulnerability  = "==============================================\n"
            vulnerability += "dangerous nodejs function : " + match[0].rule + "\n"
            vulnerability += "filename : " + audititem.filename + "\n"
            vulnerability += "==============================================\n"
            vulnerability += audititem.lines 
                
            audititem.output.list.append(vulnerability)
                    
    def finish(self):
        print("nodejs plugin finish")

