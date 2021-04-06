import re
import yara 

DEFAULT_YARA_RULE = "./plugin/go/go_danger_functions.rule"

class MyPlugin:
    
    rules = ""
    def init(self):
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
            vulnerability += "filename : " + audititem.filename + "\n"
            vulnerability += "dangerous go function : " + match[0].rule + "\n"
            length, variable, m_string = match[0].strings[0]
            vulnerability += "dangerous matches : "  + str(m_string,'utf-8') + "\n"
            vulnerability += "==============================================\n"
            vulnerability += audititem.lines 
            audititem.output.list.append(vulnerability)
                    
    def finish(self):
        print("go finish")

