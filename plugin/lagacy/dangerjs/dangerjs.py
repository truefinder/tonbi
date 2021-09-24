import re

class MyPlugin:
    danger_go_functions = []
    regex_keys = ""

    def init(self):
        print("dangerjs init")
        filename = "./plugin/dangerjs/dangerjs.db"
        with open( filename  ) as f : 
            self.regex_keys = f.readlines()
            f.close() 
            

    def audit(self,audititem):

        '''
        audititem (class AuditItem) parametered to your audit()     
            .line <= (string) target string 
            .i <= (int) target line number 
            .filename <= (string) target filename  
            .lines <= (string) use this reference lines when you find out something  
            .output <= (Class Output) for your result, use output.list.append("your string") 
            
        '''
        for item in self.regex_keys : 
            key = item.strip() 
            
            if not (key):
                print("error no key...")
                exit 

            match = re.search( key, audititem.line)
            if match : 
                vulnerability  = "==============================================\n"
                vulnerability += "dangerous js function : " + key + "\n"
                vulnerability += "filename : " + audititem.filename + "\n"
                vulnerability += "==============================================\n"
                vulnerability += audititem.lines 
                
                audititem.output.list.append(vulnerability)
                break; 
                     
    def finish(self):
        print("dangerjs finish")

