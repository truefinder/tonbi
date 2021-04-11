/* dangerous functions */ 
include "sql.yar" 
include "sh.yar" 

/* dangerous functions */ 


rule cmd_excute_python3_shellspawn : python 
{
    strings:
        $cmd1 = /run\(.*shell=True/
        $cmd2 = /Popen\(.*shell=True/
        $cmd3 = /call\(.*shell=True/
        $cmd4 = /check_call\(.*shell=True/
        $cmd5 = /check_output\(.*shell=True/ 
        $cmd6 = /^system\(/
         
    condition:
        any of them 

}

rule cmd_excute_python3_nospawn  : python 
{
    strings:
        // subprocess 
        $cmd1 = /subprocess\.(run|Popen|call|check_call|check_output)\(/
        
        // os.spawn 
        $cmd2 = /os\.spawn.*\(/
       
        // os.exec 
        $cmd3 = /os\.exec.*\(/

        // commands 
        $cmd4 = /commands\.get.*\(/

        $cmd5 = /os\.(popen|startfile)\(/
      
    condition: 
        any of them 
}

rule cmd_excute_python2
{
    strings:
        $cmd1 = /os\.popen[2-4]\(/
      
    condition:
        any of them 
}

rule file_temper
{
    strings: 
        $file1 = ".NamedTemporaryFile("
        $file2 = /^tempfile.mktemp\(/
        $file3 = "umask(0)"
        $file4 = /^chmod\(/
        $file5 = /^lchmod\(/
        $file6 = /^fchmod\(/
        $file7 = /^chown\(/
        $file8 = /^rename\(/
        $file9 = /^remove\(/
        $file10 = ".extractall("
        $file11 = /^link\(/
        $file12 = /^unlink\(/
    condition : 
        any of them 
}

rule code_injection  : python 
{
    strings : 
        $eval1 = /^eval\(/ 
       
    condition : 
        any of them 

}


rule sql_injection1 : python 
{
    strings : 
        $sql1 = ".query("
        $sql2 = "cursor.execute("

    condition : 
        any of them 
}


rule crypto  : python 
{
    strings : 
        $crypt1 = /AES\.new\(.*AES\.(MODE_ECB|MODE_ECB)/
    condition : 
        any of them 
}

rule jwt  : python 
{
    strings:
        $jwt1 = /jwt\.decode\(.*false/ nocase 
        $jwt2 = "jwt.process_jwt("
    condition:
        any of them 
}


rule ldap : python 
{
    strings :
        $ldap1 = /connect.*bind.*root/ 
    condition:
        any of them 
}

rule ssl_method  : python 
{
    strings : 
        $ssl1 = /ssl.*context.*SSLv3/
    condition : 
        any of them 
}


rule xss2  : python 
{
    strings : 
        $auto = /Environment.*autoescape.*False/ nocase 
    condition:
        any of them 
}