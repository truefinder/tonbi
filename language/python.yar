rule cmd_excute_python3_shellspawn : python 
{
    strings:
        $cmd1 = "run("
        $cmd2 = "Popen("
        $cmd3 = "call("
        $cmd4 = "check_call("
        $cmd5 = "check_output(" 

        $opt1 = "shell=True" nocase 
        $sys1 = "system("
         
    condition:
        ((1 of ($cmd*)) and $opt1 ) or 
        $sys1 

}

rule cmd_excute_python3_nospawn  : python 
{
    strings:
        // subprocess 
        $cmd1 = "run("
        $cmd2 = "Popen("
        $cmd3 = "call("
        $cmd4 = "check_call("
        $cmd5 = "check_output("

        // spawn 
        $cmd6 = "spawnl("
        $cmd7 = "spawnle("
        $cmd8 = "spawnlp("
        $cmd9 = "spawnlpe("
        $cmd10 = "spawnv("
        $cmd11 = "spawnve("
        $cmd12 = "spawnvp("
        $cmd13 = "spawnvpe("

        // exec 
        $cmd14 = "popen("
        $cmd15 = "getstatusoutput("
        $cmd16 = "getoutput("
        $cmd17 = "startfile("
        $cmd18 = "execl("
        $cmd19 = "execle("
        $cmd20 = "execlp("
        $cmd21 = "execlpe("
        $cmd22 = "execv("
        $cmd23 = "execve("
        $cmd24 = "execvp("
        $cmd25 = "execvpe("
    condition: 
        all of them 

}

rule cmd_excute_python2
{
    strings:
        $cmd1 = "popen2("
        $cmd2 = "popen3("
        $cmd3 = "popen4("      
         
    condition:
        any of them 
}

rule file_temper
{
    strings: 
        $file1 = ".NamedTemporaryFile("
        $file2 = "tempfile.mktemp()"
        $file3 = "umask(0)"
        $file4 = "chmod("
        $file5 = "lchmod("
        $file6 = "fchmod("
        $file7 = "chown("
        $file8 = "rename("
        $file9 = "remove("
        $file10 = "extractall("
        $file11 = "link("
        $file12 = "unlink("
    condition : 
        any of them 
}

rule code_injection  : python 
{
    strings : 
        $eval1 = "eval(" 
       
    condition : 
        any of them 

}


rule sql_injection1 : python 
{
    strings : 
        $sql1 = "query("
        $sql2 = "execute("

    condition : 
        any of them 
}

rule sql_injection2  : python 
{
    strings : 
        
        $sql1 = "raw" nocase 
        $sql2 = "query" nocase 
        $sql3 = "sql" nocase
        $sql4 = "fmt" nocase 
        $sql5 = "stmt" nocase 
        $sql6 = "statement" nocase 
        $param = /.*=.*%s/ nocase 
        
    condition : 
       1 of ($sql*) and $param 
}



rule sql_injection3  : python 
{
    strings : 
        $sql1 = /select.*from/ nocase 
        $sql2 = /update.*set/ nocase
        $sql3 = /insert.*into/ nocase 
        $sql4 = /delete.*from/ nocase
        $param = /.*(%s|\+)/ nocase 
    condition:
       1 of ($sql*) and $param 
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