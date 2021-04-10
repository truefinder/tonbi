/* dangerous functions */ 
include "sql.yar" 


rule cmd_excute : php
{
    strings:
        $cmd1 = "exec("
        $cmd2 = "passthru("
        $cmd3 = "popen("
        $cmd4 = "proc_close("
        $cmd5 = "proc_open("
        $cmd6 = "proc_get_status("
        $cmd7 = "proc_nice("
        $cmd8 = "proc_terminate("
        $cmd9 = "shell_exec("
        $cmd10 = "system("
        $cmd11 = "exec("
        $cmd12 = "passthru("
        $cmd13 = "popen("
        $cmd14 = "shell_exec("
        $cmd15 = "system("
    condition:
        any of them 
}

rule sql_injection1: php
{
    strings : 
        $sql1 = "mysql_query("
        $sql2 = "mysql_db_query(" 
       
    condition : 
        any of them
}


rule xss : php
{
    strings : 
        $xss1 = "echo("
        $xss2 = "eval(" 
    condition : 
        any of them 
}


rule hash : php
{
    strings :
        $hash1 = "hash("
        $hash2 = "hash_init("
        $hash3 = "hash_update("

    condition : 
        any of them 
}
