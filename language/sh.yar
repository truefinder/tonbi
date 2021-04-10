/* shell command */ 
rule command_injection : shell
{
    strings : 
        $cmd1 = /(cmd|command|shell).*=.*(\.|\+|%s)/
    condition : 
        any of them 
        
}