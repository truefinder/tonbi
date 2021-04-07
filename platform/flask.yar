
rule xss : flask 
{
    strings : 
        $xss = /\.add\(.* Content-Type/
    condition : 
        any of them 
}

rule code_injection : flask 
{
    strings : 
        $code1 = "exec("
        $code2 = /yml\.load\(.*yaml\.Loader/
    condition:
        any of them 
}

rule flask1 
{
    strings:
        
        $fl2 = "HttpResponseRedirect("
        $fl3 = "pickle.load(" 
        $fl4 = "send_file(" 
        $fl5 = "root.findall(" 
    condition:
        any of them 
}
rule flask2 
{
    strings: 
        $fl1 = "yml.load(" 
        $opt1 = "yaml.Loader"
  
    condition:
        ($fl1 and $opt1 ) or  
        ($fl2 and $opt2 ) 

}
