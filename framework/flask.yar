/* flask vulnerable code auditing rules */ 

rule xss : flask 
{
    strings : 
        $xss1 = /\.add\(.* Content-Type/
        $xss2 = "render_template_string("
        $xss3 = /render_template\(\./
        $xss4 = "flask.Markup(" 
        $xss5 = /jinja2\.Template.*render\(/
        $xss6 = /{{.*\|.*safe.*}}/
        $xss7 = /{%.*autoescape.*false.*%}/ 
        $xss8 = /<.*={{.*}}.*>/

    condition : 
        any of them 
}

rule code_injection : flask 
{
    strings : 
        $code1 = "exec("
        $code2 = /yml\.load\(.*yaml\.Loader/
        $code3 = "pickle.load("
    condition:
        any of them 
}


rule redirect : flask 
{
    strings : 
        $redir = "HttpResponseRedirect("
    condition:
        any of them 
}

rule sql_injection : flask 
{
    strings : 
        $sql1 = ".from_statement(" 
    condition : 
        any of them  
}

rule xpath_injection: flask 
{
    strings : 
        $xpath = "root.findall(" 
    condition : 
        any of them  
}

rule directory : flask
{
    strings:
        $dir1 = /send_file\(.*%s/ 
       
    condition:
        any of them 
}

