
/* django vulnerable code auditing rules */ 

rule redirect : django
{
    strings:
        $redir1 = "redirect("
    condition:
        any of them 
}

rule xss : django
{
    strings:
        $xss1 = /__setitem__\(.*Content-Type/
        $xss2 = "mark_safe("
        $xss3 = "SafeString("
        $xss4 = /filter\(.*is_safe=True/ nocase 
        $xss5 = "__html__" 
        $xss6 = "@html_safe" 
        $xss7 = "html_safe(" 
        $xss8 = "HttpResponse(" 

        $xss9 = /{{.*\|.*safeseq.*}}/
        $xss10 = /{{.*\|.*safe.*}}/
        $xss11 = /{%.*autoescape.*off.*%}/ nocase 
        $xss12 = /<.*={{.*}}.*>/

        $xss13 = /{'autoescape'.*|.*False}/ nocase 
       

    condition:
       any of them  
}

rule sql_injection : django 
{
    strings : 
        $sql1 = "cursor.execute("
    condition:
        any of them 
}