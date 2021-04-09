
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