/* gorilla vulnerable code auditing rules */ 

rule xss : gorilla 
{
    strings : 
        $xss1 = "text/template" 
    condition:
        any of them 

}

rule csrf : gorilla 
{
    strings :
        $csrf1 = "csrf.Protect(" 
    condition:
        any of them 

}

rule origin : gorilla 
{
    strings : 
        $orig1 = "AllowedOrigins" 
    condition:
        any of them 

}
