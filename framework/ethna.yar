
rule xss : ethna
{
    strings:    
        $xss2 = "setAppNE("
    condition:
       any of them  
}

