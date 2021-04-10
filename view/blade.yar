rule xss : blade 
{
    strings : 
        $xss1 = /{!!.*!!}/
    condition : 
        any of them 
}

