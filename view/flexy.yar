

rule xss2 : flexy 
{
    strings : 
        $xss7 = /{{.*:h}/}
    condition: 
        any of them 
}

