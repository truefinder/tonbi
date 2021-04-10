
rule xss1 : twig 
{
    strings :  
        $xss4 = /{{.*\|raw}}/
        $xss5 = /{%.*autoescape.*false.*%}/ nocase 
    condition: 
        any of them 
}