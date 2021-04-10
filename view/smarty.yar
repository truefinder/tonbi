rule xss_config : smarty 
{
    strings : 
        $conf1 = /$smarty->escape_html.*=.*false/ nocase 
        $conf2 = /$smarty->default_modifiers.*array.*\'\'/
    condition:
        any of them 
}

rule xss1 : smarty2 
{
    strings : 
        $xss4 = /{.*\|smarty:nodefaults/
    condition: 
        any of them 
}

rule xss2 : smarty3 
{
    strings : 
        $xss6 = /{.*nofilter}/
    condition: 
        any of them 
}
