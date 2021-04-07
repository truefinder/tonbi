/* codeigniter vulnerable code auditing rules */ 

rule xss : codeigniter config
{
    strings : 
        $xss1 = "$config['global_xss_filtering']"
        $false = /.*:.*false/ nocase 
    condition : 
        $xss1 and $false 

}

rule csrf : codeigniter config 
{
    strings : 
        $csrf1 = "$config['csrf_exclude_uris']"
        $csrf2 = "$config['csrf_regenerate']"
        $csrf3 = "$config['csrf_protection']"
        $false = /.*:.*false/ nocase 
    condition : 
        1 of ($csrf*) and $false 

}

rule directory : codeigniter
{
    strings : 
        $dir1 = "sanitize_filename("
        $false = /.*:.*false/ nocase 
    condition : 
        $dir1 and $false 

}

rule sql_injection : codeigniter
{
    strings : 
        $sql1 = /$this->db->(query|simple_query)\(/  
    condition : 
        any of them 

}

rule debug : codeigniter
{
    strings : 
        $dbg1 = "$db['default']['db_debug']"
        $true = /.*:.*true/ nocase 
    condition : 
        $dbg1  and $true 
        
}
