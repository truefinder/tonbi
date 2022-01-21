/* rails vulerable code auditing rules */ 

rule file_disclosure : ruby
{
    strings : 
	$file1 = /config\.serve_static_assets.*true/  nocase 
    condition : 
        any of them 
}




