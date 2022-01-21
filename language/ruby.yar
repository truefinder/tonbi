/* dangerous functions */ 
include "sql.yar" 
include "sh.yar" 


rule cmd_excute : ruby
{
    strings:
	$cmd1 = /(system|exec|spawn|Process\.exec|Process\.spawn|Open3\.capture2|Open3\.capture2e|Open3\.capture3|Open3\.popen2|Open3\.popen2e|Open3\.popen3|IO\.popen|Gem::Util\.popen|PTY\.spaw)/
    condition:
        any of them 
}

rule file : ruby
{
    strings:
	$file1 = /(open).*=.*(\.|\+|%s)/
    condition:
        any of them 
}

rule eval: ruby
{
    strings : 
	$eval1 = /(class_eval|instance_eval)/
	$eval2 = /(eval\(|module_eval\()/
	$eval3 = /\.eval/
    condition : 
        any of them
}


rule file_disclosure : ruby
{
    strings : 
	$file1 = /config\.serve_static_assets.*true/  nocase 
    condition : 
        any of them 
}


rule hash : ruby
{
    strings :
        $hash1 = "Digest::MD5"
	$hash2 = "Digest::SHA1"
	$hash3 = /OpenSSL::HMAC\.hexdigest\(.*(sha1|SHA256)/

    condition : 
        any of them 
}


rule deserialization : ruby 
{
    strings :
	$deserial1 = /(Marshal|YAML|CSV).load\(/
	$deserial2 = ".object_load()"

    condition : 
        any of them 
}



