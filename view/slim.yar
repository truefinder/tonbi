rule xss_config : slim 
{
	strings : 
		$conf1 = /config\.active_support.escape_html_entities_in_json.*=.*false/ nocase 
	condition:
		any of them 
}


rule xss_erb: slim 
{
	strings : 
		$erb = /ERB\.new\(/
	condition: 
		any of them 
}

rule xss_inline : slim 
{
	strings : 
		$inline1 = /render inline.*\:/
		$inline2 = /render text.*\:/
	condition: 
		any of them 
}

rule xss_unescaped : slim 
{
	strings : 
		$unescape1 = /\.html_safe/
		$unescape2 = /content_tag.*\:/
		$unescape3 = /raw \@/
	condition:
		any of them 
}

rule xss_template : slim 
{
	strings : 
		$template1 = /<%=.*\.html_safe/
		$template2 = /<%=.*content_tag.*:/
		$template3 = /<%=.*raw.*\@/
		$template4 = /<%==.*%>/
	condition:
		any of them 
}

rule xss_js : slim 
{
	strings : 
		$js1 = /<script>.*<%=.*%><\/script>/
	condition:
		any of them 

}


