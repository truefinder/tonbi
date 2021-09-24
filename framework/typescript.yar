/* typescript vulnerable code auditing rules */ 

rule   xss : typescript
{
    strings : 
        $xss1 = ".send("
        $xss2 = /Mustache\.escape.*=/
        $xss3 = /Handlebars\.compile.*noEscape/
        $xss4 = /markdownIt\(.*html.*true/
        $xss5 = /marked\.setOptions\(.*sanitize.*false/
        $xss6 = /Renderer\(.*sanitize.*false/

     condition: 
        any of them 

}

rule   sql_injection : typescript
{
    strings : 
        $sql1 = /db\.query\(/ 
        $sql2 = /\.query\(.*\+/
     condition: 
        any of them 

}
rule  sql_injection2 : typescript 
{
    strings : 
        
        $sql1 = "raw" nocase 
        $sql2 = "query" nocase 
        $sql3 = "sql" nocase
        $sql4 = "fmt" nocase 
        $sql5 = "stmt" nocase 
        $sql6 = "statement" nocase 
        $param = /.*=.*%s/ nocase 
        
    condition : 
       1 of ($sql*) and $param 
}



rule   xxe : typescript
{
    strings : 
        $xxe1 = /libxmljs\.parseXmlString.*noent.*true/
     condition: 
        any of them 

}

rule   cmd_injection: typescript
{
    strings : 
        $cmd1 = ".exec("
        $cmd2 = ".execSync("
        $cmd3 = ".spawn("
        $cmd4 = ".spanSync("
        $cmd5 = ".execFile("
        $cmd6 = ".execFileSync("
     condition: 
        any of them 

}

rule   code_injection : typescript
{
    strings : 
        $code1 = "eval("
        $code2 = "Function(" 
     condition : 
        any of them 
}

rule   directory : typescript
{
    strings : 
        $dir1 = ".readFileSync("
     condition: 
        any of them 

}

rule   crypto : typescript
{
    strings : 
        $crypto1 = /crypto\.createHash\(.*sha1/ 
        $crypto2 = /crypto\.createCipheriv.*AES-128-/ 
     condition: 
        any of them 

}

rule    dns : typescript
{
    strings : 
        $dns1 = /dnsPrefetchControl\(.*allow.*true/ 
     condition: 
        any of them 

}
