/* dangerous functions */ 
include "sql.yar" 
include "sh.yar" 

rule cmd_excute : nodejs 
{
    strings:
        $cmd1 = "exec("
        $cmd2 = "execFile("
        $cmd3 = "openItem("
        $cmd4 = "openExternal("
        $cmd5 = "spawn(" 
        $cmd6 = "fork("

    condition:
        any of them 
}

rule file_temper: nodejs 
{
    strings: 
        $file1 = ".IncomingForm("
        $file2 = ".parse("
        $file3 = ".readFile("
        $file4 = ".appendFile("
        $file5 = ".writeFile("
        $file6 = ".open("
        $file7 = ".unlink("
        $file8 = ".rename("
        $file9 = ".createReadStream("
        $file10 = ".createServer("
        $file11 = ".createTransport("
        $file12 = ".sendMail("
    condition : 
        (any of them) and not ("JSON" and $file2)
}

rule sql_injection1_mysql : nodejs 
{
    strings : 
        $sql1 = "createConnection("
        $sql2 = "query("

    condition : 
        any of them 
}

rule sql_injection1_mongodb : nodejs 
{
    strings : 

        $sql1 = "connect("
        $sql2 = "createCollection("
        $sql3 = "collection(" 
        $sub1 = "aggregate("
        $sub2 = "find(" 
        $sub3 = "insert("
        $sub4 = "delete(" 
        $sub5 = "update(" 
        $sub6 = "drop(" 
       
    condition : 
        ($sql1 or $sql2 ) or 
        ($sql3 and 1 of ($sub*))        
}


rule js_excute : nodejs 
{
    strings : 
        $eval1 = "$eval(" 
        $eval2 = "setTimeout("
        $eval3 = "setInterval("
        $eval4 = "Function("
    condition : 
        any of them 

}
rule xss : nodejs 
{
    strings : 
       
        $eql = /.*=/
        $xss2 = "dangerouslySetInnerHTML"
        $xss3 = "trustAsHtml"
       

    condition : 
        1 of ($xss*) and $eql 
}

rule ssl : nodejs 
{
    strings : 
        $true = /.*:.*true/ nocase 
        $false = /.*:.*false/ nocase 
        $zero = /.*:.*0/ nocase 
        $ssl1 = "NODE_TLS_REJECT_UNAUTHORIZED"
        $ssl2 = "rejectUnauthorized"
        $ssl3 = "insecure"
        $ssl4 = "strictSSL"
        $ssl5 = "clientPemCrtSignedBySelfSignedRootCaBuffer"
    condition :
        ( $ssl1 and $zero ) or 
        ( ($ssl2 or $ssl4) and $false ) or 
        ( $ssl3 and $true ) or 
        ( $ssl5 ) 
}

rule ssi : nodejs 
{
    strings : 
        $qoute1 = /<%.*%>/
    condition : 
        $qoute1 
}

rule cookie : nodejs 
{
    strings :
        $cookie = /document.cookie.*=/
    condition : 
        $cookie 
}
