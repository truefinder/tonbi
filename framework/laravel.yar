/* laravel vulnerable code audting rule */ 

rule xss : laravel 
{
    strings : 
        $xss1 = /{!!.*!!}/
    condition : 
        any of them 
}

rule sql_injection : laravel 
{
    strings : 
        $sql1 = "unprepared("
        $sql2 = "DB::raw("
        $sql3 = /DB::(select|insert|delete|update|statement)\(/
        $sql4 = /(fromRaw|whereRaw)\(/

    condition : 
        any of them 
}

rule  sql_injection2 : laravel 
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

rule cmd_injection : laravel 
{
    strings : 
        $cmd1 = /Artisan::(call|queue)\(/
        $cmd2 = /$this->(call|callSilently)\(/
    condition : 
        any of them 
}

rule upload : laravel 
{
    strings :
        $upload = /\'filename\'.*=>/  
    condition : 
        any of them 
}
