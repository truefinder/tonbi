
rule sql_injection_raw : sql
{
   strings : 
        
        $sql1 = "raw" nocase 
        $sql2 = "query" nocase 
        $sql3 = "sql" nocase
        $sql5 = "stmt" nocase 
        $sql6 = "statement" nocase 
        $param = /.*=.*%s/ nocase 
        
    condition : 
       1 of ($sql*) and $param 
}

rule sql_injection_var : sql 
{
    strings : 
        $sql1 = /select.*from/ nocase 
        $sql2 = /update.*set/ nocase
        $sql3 = /insert.*into/ nocase 
        $sql4 = /delete.*from/ nocase
        $param = /.*(%s|\+)/ nocase 
    condition:
       1 of ($sql*) and $param 
}

