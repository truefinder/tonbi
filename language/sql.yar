
rule sql_injection_raw : sql
{
   strings : 
        
        $sql1 = /raw.*=.*(%s|\+)/ nocase 
        $sql2 = /query.*=.*(%s|\+)/ nocase 
        $sql3 = /sql.*=.*(%s|\+)/ nocase
        $sql5 = /stmt.*=.*(%s|\+)/ nocase 
        $sql6 = /statement.*=.*(%s|\+)/ nocase 
        $nosql1 =  /(urllib|request|url)/ nocase 
        
    condition : 
       1 of ($sql*) and not $nosql1 
}

rule sql_injection_var : sql 
{
    strings : 
        $sql1 = /select.*from.*(%s|\+)/ nocase 
        $sql2 = /update.*set.*(%s|\+)/ nocase
        $sql3 = /insert.*into.*(%s|\+)/ nocase 
        $sql4 = /delete.*from.*(%s|\+)/ nocase
        
    condition:
       any of them 
}

