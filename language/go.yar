rule sql_injection : go 
{
    strings : 
        $sql1 ="Raw("
        $sql2 ="Query("
        $sql3 ="QueryRow("
        $sql4 ="QueryContext(" 
        $sql5 ="QueryRow(" 
        $sql6 ="QueryRowContext(" 
        $sql7 ="Where("
        $sql8 ="First("
        $sql9 ="Select("
        $sql10 ="Distinct("
        $sql11 ="Pluck("
        $sql12 ="Group("
        $sql13 ="Having("
        $sql14 = "Exec("   
        $sql15 = "ExecContext(" 
        $op1 = /.*%s/ 
        $op2 = /.*\+/

    condition:
        1 of ($sql*) and ( $op1 or $op2 )
}

rule sql_injection2 : go 
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

rule sql_injection3 : go 
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

rule cmd_excute: go 
{
    strings : 
        $cmd1 = "exec.Command("
        $cmd2 = "exec.CommandContext("
        
    condition:
        any of them 
}

rule xss: go 
{
    strings :
        $xss1 = "URL.Query("
        $xss2 = "QueryUnescape("
        $xss3 = "WriteString("
        $xss4 = "Write("   
        $xss5 = "Println("   
    condition : 
        any of them
}

rule file_temper : go 
{
    strings : 
        $file1 = "Clean{"
        $file2 = "Open("
        $file3 = "Read("
        $file4 = "TempFile("
    condition : 
        any of them 
}

rule ssl : go 
{
    strings : 
        $ssl1 = "InsecureSkipVerify." 
    condition : 
        any of them 
}