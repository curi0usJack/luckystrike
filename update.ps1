$currentdb = "$($PWD.Path)\ls.db"
$bakdb = "$($PWD.Path)\ls.db.bak"
$tmpdb = "$($PWD.Path)\ls.tmp.db"

# Give luckystrike a sec to close & release handles.
Write-Output "[*] Sleeping 3 seconds"
Start-Sleep -Seconds 3

# Run garbage collection to clean up sqlite file handles
Write-Output "[*] Collecting sqlite garbage..."
[System.GC]::Collect()
[System.GC]::WaitForPendingFinalizers()

Write-Output "[*] Backing up database"
if (Test-Path -Path $currentdb)
{
    Copy-Item $currentdb $tmpdb
    Move-Item $currentdb $bakdb
}

Write-Output "[*] Downloading files"

$db = (New-Object System.Net.WebClient).Downloadstring('https://raw.githubusercontent.com/curi0usJack/luckystrike/master/db.sql')
$ls = (New-Object System.Net.WebClient).Downloadstring('https://raw.githubusercontent.com/curi0usJack/luckystrike/master/luckystrike.ps1')

if ($db -eq $null -or $ls -eq $null)
{
    Write-Output "[*] Unable to download files. Aborting"
    exit
}

Write-Output "[*] Importing PSSQLite"
Import-Module 'PSSQLite'

Write-Output "[*] Migrating database"

# tmp == current. current == new. Don't ask.
$dbConnCurrent = New-SQLiteConnection -DataSource $tmpdb
$dbConnNew = New-SQLiteConnection -DataSource $currentdb
try 
{
    Invoke-SqliteQuery -SQLiteConnection $dbConnNew -Query $db | Out-Null

    $payloads = Invoke-SqliteQuery -SQLiteConnection $dbConnCurrent -Query "SELECT * FROM PAYLOADS"
    $templates = Invoke-SqliteQuery -SQLiteConnection $dbConnCurrent -Query "SELECT * FROM TEMPLATES"

    foreach ($template in $templates)
    {
        $params = @{'name' = $template.Name; 'doctype' = $template.DocType; 'text' = $template.TemplateText}
        $query = "INSERT INTO TEMPLATES (NAME, DOCTYPE, TEMPLATETEXT) VALUES (@name, @doctype, @text)"
        Invoke-SqliteQuery -SQLiteConnection $dbConnNew -Query $query -SqlParameters $params | Out-Null
    }

    foreach ($p in $payloads)
    {
        $params = @{'name' = $p.Name; 'desc' = $p.Description; 'tip' = $p.TargetIP; 'tport' = $p.TargetPort; 'numblocks' = $p.NumBlocks; 'type' = $p.PayloadType; 'text' = $p.PayloadText }
        $query = "INSERT INTO PAYLOADS (NAME, DESCRIPTION, TARGETIP, TARGETPORT, PAYLOADTYPE, NUMBLOCKS, PAYLOADTEXT) VALUES (@name, @desc, @tip, @tport, @type, @numblocks, @text)"
        Invoke-SqliteQuery -SQLiteConnection $dbConnNew -Query $query -SqlParameters $params | Out-Null
    }
}
catch
{
    if ($dbConnCurrent -ne $null)
    {
		$dbConnCurrent.Dispose()
	}
	if ($dbConnNew -ne $null)
    {
		$dbConnNew.Dispose()
	}
    Write-Output "[!] Error occurred. Restoring database."
    throw
    Remove-Item $tmpdb -Force -ErrorAction Continue
    Remove-Item $currentdb -Force -ErrorAction Continue
    Rename-Item $bakdb $currentdb
	Read-Host "Please take a screenshot of this and log an issue on github. Press any key to exit."
    exit
}
finally
{
	if ($dbConnCurrent -ne $null)
    {
		$dbConnCurrent.Dispose()
	}
	if ($dbConnNew -ne $null)
    {
		$dbConnNew.Dispose()
	}
}

try 
{
    Write-Output "[*] Updating luckystrike.ps1"
    Remove-Item "$($PWD.Path)\luckystrike.ps1"
    $ls | Out-File "$($PWD.Path)\luckystrike.ps1"
}
catch [System.Exception] {
    Write-Output "Error saving new version of luckystrike.ps1"
    throw
	Read-Host "Press any key to exit."
    exit
}

try 
{
    Write-Output "[*] Cleaning up"
    Remove-Item $tmpdb
    Remove-Item $bakdb
}
catch [System.Exception] 
{
    Write-Output "[!] Unable to remove current db file: $currentdb. Remove this file manually and copy ls.db.new to ls.db, then you're good to go."
    throw
	Read-Host "Press any key to exit."
}

Write-Output "[*] Done!"
Write-Output "`nUpdates in 2.0 - Word support, Invoke-Obfuscation support, new attack methods. See blog post here for new features https://curi0usjack.blogspot.com/2017/07/luckystrike-20-is-here.html"
Read-Host "`nPress any key to continue. If errors, grab a screenshot and submit an issue with the debug log on github, otherwise run the new version of luckystrike.ps1. Happy hacking! --@curi0usJack"
