$currentdb = "$($PWD.Path)\ls.db"
$bakdb = "$($PWD.Path)\ls.db.bak"
$tmpdb = "$($PWD.Path)\ls.tmp.db"

Write-Output "[*] Backing up database"
if (Test-Path -Path $currentdb)
{
    Copy-Item $currentdb $tmpdb
    Move-Item $currentdb $bakdb
}

Write-Output "[*] Downloading files"
$db = (New-Object System.Net.WebClient).Downloadstring('https://raw.githubusercontent.com/Shellntel/luckystrike/dev/db.sql')
$ls = (New-Object System.Net.WebClient).Downloadstring('https://raw.githubusercontent.com/Shellntel/luckystrike/dev/luckystrike.ps1')

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
    Invoke-SqliteQuery -SQLiteConnection $dbConnNew -Query $db

    $payloads = Invoke-SqliteQuery -SQLiteConnection $dbConnCurrent -Query "SELECT * FROM PAYLOADS"
    $templates = Invoke-SqliteQuery -SQLiteConnection $dbConnCurrent -Query "SELECT * FROM TEMPLATES"

    foreach ($template in $templates)
    {
        $params = @{'name' = $template.Name; 'doctype' = $template.DocType; 'text' = $template.TemplateText}
        $query = "INSERT INTO TEMPLATES (NAME, DOCTYPE, TEMPLATETEXT) VALUES (@name, @doctype, @text)"
        Invoke-SqliteQuery -SQLiteConnection $dbConnNew -Query $query -SqlParameters $params
    }

    foreach ($p in $payloads)
    {
        $params = @{'name' = $p.Name; 'desc' = $p.Description; 'tip' = $p.TargetIP; 'tport' = $p.TargetPort; 'type' = $p.PayloadType; 'text' = $p.PayloadText }
        $query = "INSERT INTO PAYLOADS (NAME, DESCRIPTION, TARGETIP, TARGETPORT, PAYLOADTYPE, PAYLOADTEXT) VALUES (@name, @desc, @tip, @tport, @type, @text)"
        Invoke-SqliteQuery -SQLiteConnection $dbConnNew -Query $query -SqlParameters $params
    }
}
catch [System.Exception]
{
    $dbConnCurrent.Close()
    $dbConnCurrent.Dispose()
    $dbConnNew.Close()
    $dbConnNew.Dispose()
    Write-Output "[!] Error occurred. Restoring database."
    throw
    Remove-Item $tmpdb -Force -ErrorAction Continue
    Remove-Item $currentdb -Force -ErrorAction Continue
    Rename-Item $bakdb $currentdb
    exit
}
finally
{
    $dbConnCurrent.Close()
    $dbConnCurrent.Dispose()
    $dbConnNew.Close()
    $dbConnNew.Dispose()
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
}

Write-Output "[*] Done!"