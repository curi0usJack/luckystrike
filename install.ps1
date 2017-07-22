#Requires -Version 5 -RunAsAdministrator
<#
.SYNOPSIS
    The installation script that prepares the luckystrike database & copies down luckystrike from git.

.DESCRIPTION
    This script basically just does the following:

        1) Creates .\luckystrike\ 
        2) Attempts to install the PSSQLite module if you don't already have it (requires admin rights).
        3) Builds the luckystrike database file (ls.db).
        4) Copies down luckystrike.ps1 from Github.

.NOTES
	Version:		1.1

    Contributors: 	Jason Lang 		@curi0usJack

    Help Last Modified: 09/16/2016  
#>
$requiredmodules = @('PSSQlite')
$installfolder = "$($PWD.Path)\luckystrike"
$dbpath = "$installfolder\ls.db"

Write-Output "### LUCKYSTRIKE INSTALLATION ROUTINE ###"
Write-Output "[*] Installing\Importing Dependencies.."
# Install dependencies (if necessary)
foreach ($moduleName in $requiredmodules)
{
    if (!(Get-Module -ListAvailable -Name $moduleName)) 
    {
        try
        {
            Write-Output "[*] Module ($moduleName) not found, attempting to install and import."

            #Simple alternative, if you have PowerShell v5, or the PowerShellGet module:
            Install-Module $moduleName -ErrorAction Stop
            Import-Module $moduleName -ErrorAction Stop
        }
        catch
        {
            Write-Error "[!] Module install/import error! Attempt to manually install $moduleName"
            exit
        }
    }
    else
    {
        Import-Module $moduleName -ErrorAction Stop
    }
}

# Create the install folder
if (!(Test-Path -Path $installfolder))
{
    Write-Output "[*] Creating $installfolder"
    New-Item $installfolder -ItemType Directory | Out-Null
}

# Create database if it doesn't exit
if (!(Test-Path -Path $dbpath))
{
    Write-Output "[*] Downloading db.sql"
    $init = (New-Object System.Net.WebClient).Downloadstring('https://raw.githubusercontent.com/curi0usJack/luckystrike/master/db.sql')

    Write-Output "[*] Creating & initializing database: $dbpath"
    $dbConnection = New-SQLiteConnection -DataSource $dbpath 
    try 
    {
        
        Invoke-SqliteQuery -SQLiteConnection $dbConnection -Query $init | Out-Null
    }
    catch [System.Exception] 
    {
        throw  
        exit  
    }
    finally
    {
        $dbConnection.Dispose()
    }
}
else 
{
    Write-Output "[*] Detected database at $dbpath."
}

Write-Output "[*] Downloading luckystrike.ps1 into $installfolder"
(New-Object System.Net.Webclient).DownloadFile('https://raw.githubusercontent.com/curi0usJack/luckystrike/master/luckystrike.ps1', "$installfolder\luckystrike.ps1")

Write-Output "[*] Done!"
