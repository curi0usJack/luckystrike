# luckystrike
A PowerShell based utility for the creation of malicious Office macro documents.

## Getting Started

1. Read this: http://www.shellntel.com/blog/2016/9/13/luckystrike-a-database-backed-evil-macro-generator
2. Make sure you are on a Win7-10 machine (32 or 64bit).
3. You must be running a current version of PowerShell (v5+).
4. You must have Microsoft Excel installed (I did my testing with 2013).
5. From an ADMINISTRATIVE PowerShell prompt, run the following command. A luckystrike folder will be created for you.
  1. `iex (new-object net.webclient).downloadstring('https://raw.githubusercontent.com/Shellntel/luckystrike/master/install.ps1')`
6. Run .\luckystrike\luckystrike.ps1 (lowpriv or admin. Doesn't matter).
7. Repeat step #1 when you have a question, or submit a github issue. :-)
