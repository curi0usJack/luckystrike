# luckystrike
A PowerShell based utility for the creation of malicious Office macro documents. To be used for pentesting or educational purposes only.

## Getting Started

1. Read this: http://www.shellntel.com/blog/2016/9/13/luckystrike-a-database-backed-evil-macro-generator.
1. Read the wiki!
2. Make sure you are on a Win7-10 machine (32 or 64bit).
3. You must be running a current version of PowerShell (v5+).
4. You must have Microsoft Excel installed (I did my testing with 2013).
5. From an ADMINISTRATIVE PowerShell prompt, run the following command. A luckystrike folder will be created for you.
  1. `iex (new-object net.webclient).downloadstring('https://git.io/v7kbp')`
6. Run .\luckystrike\luckystrike.ps1 (also as an administrator).

## If you have a problem

1. Run luckystrike with the -Debug switch. This will generate a debug .log file in the luckystrike directory.
1. Reproduce the issue
1. Take a screenshot of the error
1. Submit a github issue with the screenshot & debug log attached.
1. Be patient. I'm one guy. :-)
