# luckystrike
A PowerShell based utility for the creation of malicious Office macro documents. To be used for pentesting or educational purposes only.

### Requirements

1. Windows 7, 8 or 10 (32/64bit)
2. PowerShell version greater than 5.x (Check by running `$PSVersionTable.PSVersion`)
3. Microsoft Excel (tested with MSExcel 2013)

### Getting Started

1. Read this: [Luckystrike: An Evil Office Document Generator.](http://www.shellntel.com/blog/2016/9/13/luckystrike-a-database-backed-evil-macro-generator.)
2. Read the [wiki 📖](https://github.com/curi0usJack/luckystrike/wiki)!
3. Open an ADMINISTRATIVE PowerShell prompt
4. Run `iex (new-object net.webclient).downloadstring('https://git.io/v7kbp')` (a luckystrike folder will be created for you.)
5. Run `.\luckystrike\luckystrike.ps1` (also as an administrator)

### Issues

#### Troubleshooting

- Ensure you are running in an administrator powershell prompt
- Run luckystrike with the -Debug switch `.\luckystrike\luckystrike.ps1 -Debug`

This will generate a debug .log file in the luckystrike directory.

#### Reporting Issues

1. Ensure you have first performed all troubleshooting steps
2. Save log output
3. Take a screenshot of the error
4. [https://github.com/curi0usJack/luckystrike/issues/new](Submit an issue) with the screenshot & debug log attached
5. Be patient. I'm one guy. :-)
