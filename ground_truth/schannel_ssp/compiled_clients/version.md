TLS Library: Schannel SSP
OS-Version: 
Get-ComputerInfo | Select-Object WindowsProductName, WindowsVersion, OsBuildNumber, OsArchitecture

WindowsProductName WindowsVersion OsBuildNumber OsArchitecture
------------------ -------------- ------------- --------------
Windows 10 Home    2009           22621         64-Bit-ARM-Prozessor


Version of DLLs:
PS C:\> (Get-Item "C:\Windows\System32\secur32.dll").VersionInfo

ProductVersion   FileVersion      FileName
--------------   -----------      --------
10.0.22621.1     10.0.22621.1 ... C:\Windows\System32\secur32.dll


PS C:\> (Get-Item "C:\Windows\System32\ncrypt.dll").VersionInfo

ProductVersion   FileVersion      FileName
--------------   -----------      --------
10.0.22621.4830  10.0.22621.48... C:\Windows\System32\ncrypt.dll


PS C:\> (Get-Item "C:\Windows\System32\ncryptsslp.dll").VersionInfo

ProductVersion   FileVersion      FileName
--------------   -----------      --------
10.0.22621.2506  10.0.22621.25... C:\Windows\System32\ncryptsslp.dll


PS C:\> (Get-Item "C:\Windows\System32\ncryptprov.dll").VersionInfo

ProductVersion   FileVersion      FileName
--------------   -----------      --------
10.0.22621.4830  10.0.22621.48... C:\Windows\System32\ncryptprov.dll


PS C:\> (Get-Item "C:\Windows\System32\schannel.dll").VersionInfo

ProductVersion   FileVersion      FileName
--------------   -----------      --------
10.0.22621.4830  10.0.22621.48... C:\Windows\System32\schannel.dll


PS C:\> (Get-Item "C:\Windows\System32\sspicli.dll").VersionInfo

ProductVersion   FileVersion      FileName
--------------   -----------      --------
10.0.22621.3810  10.0.22621.38... C:\Windows\System32\sspicli.dll 
