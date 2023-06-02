# Windows 11 Debloat Guide

## IMPORTANT

This guide is meant for advanced users who wants to get rid off Windows 11's bloatware and telemetry, if you have no experience of such thing then you can consider this [guide](https://youtu.be/QBp1d2uhG5M) for ease. <br>

![Windows 10 and later x64-2023-01-28-14-07-35](https://user-images.githubusercontent.com/81305501/215268038-8c6d21c8-14f0-4fc6-81b3-498bf5de8a30.png)

**Note : You're doing this at your own risk, I am not responsible for any data loss or damage that may occur.** <br>
Last tested on Windows 11 22621.525.

### Pros

➕ Get rid of bloatware <br>
➕ Disable most of the telemetry <br>
➕ Gain performance <br>
➕ Optimize Windows 11 for gaming as well as productivity <br>
➕ Strip Windows 11 to barebones (In Advanced removal below) <br>

### Cons

➖ Breaks Sysprep <br>
➖ Breaks newer system updates if you use install_wim_tweak to remove components <br>
➖ Don't use sfc/scannow command <br>

## Pre-Requisite

• NTFS Access (to remove Windows Defender) <br>
• Install_Wim_Tweak.exe (skip if you want to recieve updates) <br>
• DISM++ (Optional but recommended) <br>
• Winaero Tweaker

## Debloating Windows 11 

### Before you debloat!
At the end of the setup process, create a local account, don't use Cortana and turn off everything in the privacy settings. <br>

![Screenshot (01)](https://user-images.githubusercontent.com/85176292/132122504-1412f80f-2bac-4671-93f0-fa5204082b59.png)
![Screenshot (02)](https://user-images.githubusercontent.com/85176292/132122505-95823c80-06cc-4037-a48a-7e4a2e0a904a.png)

To create a local user account in Windows 11 22H2 (doesn't include Enterprise/Education), you can go with 3 alternative options:

1. When you should connect to a Internet, press Shift+F10 and type in Command Prompt:
```oobe\bypassnro```.
After reboot, you should select I don't have internet and continue further.
![Windows 10 and later x64-2023-01-27-16-12-01](https://user-images.githubusercontent.com/81305501/215120064-2e8f4129-d66e-423f-9586-39aac8364e86.png)

2. Configure as normally, until you get a login to Microsoft Account. Then type in a@a.com, and any random password.
![Windows 10 and later x64-2023-01-27-16-16-33](https://user-images.githubusercontent.com/81305501/215121534-dec5fc8b-265c-4274-a992-7e2444d405c3.png)
It should error that someone has entered an incorrect password too many times. Just click Next and make a local account.

3. Select Set up for work and school on the How would you like to set up this device screen. Click Next, select Sign-in options and choose Domain join instead. You should be on the local account screen.

**Make sure you are doing this on a temporary user account because you'll be deleting this later on.** <br>
Copy and paste the "install_wim_tweak.exe" to C:\Windows\System32 <br>

![Screenshot (03)](https://user-images.githubusercontent.com/85176292/132123362-f68c5829-c739-4628-94be-7ca2dc27fb54.png)

The first thing to do after the install is installing the updates. You should get all installed, because some of them might revert your changes after the debloat. So after the OOBE, open up Start Menu, select Settings, go to Windows Update section, and click Check updates.

Before debloating if you have recently updated your copy of Windows 11 or just freshly installed it, I would recommend you to cleanup the component store with /resetbase command or use DISM++ for ease, it clears the temp files with update leftovers in WinSxS. <br>

![Screenshot (04)](https://user-images.githubusercontent.com/85176292/132123367-6e2ebe05-9f93-4c18-86cf-ffb1f7cc34ea.png)

![Screenshot (05)](https://user-images.githubusercontent.com/85176292/132123387-5c0b6700-0497-4561-a01f-2ba419455c46.png)

**Note : If DISM++ gives error while cleaning up the component store use this command (Command Prompt as Admin Obviously)**

```
DISM /Online /Cleanup-Image /StartComponentCleanup /ResetBase
```
After the cleanup is done you can start debloating Windows 11. <br>

### **REMOVE ALL APPS AUTOMATICALLY**
If you want to remove all the apps automatically, in the Powershell, type this:
```
Get-AppxPackage | Remove-AppxPackage
```
Ignore all the errors. If you prefer to delete all apps manually, start from Alarms and Clock section.

### Alarms and Clock
In the Powershell, type:
```
Get-AppxPackage -AllUsers *alarms* | Remove-AppxPackage
Get-AppxPackage -AllUsers *people* | Remove-AppxPackage
```
You can ignore any error that pops up.

### Calculator
In the PowerShell, type:
```
Get-AppxPackage -AllUsers *calc* | Remove-AppxPackage
```
Download Classic Calulator from [Here](https://winaero.com/get-calculator-from-windows-8-and-windows-7-in-windows-10/)

### Mail, Calendar, ...
In the PowerShell, type:
```
Get-AppxPackage -AllUsers *comm* | Remove-AppxPackage
Get-AppxPackage -AllUsers *mess* | Remove-AppxPackage
```

### Clipchamp, Quick Assist and Family
In the Powershell, type:
```
Get-AppxPackage -AllUsers *Clipchamp* | Remove-AppxPackage
Get-AppxPackage -AllUsers *QuickAssist* | Remove-AppxPackage
Get-AppxPackage -AllUsers *Family* | Remove-AppxPackage
```

### Camera
In the PowerShell, type:
```
Get-AppxPackage -AllUsers *camera* | Remove-AppxPackage
````
Ignore any error that pops up

### Connect
In the command prompt, type:
```
install_wim_tweak /o /c Microsoft-PPIProjection-Package /r
```

### Contact Support, Get Help
In the command prompt, type:
```
install_wim_tweak /o /c Microsoft-Windows-ContactSupport /r
```

### Cortana (UWP App)
In the powershell, type:
```
Get-AppxPackage -allusers Microsoft.549981C3F5F10 | Remove-AppxPackage
```

### Music, TV
In the PowerShell, type: <br>
```
Get-AppxPackage -AllUsers *zune* | Remove-AppxPackage
Get-WindowsPackage -Online | Where PackageName -like *MediaPlayer* | Remove-WindowsPackage -Online -NoRestart
```

### Groove Music
In the PowerShell, type:
```
Get-AppxPackage -AllUsers *zune* | Remove-AppxPackage
```

### Microsoft Solitare Collection
In the PowerShell, type:
```
Get-AppxPackage *Microsoft.MicrosoftSolitaireCollection* | Remove-AppxPackage
```

### Office
In the PowerShell, type:
```
Get-AppxPackage *Microsoft.MicrosoftOfficeHub* | Remove-AppxPackage
Get-AppxPackage *Microsoft.Office.Sway* | Remove-AppxPackage
Get-AppxPackage *Microsoft.Office.Desktop* | Remove-AppxPackage
```

### Get Help
In the PowerShell, type:
```
Get-AppxPackage -AllUsers *GetHelp* | Remove-AppxPackage
```

### Feedback Hub
In the PowerShell, type:
```
Get-AppxPackage *Microsoft.WindowsFeedbackHub* | Remove-AppxPackage
```

### Sticky Notes
In the PowerShell, type: <br>
```
Get-AppxPackage -AllUsers *sticky* | Remove-AppxPackage
```

### Maps
In the PowerShell, type: <br>
```
Get-AppxPackage -AllUsers *maps* | Remove-AppxPackage
```

### Removing Services
In Command Prompt, type: <br>
```
sc delete MapsBroker
sc delete lfsvc
schtasks /Change /TN "\Microsoft\Windows\Maps\MapsUpdateTask" /disable
schtasks /Change /TN "\Microsoft\Windows\Maps\MapsToastTask" /disable
```

### OneNote
In the PowerShell, type:
```
Get-AppxPackage -AllUsers *onenote* | Remove-AppxPackage
```

### Photos
In the PowerShell, type:
```
Get-AppxPackage -AllUsers *photo* | Remove-AppxPackage
```
Enable Classic Photoviewer using [WinAeroTweaker](https://winaero.com/download-winaero-tweaker/)

### Weather, News, ...
In the PowerShell, type:
```
Get-AppxPackage -AllUsers *bing* | Remove-AppxPackage
```

### Sound Recorder
In the PowerShell, type:
```
Get-AppxPackage -AllUsers *soundrec* | Remove-AppxPackage
```
Alternatives [Audacity](http://www.audacityteam.org/)

### Microsoft Quick Assist
In the PowerShell, type:
```
Get-WindowsPackage -Online | Where PackageName -like *QuickAssist* | Remove-WindowsPackage -Online -NoRestart
```
### OneDrive
In the Command Promopt, type:
```
%SystemRoot%\SysWOW64\OneDriveSetup.exe /uninstall
rd "%UserProfile%\OneDrive" /s /q
rd "%LocalAppData%\Microsoft\OneDrive" /s /q
rd "%ProgramData%\Microsoft OneDrive" /s /q
rd "C:\OneDriveTemp" /s /q
del "%USERPROFILE%\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\OneDrive.lnk" /s /f /q
```

### Your Phone
In the PowerShell, type:
```
Get-AppxPackage -AllUsers *phone* | Remove-AppxPackage
```

### Hello Face
In the PowerShell, type:
```
Get-WindowsPackage -Online | Where PackageName -like *Hello-Face* | Remove-WindowsPackage -Online -NoRestart
```

In the command prompt, type:
```
schtasks /Change /TN "\Microsoft\Windows\HelloFace\FODCleanupTask" /Disable
```

### Widgets (Windows Web Experience Pack)
In the Powershell, type:
```
Get-AppxPackage -AllUsers *WebExperience* | Remove-AppxPackage
```
When it's done removing, log out of your account, and log back in. You shouldn't have Widgets option in taskbar settings.

### Microsoft Store 
In the PowerShell, type: <br>
```
Get-AppxPackage -AllUsers *store* | Remove-AppxPackage
```
You can ignore any error that pops up.<br>

In Command Prompt, type: <br>
```
install_wim_tweak /o /c Microsoft-Windows-ContentDeliveryManager /r
install_wim_tweak /o /c Microsoft-Windows-Store /r
```

### Removing Services (Not Recommended if you are going to use any UWP app)

In Command Prompt, type: <br>
```
reg add "HKLM\Software\Policies\Microsoft\WindowsStore" /v RemoveWindowsStore /t REG_DWORD /d 1 /f
reg add "HKLM\Software\Policies\Microsoft\WindowsStore" /v DisableStoreApps /t REG_DWORD /d 1 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\AppHost" /v "EnableWebContentEvaluation" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\PushToInstall" /v DisablePushToInstall /t REG_DWORD /d 1 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v SilentInstalledAppsEnabled /t REG_DWORD /d 0 /f
sc delete PushToInstall
```

### Xbox and Game DVR
In the PowerShell, type: <br>
```
Get-AppxPackage -AllUsers *xbox* | Remove-AppxPackage
```

### Removing Services (Not Recommended if you are going to use it in future)
In Command Prompt, type: <br>
```
sc delete XblAuthManager
sc delete XblGameSave
sc delete XboxNetApiSvc
sc delete XboxGipSvc
reg delete "HKLM\SYSTEM\CurrentControlSet\Services\xbgm" /f
schtasks /Change /TN "Microsoft\XblGameSave\XblGameSaveTask" /disable
schtasks /Change /TN "Microsoft\XblGameSave\XblGameSaveTaskLogon" /disable
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\GameDVR" /v AllowGameDVR /t REG_DWORD /d 0 /f
```

### Microsoft Edge (Chromium)

**DOESN'T WORK ANYMORE IN NEWER VERSIONS**

![Screenshot (07)](https://user-images.githubusercontent.com/85176292/132125057-ab8b2dbb-bb0a-4dc3-88c2-418f683e5332.png)

Now open powershell as Administrator and type: <br>
```
cd %PROGRAMFILES(X86)%\Microsoft\Edge\Application\10*\Installer && setup --uninstall --force-uninstall --system-level
```
Microsoft Edge is now uninstalled, but you still can see a broken icon on start menu to get rid off it open command prompt and type: <br>

![Screenshot (08)](https://user-images.githubusercontent.com/85176292/132125728-0bca64ec-243b-4d22-865a-2f17ac82d478.png)

```
install_wim_tweak.exe /o /l
install_wim_tweak.exe /o /c "Microsoft-Windows-Internet-Browser-Package" /r
install_wim_tweak.exe /h /o /l
```
Restart is required after this (you can restart later when you are done debloating everything).

In Powershell, type:
```
Get-AppxPackage -AllUsers *GetHelp* | Remove-AppxPackage
```

### Windows Defender (removing dependency updates and services)

If you want to backup all services, in the command prompt, type:
```
reg export HKLM\System\CurrentControlSet\Services\Sense Sense.reg
reg export HKLM\System\CurrentControlSet\Services\SecurityHealthService SecurityHealthService.reg
reg export HKLM\System\CurrentControlSet\Services\WinDefend WinDefend.reg
```
Copy them somewhere else, and apply them, if you plan to restore Windows Defender.

To remove Windows Defender, in the command prompt, type:
```
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" /v SmartScreenEnabled /t REG_SZ /d "Off" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\AppHost" /v "EnableWebContentEvaluation" /t REG_DWORD /d "0" /f
reg add "HKCU\Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\microsoft.microsoftedge_8wekyb3d8bbwe\MicrosoftEdge\PhishingFilter" /v "EnabledV9" /t REG_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v DisableAntiSpyware /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" /v SpyNetReporting /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" /v SubmitSamplesConsent /t REG_DWORD /d 2 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" /v DontReportInfectionInformation /t REG_DWORD /d 1 /f
reg delete "HKLM\SYSTEM\CurrentControlSet\Services\Sense" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\MRT" /v "DontReportInfectionInformation" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\MRT" /v "DontOfferThroughWUAU" /t REG_DWORD /d 1 /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v "SecurityHealth" /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run" /v "SecurityHealth" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\SecHealthUI.exe" /v Debugger /t REG_SZ /d "%windir%\System32\taskkill.exe" /f
install_wim_tweak /o /c Windows-Defender /r
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Notifications\Settings\Windows.SystemToast.SecurityAndMaintenance" /v "Enabled" /t REG_DWORD /d 0 /f
reg delete "HKLM\SYSTEM\CurrentControlSet\Services\SecurityHealthService" /f
schtasks /Change /TN "Microsoft\Windows\AppID\SmartScreenSpecific" /disable
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v "EnableSmartScreen" /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Internet Explorer\PhishingFilter" /v "EnabledV9" /t REG_DWORD /d 0 /f

```

To remove WinDefend, which is the main service, you need to: 
1. Go to winaero.com and download Winaero Tweaker. Install it.
2. In Tools section, you should find "Run as TrustedInstaller". In "Exectuable file" type regedit.exe. 
![Screenshot 2023-01-28 041259](https://user-images.githubusercontent.com/81305501/215266309-738e2ff5-49b5-4de7-af64-5ea746cdedad.png)
3. Press Enter.
4. Go to HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WinDefend.
5. Right-click WinDefend, and select Delete from the context menu.

![Screenshot 2023-01-28 (2)](https://user-images.githubusercontent.com/81305501/215266405-b47577fe-ea4f-41f6-86d4-80c3c413384b.png)

6. When a permanent delete dialog appears, select Yes.

![Screenshot 2023-01-28 042403](https://user-images.githubusercontent.com/81305501/215266726-fc6ebf26-0620-4020-9087-afad2a2592c6.png)

7. Reboot your PC.
Don't forget to backup the services. 

After that use NTFS Access and take ownership of C:\Program Files\WindowsApps\ and C:\ProgramData\Microsoft\.

![Screenshot (09)](https://user-images.githubusercontent.com/85176292/132126349-d91c4b65-f3c4-412e-a0c9-bba4c039ac30.png)

In WindowsApps, delete the SecHealthUI folder.

![Screenshot (10)](https://user-images.githubusercontent.com/85176292/132126362-c47be7df-d62f-4212-bd07-97714fd47041.png)

In ProgramData\Microsoft, delete every folder related to Windows Defender.

![Screenshot (11)](https://user-images.githubusercontent.com/85176292/132126653-1cbec29b-4c31-49f0-b596-b230913f4f30.png)

### Windows Defender (keeping definition updates and services)

Just take the ownership of C:\Program Files\WindowsApps\ and C:\ProgramData\Microsoft <br>
Then delete the SecHealthUI folder insider WindowsApps and every folder related to Windows Defender inside ProgramData. <br>
Now disable Windows Defender through WinAeroTweaker.

### Optimizing

Now since you have removed all the bloatware let's just finally delete the leftovers from C:\Program Files\WindowsApps <br>
Take the ownership as we did above. <br>
Now delete folders according to what apps you removed... <br>

For example, I've removed everything and kept Store, Xbox, Notepad (UWP) and Windows Terminal. <br>

![Screenshot (12)](https://user-images.githubusercontent.com/85176292/132127306-370369f6-d9f0-4a39-87e4-9b1eaa35eef8.png)

And here I've removed every bloatware. <br>

![Screenshot (13)](https://user-images.githubusercontent.com/85176292/132127308-3c44ff88-4dd9-4595-a1c9-f868c77ff33c.png)

Now create a new user account or enable Windows Administrator Account, log into it and voila! <br>
You have successfully removed nearly all UWP apps from Windows 11!

![Screenshot (14)](https://user-images.githubusercontent.com/85176292/132127314-a39be4cc-f084-4190-81e5-c44306db1edf.png)

Unfortunately there is no way to remove "Get Started App" from the start menu without compromising the new Start Menu/taskbar so just pretend it's not there at all :)

### Removing Options from Settings Apps
Now since you have removed the bloatware, it is recommended to remove the options related to them from the Settings.<br>
Open Regedit and go to `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer` <br>
Create new string named 'SettingsPageVisibility' <br>
Now type: 
```
hide:cortana;crossdevice;easeofaccess-speechrecognition;holographic-audio;mobile-devices;privacy-automaticfiledownloads;privacy-feedback;recovery;remotedesktop;speech;sync;sync;easeofaccess-closedcaptioning;easeofaccess-highcontrast;easeofaccess-keyboard;easeofaccess-magnifier;easeofaccess-mouse;easeofaccess-narrator;easeofaccess-otheroptions;privacy-location;backup;findmydevice;quiethours;tabletmode
```

TIP : Add `;windowsdefender` at the end of the string value if you have removed Windows Defender as well (doesn't matter if you kept updates or not)

### Edit with 3D Paint / 3D Print
It is now possible to remove 3D Paint and 3D Print, but they forgot to remove the option in the context menu when you remove them. To remove it, run this in the command prompt:
```
for /f "tokens=1* delims=" %I in (' reg query "HKEY_CLASSES_ROOT\SystemFileAssociations" /s /k /f "3D Edit" ^| find /i "3D Edit" ') do (reg delete "%I" /f )
for /f "tokens=1* delims=" %I in (' reg query "HKEY_CLASSES_ROOT\SystemFileAssociations" /s /k /f "3D Print" ^| find /i "3D Print" ') do (reg delete "%I" /f )
```
### Disabling Cortana
Open command prompt again and use this command:
```
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v AllowCortana /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"  /v "{2765E0F4-2918-4A46-B9C9-43CDD8FCBA2B}" /t REG_SZ /d  "BlockCortana|Action=Block|Active=TRUE|Dir=Out|App=C:\windows\systemapps\microsoft.windows.cortana_cw5n1h2txyewy\searchui.exe|Name=Search  and Cortana  application|AppPkgId=S-1-15-2-1861897761-1695161497-2927542615-642690995-327840285-2659745135-2630312742|" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /v BingSearchEnabled /t REG_DWORD /d 0 /f
```

### Turn off Windows Error reporting
In the command prompt, type:
```
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting" /v Disabled /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting" /v Disabled /t REG_DWORD /d 1 /f
```

### Windows Updates (Keeping Store Unaffected)
By doing this you will still be able to use Windows Store (Windows Updates service will run in background) without downloading any update. <br>
Open Regedit and go to `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer` <br>
Open the string we created earlier and type `;windowsupdate` at the end

### Disabling Windows Updates (Effects Windows Store)
By doing this you will not be able to use Microsoft Store or any other app which requires Windows Updates to be enabled.
Open Command Prompt and type:

```
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\wuauserv" /v Start /t REG_DWORD /d 4 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\UsoSvc" /v Start /t REG_DWORD /d 4 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\DoSvc" /v Start /t REG_DWORD /d 4 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" /v NoAutoUpdate /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" /v AUOptions /t REG_DWORD /d 2 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" /v ScheduledInstallDay /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" /v ScheduledInstallTime /t REG_DWORD /d 3 /f
```

### Disable sync
It doesn't really affect you if you're not using a Microsoft Account, but it will at least disable the Sync settings from the Settings app.
In the command prompt, type:
```
reg add "HKLM\Software\Policies\Microsoft\Windows\SettingSync" /v DisableSettingSync /t REG_DWORD /d 2 /f
reg add "HKLM\Software\Policies\Microsoft\Windows\SettingSync" /v DisableSettingSyncUserOverride /t REG_DWORD /d 1 /f
```

### Removing Telemetry and other unnecessary services
In the command prompt type the following commands:
```
sc delete DiagTrack
sc delete dmwappushservice
sc delete WerSvc
sc delete OneSyncSvc
sc delete MessagingService
sc delete wercplsupport
sc delete PcaSvc
sc config wlidsvc start=demand
sc delete wisvc
sc delete RetailDemo
sc delete diagsvc
sc delete shpamsvc 
sc delete TermService
sc delete UmRdpService
sc delete SessionEnv
sc delete TroubleshootingSvc
for /f "tokens=1" %I in ('reg query "HKLM\SYSTEM\CurrentControlSet\Services" /k /f "wscsvc" ^| find /i "wscsvc"') do (reg delete %I /f)
for /f "tokens=1" %I in ('reg query "HKLM\SYSTEM\CurrentControlSet\Services" /k /f "OneSyncSvc" ^| find /i "OneSyncSvc"') do (reg delete %I /f)
for /f "tokens=1" %I in ('reg query "HKLM\SYSTEM\CurrentControlSet\Services" /k /f "MessagingService" ^| find /i "MessagingService"') do (reg delete %I /f)
for /f "tokens=1" %I in ('reg query "HKLM\SYSTEM\CurrentControlSet\Services" /k /f "PimIndexMaintenanceSvc" ^| find /i "PimIndexMaintenanceSvc"') do (reg delete %I /f)
for /f "tokens=1" %I in ('reg query "HKLM\SYSTEM\CurrentControlSet\Services" /k /f "UserDataSvc" ^| find /i "UserDataSvc"') do (reg delete %I /f)
for /f "tokens=1" %I in ('reg query "HKLM\SYSTEM\CurrentControlSet\Services" /k /f "UnistoreSvc" ^| find /i "UnistoreSvc"') do (reg delete %I /f)
for /f "tokens=1" %I in ('reg query "HKLM\SYSTEM\CurrentControlSet\Services" /k /f "BcastDVRUserService" ^| find /i "BcastDVRUserService"') do (reg delete %I /f)
for /f "tokens=1" %I in ('reg query "HKLM\SYSTEM\CurrentControlSet\Services" /k /f "Sgrmbroker" ^| find /i "Sgrmbroker"') do (reg delete %I /f)
sc delete diagnosticshub.standardcollector.service
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Siuf\Rules" /v "NumberOfSIUFInPeriod" /t REG_DWORD /d 0 /f
reg delete "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Siuf\Rules" /v "PeriodInNanoSeconds" /f
reg add "HKLM\SYSTEM\ControlSet001\Control\WMI\AutoLogger\AutoLogger-Diagtrack-Listener" /v Start /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /v AITEnable /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /v DisableInventory /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /v DisablePCA /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /v DisableUAR /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\MicrosoftEdge\PhishingFilter" /v "EnabledV9" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v "EnableSmartScreen" /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Internet Explorer\PhishingFilter" /v "EnabledV9" /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoRecentDocsHistory" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\CompatTelRunner.exe" /v Debugger /t REG_SZ /d "%windir%\System32\taskkill.exe" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\DeviceCensus.exe" /v Debugger /t REG_SZ /d "%windir%\System32\taskkill.exe" /f
```

### Scheduled tasks
In command prompt type:
```
schtasks /Change /TN "Microsoft\Windows\AppID\SmartScreenSpecific" /disable
schtasks /Change /TN "Microsoft\Windows\Application Experience\AitAgent" /disable
schtasks /Change /TN "Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser" /disable
schtasks /Change /TN "Microsoft\Windows\Application Experience\ProgramDataUpdater" /disable
schtasks /Change /TN "Microsoft\Windows\Application Experience\StartupAppTask" /disable
schtasks /Change /TN "Microsoft\Windows\Autochk\Proxy" /disable
schtasks /Change /TN "Microsoft\Windows\CloudExperienceHost\CreateObjectTask" /disable
schtasks /Change /TN "Microsoft\Windows\Customer Experience Improvement Program\BthSQM" /disable
schtasks /Change /TN "Microsoft\Windows\Customer Experience Improvement Program\Consolidator" /disable
schtasks /Change /TN "Microsoft\Windows\Customer Experience Improvement Program\KernelCeipTask" /disable
schtasks /Change /TN "Microsoft\Windows\Customer Experience Improvement Program\Uploader" /disable
schtasks /Change /TN "Microsoft\Windows\Customer Experience Improvement Program\UsbCeip" /disable
schtasks /Change /TN "Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector" /disable
schtasks /Change /TN "Microsoft\Windows\DiskFootprint\Diagnostics" /disable
schtasks /Change /TN "Microsoft\Windows\FileHistory\File History (maintenance mode)" /disable
schtasks /Change /TN "Microsoft\Windows\Maintenance\WinSAT" /disable
schtasks /Change /TN "Microsoft\Windows\PI\Sqm-Tasks" /disable
schtasks /Change /TN "Microsoft\Windows\Power Efficiency Diagnostics\AnalyzeSystem" /disable
schtasks /Change /TN "Microsoft\Windows\Shell\FamilySafetyMonitor" /disable
schtasks /Change /TN "Microsoft\Windows\Shell\FamilySafetyRefresh" /disable
schtasks /Change /TN "Microsoft\Windows\Shell\FamilySafetyUpload" /disable
schtasks /Change /TN "Microsoft\Windows\Windows Error Reporting\QueueReporting" /disable
schtasks /Change /TN "Microsoft\Windows\WindowsUpdate\Automatic App Update" /disable
schtasks /Change /TN "Microsoft\Windows\License Manager\TempSignedLicenseExchange" /disable
schtasks /Change /TN "Microsoft\Windows\Clip\License Validation" /disable
schtasks /Change /TN "\Microsoft\Windows\ApplicationData\DsSvcCleanup" /disable
schtasks /Change /TN "\Microsoft\Windows\Power Efficiency Diagnostics\AnalyzeSystem" /disable
schtasks /Change /TN "\Microsoft\Windows\PushToInstall\LoginCheck" /disable
schtasks /Change /TN "\Microsoft\Windows\PushToInstall\Registration" /disable
schtasks /Change /TN "\Microsoft\Windows\Shell\FamilySafetyMonitor" /disable
schtasks /Change /TN "\Microsoft\Windows\Shell\FamilySafetyMonitorToastTask" /disable
schtasks /Change /TN "\Microsoft\Windows\Shell\FamilySafetyRefreshTask" /disable
schtasks /Change /TN "\Microsoft\Windows\Subscription\EnableLicenseAcquisition" /disable
schtasks /Change /TN "\Microsoft\Windows\Subscription\LicenseAcquisition" /disable
schtasks /Change /TN "\Microsoft\Windows\Diagnosis\RecommendedTroubleshootingScanner" /disable
schtasks /Change /TN "\Microsoft\Windows\Diagnosis\Scheduled" /disable
schtasks /Change /TN "\Microsoft\Windows\NetTrace\GatherNetworkInfo" /disable
del /F /Q "C:\Windows\System32\Tasks\Microsoft\Windows\SettingSync\*" 
```
## Disabling useless services and applying some tweaks

Use the batch script to disable some useless services and the reg file to import some tweaks. <br>

## Tweaks for Winaero Tweaker

Simply install WinAeroTweaker and import the preset (.ini file) <br>

![Screenshot (1672)](https://user-images.githubusercontent.com/85176292/147569287-a7223dc9-3081-4289-b18e-8f71507e8d02.png)

## (OPTIONAL) Disabling Windows Update and Store related services (if you don't want to use them)

Use the batch script to disable them. <br>

## Stripping Windows 11 to barebone! (only for 21H2)

To strip Windows 11 to barebones, you need to uninstall Windows Feature Experience Pack, which has most of the new features (XAML taskbar, start menu, Get Started app). After uninstalling Feature Experience Pack, you won't be able to go back to the Windows 11 look, unless you reinstall Feature Experience Pack. **DO NOT DO THIS AT HOME AND ON YOUR MAIN COMPUTER.**

1. Install ExplorerPatcher or StartAllBack, and enable custom shell (Windows 10 taskbar and start menu in case of ExplorerPatcher, custom taskbar and start menu for SAB)
2. Open up CMD with Administrator permissions, and type in: 
```
DISM /Online /Get-Packages | findstr UserExperience
```
![image](https://user-images.githubusercontent.com/81305501/214150015-10e3f270-85c5-4c07-95be-de655aaa3cef.png)

3. Type in: 
```
DISM /Online /Remove-Package /PackageName: (type in what you got in Package Identity earlier)
```
If you have two packages (like in previous screenshot), uninstall the newer one.

4. Press Enter and proceed to remove package. If DISM prompts you to restart, type Y. If you don't want to restart for now, type N.

![214150565-0c3204ab-6c03-4a51-b49e-4f38c56195b4](https://user-images.githubusercontent.com/81305501/214152195-c86a5a5d-8b82-46ac-86ba-eb51abc12fdc.png)

5. After reboot, your system will be stripped to barebones (forgot to debloat earlier)
 
![Windows 10 and later x64-2023-01-23-22-12-55](https://user-images.githubusercontent.com/81305501/214151238-e684c5e2-9e73-4ca9-b0af-2d2f0eb613e9.png)



## Congratulations! Your copy of Windows is now debloated & optimized!
More bloat will be added in the future, and I'll do what I can to keep this guide updated. As of January 2023, this guide works on Windows 11 22621.525.

## Credits 

• This guide is based on Adolf Intel's [Windows 10 Privacy Guide](https://github.com/adolfintel/Windows10-Privacy) with many modifications to make it usable on Windows 11 <br>
• Original Guide by The World Of PC#8783, this version is made by Typical#9480 <br>

