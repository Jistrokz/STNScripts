#PS1
#"STN-TheScrapper - Windows"
#__author__ = "Kartavya Trivedi"
#__version__ = "2.0"
#__date__ = "2021-12-16"

# #$Computers = get-content C:\list.txt 
# $(get-content -path "C:/the path")

# foreach($Computer in Computers)
# {
# Invoke-Command -ComputerName $Computer -ScriptBlock{
#     Get-WmiObject -Class Win32_Service -Filter "name='svc1' or name='svc2'" -ErrorAction SilentlyContinue 
# } -ThrottleLimit 50
# }
Write-Host "____ ___ _  _    _ _  _ ____          ___ _  _ ____ ____ ____ ____ ____ ___  ___  ____ ____ " -ForegroundColor Green
Write-Host "[__   |  |\ |    | |\ | |       __     |  |__| |___ [__  |    |__/ |__| |__] |__] |___ |__/ " -ForegroundColor Green
Write-Host "___]  |  | \|    | | \| |___           |  |  | |___ ___] |___ |  \ |  | |    |    |___ |  \ " -ForegroundColor Green
Write-Host " "
Write-Host "  Version 2.0, Kartavya Trivedi" -ForegroundColor Green

$Path2HostName = Read-Host -Prompt "Please input the exact path to the File containing Hostname "
$Path2TheScrapper = Read-Host -Prompt "Please input the exact path to the TheScrapper "

Invoke-Command -ComputerName $(get-content -path $Path2HostName) -FilePath $Path2TheScrapper