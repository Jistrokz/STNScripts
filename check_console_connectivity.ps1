# Name: check_console_connectivity.ps1
# Author: SentinelOne
# Version: 1.13
# DateCreated: 2022-01-21
# DateUpdated: 2023-03-08 (by Mat Salamon)

param ([Parameter(Mandatory=$false)] [ValidateSet("true", "false")] $NetshCapture='true', $Proxyurl='false', $CaptureInterval = 61 , $CustomUrl, $CustomPassphrase)


## Get agent current path
$path = 'C:\Program Files\SentinelOne\Sentinel*\SentinelCtl.exe' #adding it here in case Measure-Object is not supported by some browsers in Powershell

$count_directories = (Get-ChildItem -Path 'C:\Program Files\SentinelOne\' | Measure-Object).Count

if ( 1 -eq $count_directories)
{
$path = 'C:\Program Files\SentinelOne\Sentinel*\SentinelCtl.exe'
}
else {
        $helper = New-Object -ComObject "SentinelHelper.1"
        $agent_version = ($helper.GetAgentStatusJSON() | ConvertFrom-Json)[0].'agent-version'
        $path = "C:\Program Files\SentinelOne\Sentinel Agent $agent_version\SentinelCtl.exe"
}

#################################################
#                               getting mgmt url                                #
#################################################

if($CustomUrl -eq $null){
$config = & $path config | select-string -Pattern "server.mgmtServer"
$mgmt = $config -split ' ' | select -last 1
$domain_name = $mgmt.Substring(8)
}else {$domain_name = $CustomUrl}
<# This section is obselete starting version 1.9
#################################################
# Replace the below variable with your mgmt url #
#################################################

$domain_name = "yourmgmt.sentinelone.net" # Do NOT include http/https."

#################################################
# Checking if the domain name was correctly changed #
#################################################


if ($domain_name -eq "yourmgmt.sentinelone.net") {Write-Host "`nPLEASE MAKE SURE TO CHANGE LINE 13 OF THIS SCRIPT " -BackgroundColor RED -ForegroundColor White
break}
#>

###################################
##   Prepare script              ##
###################################

$outputArchiveFullName = "$env:windir\temp\Connectivity_check-$(hostname)-$(get-date -f yyyy-MM-dd-HH-mm-ss).zip"
$outputFolder ="$env:windir\temp\Connectivity_check-$(hostname)-$(get-date -f yyyy-MM-dd-HH-mm-ss)"

Write-Host "`n###Creating temp folder###"  -BackgroundColor White -ForegroundColor Black
New-Item -ItemType Directory -Force -Path $outputFolder

Write-Host "`n###Starting transcript###"  -BackgroundColor White -ForegroundColor Black
Start-Transcript "$outputFolder\connectivity_check.txt"

Write-Host "`nConnectivity check towards " $domain_name -BackgroundColor Cyan -ForegroundColor Black

Write-Host "`nSome steps will require admin rights to display complete outputs. Checking if running as Administrator:" -BackgroundColor White -ForegroundColor Black

$user = [Security.Principal.WindowsIdentity]::GetCurrent();
$admin=(New-Object Security.Principal.WindowsPrincipal $user).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)  

if ($admin -eq $false) {
Write-Host "`nWarning : The network capture won't be performed and Data will be missing. Please run the script as Administrator" -BackgroundColor Yellow -ForegroundColor Black
}
else { 
    Write-Host "`nScript is running as Administrator" -BackgroundColor Green -ForegroundColor Black
}

#Set-ExecutionPolicy Unrestricted #

###################################
##   Certificate Check           ##
###################################

Write-Host "`n###Performing Certificate Check###" -BackgroundColor White -ForegroundColor Black

$DigiCertGlobalRootCAThumbprint = 'A8985D3A65E5E5C4B2D7D66D40C6DD2FB19C5436'


#$DigiCertGlobalRootCA = Get-ChildItem -Recurse Cert:\LocalMachine\Root | Where-Object -Property Thumbprint -EQ $DigiCertGlobalRootCAThumbprint | Select-Object -First 1
$DigiCertGlobalRootCA = Get-ChildItem -Recurse Cert:\LocalMachine\Root | Where-Object {$_.Thumbprint -match $DigiCertGlobalRootCAThumbprint} | Select-Object -First 1

if(!$DigiCertGlobalRootCA){
    Write-host 'ERROR: DigiCert Global Root (Thumbprint A8985D3A65E5E5C4B2D7D66D40C6DD2FB19C5436) CA is not imported in the LocalMachine certificate store, please follow: "https://support.sentinelone.com/hc/en-us/articles/115004252325-Installing-DigiCert-Certificates"' -BackgroundColor Red -ForegroundColor Black
} else {
    Write-host 'DigiCert Global Root CA is imported (Thunbprint A8985D3A65E5E5C4B2D7D66D40C6DD2FB19C5436).' 
}


###################################
##   Cipher Suite Check Script   ##
###################################

Write-Host "`n###Performing Cipher Suite Check###" -BackgroundColor White -ForegroundColor Black

##Pull and Build required data
$scriptFolder = "$outputFolder"
$keyValue = (Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Control\Cryptography\Configuration\Local\SSL\00010002 -Name Functions).Functions
$gpoValue = (Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\00010002 -Name Functions).Functions
$osKeyValue = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" -Name ProductName).ProductName 
$hotfixList = @(Get-HotFix)
#### Our Supported Cipher Suites also supported by 2008 R2 SP1 and 2012/2012 R2 ###
##Supporting documents
$supportedCipherSuites = $scriptFolder + "\SupportedCipherSuites.csv"
$gpoCipherSuites = $scriptFolder + "\GPOCipherSuites.csv"
$localCipherSuites = $scriptFolder + "\LocalCipherSuites.csv"
$commonCipherSuites = $scriptFolder + "\CommonCipherSuites.csv"
$hotfixFile = $scriptFolder + "\HotfixList.csv"
## Server specific Script Blocks
$2k8Win7 = {
                ##Check if Server 2008R2 SP1 or Windows 7 SP1 and if Required updates are installed
                $csdValue = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" -Name CSDVersion).CSDVersion
                if ($csdValue -notlike "Service Pack 1")
                    {
                        Write-Host "You must install Service Pack 1 to be supported"
                        Exit
                    }
                ##Continuing after passing SP1 Validation
                Write-Host "This is Windows Server 2008 R2 SP1"
                if ($hotfixList -like "*KB4457144*")
                    {
                        Set-Content -Path $hotfixFile -Value "KB4457144 is Installed"
                    }
                Else
                    {
                        Set-Content -Path $hotfixFile -Value "KB4457144 is not Installed"
                    }
                if ($hotfixList -like "*KB3140245*")
                    {
                        Add-Content -Path $hotfixFile -Value "KB3140245 is Installed"
                    }
                Else
                    {
                        Add-Content -Path $hotfixFile -Value "KB3140245 is not Installed"
                    }
                if ($hotfixList -like "*KB3033929*")
                    {
                        Add-Content -Path $hotfixFile -Value "KB3033929 is Installed"
                    }
                Else
                    {
                        Add-Content -Path $hotfixFile -Value "KB3033929 is not Installed"
                    }                  
           }
$server2012 = {
                Write-Host "This is Windows Server 2012"
                if ($hotfixList -like "*KB3140245*")
                    {
                        Set-Content -Path $hotfixFile -Value "KB3140245 is Installed"
                    }
                Else
                    {
                        Set-Content -Path $hotfixFile -Value "KB3140245 is not Installed"
                    }                
              }
$server2012R2 = {
                    Write-Host "This is Server 2012R2"
                    if ($hotfixList -like "*KB2919355*")  ### This is a rollup of all the others and is all that is required for communication --  Setup If Statement to check this and end or if this does not exist check the others.
                        {
                            Set-Content -Path $hotfixFile -Value "Roll-up Update KB2919355 is Installed and contains the other required updates."
                        }
                    Else
                        {
                            Set-Content -Path $hotfixFile -Value "Roll-up Update KB2919355 is not Installed. `n So the following updates must be installed."
                            if ($hotfixList -like "*KB2919442*")
                                {
                                    Add-Content -Path $hotfixFile -Value "KB2919442 is Installed"
                                }
                            Else
                                {
                                    Add-Content -Path $hotfixFile -Value "KB2919442 is not Installed"
                                }
                            if ($hotfixList -like "*KB2932046*")
                                {
                                    Add-Content -Path $hotfixFile -Value "KB2932046 is Installed"
                                }
                            Else
                                {
                                    Add-Content -Path $hotfixFile -Value "KB2932046 is not Installed"
                                }
                            if ($hotfixList -like "*KB2959977*")
                                {
                                    Add-Content -Path $hotfixFile -Value "KB2959977 is Installed"
                                }
                            Else
                                {
                                    Add-Content -Path $hotfixFile -Value "KB2959977 is not Installed"
                                }
                            if ($hotfixList -like "*KB2937592*")
                                {
                                    Add-Content -Path $hotfixFile -Value "KB2937592 is Installed"
                                }
                            Else
                                {
                                    Add-Content -Path $hotfixFile -Value "KB2937592 is not Installed"
                                }
                            if ($hotfixList -like "*KB2938439*")
                                {
                                    Add-Content -Path $hotfixFile -Value "KB2938439 is Installed"
                                }
                            Else
                                {
                                    Add-Content -Path $hotfixFile -Value "KB2938439 is not Installed"
                                }
                            if ($hotfixList -like "*KB2934018*")
                                {
                                    Add-Content -Path $hotfixFile -Value "KB2934018 is Installed"
                                }
                            Else
                                {
                                    Add-Content -Path $hotfixFile -Value "KB2934018 is not Installed"
                                }                            
                        }
                }
##Pull System Loaded Cipher Suites
if ($gpoValue)
    {
        $systemCipherSuites = $gpoCipherSuites
        $cipherSuites = $gpoValue
    }
else
    {
        $systemCipherSuites = $localCipherSuites
        $cipherSuites = $keyValue
    }
Set-Content -Path $systemCipherSuites -Value $cipherSuites
##
##Check OS Updates before checking Cipher Suites... 
##OS Update Requirements must be met before proper Cipher Suites come into play.
##Updates used are a combonation of updates listed in our System Requirements and Cipher Suite Troubleshooting KB
##
if ($osKeyValue -like "*Server 2008 R2*" -or $osKeyValue -like "*Windows 7*")
    {
        .$2k8Win7
    }
##Check if Windows Server 2012 and if Required Updates are installed
if ($osKeyValue -like "Windows Server 2012*")
    {
        .$server2012
    }
##Check if Windows Server 2012 R2 and if Required Updates are installed
if ($osKeyValue -like "*Server 2012 R2*" -or $osKeyValue -like "*Windows 8.1*")
    {
        .$server2012R2        
    }
##Generate Supported Cipher Suites text file and add list of cipher suites
##If you need to check for different Cipher Suites,you must update the Supported Cipher Suites in the Set-Content
if (($osKeyValue -like "*Server 2012 R2*") -or ($osKeyValue -like "*Windows 8.1*") -or ($osKeyValue -like "Windows Server 2012") -or ($osKeyValue -like "*Server 2008 R2*") -or ($osKeyValue -like "*Windows 7*"))
    {
Set-Content $supportedCipherSuites -Value "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384
TLS_DHE_RSA_WITH_AES_128_GCM_SHA256
TLS_DHE_RSA_WITH_AES_256_CBC_SHA
TLS_DHE_RSA_WITH_AES_128_CBC_SHA"
                ## Compare Supported Manager Cipher Suites between Manager and Client ##                
                Get-Content $supportedCipherSuites | ForEach-Object {
                        $supportedCipherSuites_Line = $_
                        Get-Content $systemCipherSuites | Where-Object {$_.Contains($supportedCipherSuites_Line)} | Out-File -FilePath $commonCipherSuites -Append
                    }        
    }
else 
    {
Set-Content $supportedCipherSuites -Value "TLS_AES_256_GCM_SHA384
TLS_CHACHA20_POLY1305_SHA256
TLS_AES_128_GCM_SHA256
TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
TLS_DHE_RSA_WITH_AES_128_GCM_SHA256
TLS_DHE_RSA_WITH_AES_256_GCM_SHA384
TLS_DHE_RSA_WITH_AES_128_CBC_SHA256
TLS_DHE_RSA_WITH_AES_128_CBC_SHA
TLS_DHE_RSA_WITH_AES_256_CBC_SHA256
TLS_DHE_RSA_WITH_AES_256_CBC_SHA
TLS_DHE_RSA_WITH_AES_256_CCM_8
TLS_DHE_RSA_WITH_AES_256_CCM
TLS_DHE_RSA_WITH_AES_128_CCM_8
TLS_DHE_RSA_WITH_AES_128_CCM
TLS_RSA_WITH_AES_256_CCM_8
TLS_RSA_WITH_AES_256_CCM
TLS_RSA_WITH_AES_128_CCM_8
TLS_RSA_WITH_AES_128_CCM
TLS_ECDHE_RSA_WITH_CAMELLIA_256_CBC_SHA384
TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256
TLS_ECDHE_RSA_WITH_CAMELLIA_128_CBC_SHA256
TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256
TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA
TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA
TLS_RSA_WITH_CAMELLIA_256_CBC_SHA256
TLS_RSA_WITH_CAMELLIA_128_CBC_SHA256"
        ##Compare Supported Manager Cipher Suites and Cipher Suites loaded by the system##        
        Get-Content $supportedCipherSuites | ForEach-Object {
                $supportedCipherSuites_Line = $_
                Get-Content $systemCipherSuites | Where-Object {$_.Contains($supportedCipherSuites_Line)} | Out-File -FilePath $commonCipherSuites -Append
            }
    }
## How many Common Cipher Suites were found?
$countCiphers = Get-Content -Path $commonCipherSuites | Measure-Object -Line
$count = $countCiphers | Select-Object -ExpandProperty Lines
Write-Host "Cipher Suite comparison complete `n
There were " $count "Cipher Suites loaded that are supported by the manager and Operating System. `n"
Write-Host "Please review the CommonCipherSuites.csv file. `n
Make sure at least 3 of the Cipher Suites listed are at the top of the list in SystemCipherSuites.txt."

##Extracting registry keys from SCHANNEL:

Write-Host "`n###Extracting SCHANNEL configuration###" -BackgroundColor White -ForegroundColor Black
& reg export "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL" $outputFolder\\schannel.txt

##Extracting registry keys from local policy:

Write-Host "`n###Extracting Ciphers pushed by local group policy###" -BackgroundColor White -ForegroundColor Black
& reg export "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL" $outputFolder\\local_policy.txt
& reg export "HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Policies\Microsoft\Cryptography\Configuration\SSL" $outputFolder\\local_policy_Wow6432Node.txt

###################################
##Checking environmental facotrs ##
###################################

## Retrieving Powershell Version

$Psmajorversion = $PSVersionTable.PSVersion.Major

## Defining TLS 1.2 to be used
if ($Psmajorversion -gt 2)
{
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
}
else
{
[Net.ServicePointManager]::SecurityProtocol =  [Enum]::ToObject([Net.SecurityProtocolType], 3072)
}

[System.Net.WebRequest]::DefaultWebProxy.Credentials = [System.Net.CredentialCache]::DefaultNetworkCredentials

Write-Host "`nChecking environmental factors affecting connectivity."  -BackgroundColor White -ForegroundColor Black

Write-Host "###Attempting DNS Resolution###" -BackgroundColor White -ForegroundColor Black

if (($osKeyValue -like "*Server 2012 R2*") -or ($osKeyValue -like "*Windows 8.1*") -or ($osKeyValue -like "Windows Server 2012*") -or ($osKeyValue -like "*Server 2008 R2*") -or ($osKeyValue -like "*Windows 7*"))
{
[System.Net.Dns]::GetHostEntry($domain_name)
}
else
{
Resolve-DnsName -Name $domain_name
}

#Write-Host "`n####Output of TLS ciphers####" -BackgroundColor White -ForegroundColor Black
#Get-TLSCipherSuite | ft name

Write-Host "`n####Issuing TCP TEST####" -BackgroundColor White -ForegroundColor Black

if (($osKeyValue -like "*Server 2012 R2*") -or ($osKeyValue -like "*Windows 8.1*") -or ($osKeyValue -like "Windows Server 2012*") -or ($osKeyValue -like "*Server 2008 R2*") -or ($osKeyValue -like "*Windows 7*"))
{
        $connection = New-Object System.Net.Sockets.TcpClient($domain_name, 443)
        if ($connection.Connected) { Write-Host "TcpTestSucceeded :  True" 
        } else { Write-Host "TcpTestSucceeded :  False"}
}
else

{
$Test_Netconnection = Test-NetConnection -ComputerName $domain_name -Port 443
Write-Host "TcpTestSucceeded : "$Test_Netconnection.'TcpTestSucceeded'
}


if (($Proxyurl -eq $false) -and ($Psmajorversion -le 2))
{
        Write-Host "`n####Issuing Web Request####" -BackgroundColor White -ForegroundColor Black
        [Net.ServicePointManager]::SecurityProtocol =  [Enum]::ToObject([Net.SecurityProtocolType], 3072)

$url = "https://" + $domain_name
        $webrequest = [System.Net.WebRequest]::Create($url)
        $oldresponse = $webrequest.GetResponse()
        Write-Host "Response:" $oldresponse.StatusCode
}
elseif (($Proxyurl -eq $false) -and ($Psmajorversion -gt 2)) {
        
        Write-Host "`n####Issuing Web Request####" -BackgroundColor White -ForegroundColor Black
    $url = "https://" + $domain_name
    $Response = Invoke-WebRequest -URI $url -UseBasicParsing
    Write-Host "Response:" $Response.'StatusCode' $Response.'StatusDescription'
}
else
{
    Write-Host "`n####Issuing Web Request####" -BackgroundColor White -ForegroundColor Black
    $url = "https://" + $domain_name
    $Response = Invoke-WebRequest -URI $url -UseBasicParsing
    Write-Host "Response:" $Response.'StatusCode' $Response.'StatusDescription'

    Write-Host "`n####Issuing Web Request with PROXY####" -BackgroundColor White -ForegroundColor Black
    $url = "https://" + $domain_name
    $Response = Invoke-WebRequest -URI $url -UseBasicParsing -Proxy $Proxyurl

    Write-Host "Response:" $Response.'StatusCode' $Response.'StatusDescription'
}

Write-Host "`n####Getting Agent Status####" -BackgroundColor White -ForegroundColor Black
$com_object = (New-Object -ComObject 'SentinelHelper.1').GetAgentStatusJSON()
if ($Psmajorversion -gt 2)
{
        $com_object | ConvertFrom-Json | ConvertTo-Json | Write-Host
}
else
{
$com_object | Write-Host
}

Write-Host "`n####Sentinelctl Status output####" -BackgroundColor White -ForegroundColor Black
& $path  status | Out-String

Write-Host "`n####Displaying SentinelOne win32_service####" -BackgroundColor White -ForegroundColor Black
&  Get-WmiObject win32_service | ?{$_.PathName -like '*sentinel*'} | select Name, DisplayName, State, PathName | Out-String

Write-Host "`n####Displaying SentinelOne Win32_SystemDriver####" -BackgroundColor White -ForegroundColor Black
&  Get-WmiObject Win32_SystemDriver | ?{$_.PathName -like '*sentinel*'} | select Name, DisplayName, State, PathName | Out-String

#the above is equivalent of running from cmd : sc query type=all state=all | Findstr /i sentinel*

if($NetshCapture -eq "true" -And $admin -eq $true){
    Write-Host "####Network capture will start####" -BackgroundColor White -ForegroundColor Black
    & netsh trace start capture=yes tracefile=$outputFolder\\pcap.etl
        Write-Host -NoNewline "Attempting to reload the agent: "
    #& $path reload -a -k "1"
        if($CustomPassphrase -eq $null){
        & $path reload -a -k "1"
        } else {
                        Write-Host "CustomPassphrase is being used"
        & $path reload -a -k $CustomPassphrase
        }
        Write-Host "Network capture is in progress please don't quit this window or type any key, it will interrupt the capture" -BackgroundColor Yellow -ForegroundColor Black
        Write-Host "Capture time is " $CaptureInterval " seconds"
        timeout $CaptureInterval | out-null
    & netsh trace stop
}


Stop-Transcript

###################################
##Collecting Data##
###################################

if ($Psmajorversion -lt 5)
{ Write-Host "`nPlease zip the folder" $outputFolder " and send it to support"  -BackgroundColor Yellow -ForegroundColor Black  
}
else
{
& Compress-Archive -Path $outputFolder\ -DestinationPath "$outputArchiveFullName" -Force
Write-Host "`nPlease send the zip file located in" $outputArchiveFullName  -BackgroundColor Green -ForegroundColor Black
}
