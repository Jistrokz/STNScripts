#PS1
#"STN-TheScrapper - Windows"
#__author__ = "Kartavya Trivedi"
#__version__ = "1.0"
#__date__ = "2021-12-15"


Write-Host "____ ___ _  _    _ _  _ ____          ___ _  _ ____ ____ ____ ____ ____ ___  ___  ____ ____ " -ForegroundColor Green
Write-Host "[__   |  |\ |    | |\ | |       __     |  |__| |___ [__  |    |__/ |__| |__] |__] |___ |__/ " -ForegroundColor Green
Write-Host "___]  |  | \|    | | \| |___           |  |  | |___ ___] |___ |  \ |  | |    |    |___ |  \ " -ForegroundColor Green
Write-Host " "
Write-Host "  Version 1.0, Kartavya Trivedi" -ForegroundColor Green

Get-ChildItem 'C:\' -rec -force -include *.jar -ea 0 | ForEach-Object {select-string "JndiLookup.class" $_} | Select-Object -exp Path
#powershell.exe -encoded ZwBjAGkAIAAnAEMAOgBcACcAIAAtAHIAZQBjACAALQBmAG8AcgBjAGUAIAAtAGkAbgBjAGwAdQBkAGUAIAAqAC4AagBhAHIAIAAtAGUAYQAgADAAIAB8ACAAZgBvAHIAZQBhAGMAaAAgAHsAcwBlAGwAZQBjAHQALQBzAHQAcgBpAG4AZwAgACcASgBuAGQAaQBMAG8AbwBrAHUAcAAuAGMAbABhAHMAcwAnACAAfQAgAHwAIABzAGUAbABlAGMAdAAgAC0AZQB4AHAAIABQAGEAdABoAA==
#$EncodedCommand = "Z2NpICdDOlwnIC1yZWMgLWZvcmNlIC1pbmNsdWRlICouamFyIC1lYSAwIHwgZm9yZWFjaCB7c2VsZWN0LXN0cmluZyAiSm5kaUxvb2t1cC5jbGFzcyIgJF99IHwgc2VsZWN0IC1leHAgUGF0aA=="
#gci 'C:\' -rec -force -include *.jar -ea 0 | foreach {select-string "JndiLookup.class" $_} | select -exp Path

#Let's scan the drivers for the presence of Log4jjar files
Add-Type -AssemblyName System.IO.Compression
Add-Type -AssemblyName System.IO.Compression.FileSystem
$TheScrapper_LogFolder = "C:\"
$TheScrapper_log4jCsv = "$TheScrapper_LogFolder\log4j.csv"
$TheScrapper_TargetManifestFile = "$TheScrapper_LogFolder\log4j-manifest.txt"
$TheScrapper_ManifestCsv = "$TheScrapper_LogFolder\log4j-manifest.csv"
$jndiCsv = "$TheScrapper_LogFolder\log4j-jndi.csv"
$log4Filter = "log4j*.jar"
$jarFiles = Get-PSDrive | Where-Object { $_.Name.length -eq 1 } | Select-Object -ExpandProperty Root | Get-ChildItem -File -Recurse -Filter $log4Filter -ErrorAction SilentlyContinue | Select-Object -ExpandProperty FullName
$jarFiles | Export-Csv $TheScrapper_log4jCsv
$global:result = $null
foreach ($jarFile in $jarFiles) {
    Write-Output $jarFile
    $zip = [System.IO.Compression.ZipFile]::OpenRead($jarFile)
    $zip.Entries | 
    Where-Object { $_.Name -like 'JndiLookup.class' } | ForEach-Object {  
        $output = "$($jarFile.ToString()),$($_.FullName)"      
        Write-Output $output
        $output | Out-File -Append $jndiCsv        
        if ($null -eq $global:result) { $global:result = "Jndi class exists" }        
    }
    $zip.Entries | 
    Where-Object { $_.FullName -eq 'META-INF/MANIFEST.MF' } | ForEach-Object {        
        [System.IO.Compression.ZipFileExtensions]::ExtractToFile($_, $TheScrapper_TargetManifestFile, $true)
        $implementationVersion = (Get-Content $TheScrapper_TargetManifestFile | Where-Object { $_ -like 'Implementation-Version: *' }).ToString()
        Write-Output $implementationVersion
        "$($jarFile.ToString()),$($implementationVersion.ToString())" | Out-File -Append $TheScrapper_ManifestCsv   
        Remove-Item $TheScrapper_TargetManifestFile -ErrorAction SilentlyContinue
        $implementationVersion_ = $implementationVersion.Replace('Implementation-Version: ', '').Split('.')
        if ($implementationVersion_[0] -eq 2 -and $implementationVersion_ -lt 15 ) {
            Write-Output "log4shell vulnerability exists"
            $global:result = "Vulnerable"
        }
    }
    if ($null -eq $global:result) { $global:result = "Jndi class not found" }
}
Write-Output "Result: $global:result"