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

gci 'C:\' -rec -force -include *.jar -ea 0 | foreach {select-string "JndiLookup.class" $_} | select -exp Path
#powershell.exe -encoded ZwBjAGkAIAAnAEMAOgBcACcAIAAtAHIAZQBjACAALQBmAG8AcgBjAGUAIAAtAGkAbgBjAGwAdQBkAGUAIAAqAC4AagBhAHIAIAAtAGUAYQAgADAAIAB8ACAAZgBvAHIAZQBhAGMAaAAgAHsAcwBlAGwAZQBjAHQALQBzAHQAcgBpAG4AZwAgACcASgBuAGQAaQBMAG8AbwBrAHUAcAAuAGMAbABhAHMAcwAnACAAfQAgAHwAIABzAGUAbABlAGMAdAAgAC0AZQB4AHAAIABQAGEAdABoAA==
#$EncodedCommand = "Z2NpICdDOlwnIC1yZWMgLWZvcmNlIC1pbmNsdWRlICouamFyIC1lYSAwIHwgZm9yZWFjaCB7c2VsZWN0LXN0cmluZyAiSm5kaUxvb2t1cC5jbGFzcyIgJF99IHwgc2VsZWN0IC1leHAgUGF0aA=="
#gci 'C:\' -rec -force -include *.jar -ea 0 | foreach {select-string "JndiLookup.class" $_} | select -exp Path