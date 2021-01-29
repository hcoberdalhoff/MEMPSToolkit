Get-ChildItem -path "*.json" | % { Import-AADGroupFromFile -importFile $_.Name }
