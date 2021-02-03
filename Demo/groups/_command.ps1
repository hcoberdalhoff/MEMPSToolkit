Get-ChildItem -path "*.json" | ForEach-Object { Import-AADGroupFromFile -importFile $_.Name }
