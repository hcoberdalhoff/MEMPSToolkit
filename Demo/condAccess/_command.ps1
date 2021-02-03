Get-ChildItem -Path "*.json" | ForEach-Object { $object = Import-PolicyObject -filename $_.Name; Add-ConditionalAccessPolicy -policy $object }
