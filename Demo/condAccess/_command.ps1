Get-ChildItem -Path "*.json" | % { $object = Import-PolicyObject -filename $_.Name; Add-ConditionalAccessPolicy -policy $object }
