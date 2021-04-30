Get-ChildItem -Path "*.json" | ForEach-Object { 
    # Import File to policy object
    $object = Import-PolicyObject -filename $_.Name; 
    # Create new policy (in Intune) from policy object
    Add-ConditionalAccessPolicy -policy $object 
}
