Get-ChildItem -Path "*.json" | ForEach-Object { 
    $object = Import-PolicyObject -filename $_.Name; 
    $result = Add-DeviceConfiguration -config $object; 
    Assign-DeviceConfigurationToGroup -configId $result.id -TargetGroupName "MEMTestGroupInclude" 
}
