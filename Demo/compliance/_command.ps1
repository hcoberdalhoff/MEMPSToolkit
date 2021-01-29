Get-ChildItem -Path "*.json" | % { 
    $object = Import-PolicyObject -filename $_.Name ; 
    $result = Add-CompliancePolicy -policy $object -action "block" 
    Assign-CompliancePolicyToGroup -CompliancePolicyId $result.id -TargetGroupName "MEMTestGroupInclude"
}
