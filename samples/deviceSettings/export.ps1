$pols = Get-DeviceConfigurationPolicies
$pols | ForEach-Object {
    $name = $_.name -replace "[$([RegEx]::Escape([string][IO.Path]::GetInvalidFileNameChars()))]+", "_"
    $pol = Get-DeviceConfigurationPolicySettingsById -id $_.id
    $pol | ConvertTo-Json -Depth 20 > ($name + ".settings.json")
    $_ | ConvertTo-Json -Depth 20 > ($name + ".metadata.json")
}