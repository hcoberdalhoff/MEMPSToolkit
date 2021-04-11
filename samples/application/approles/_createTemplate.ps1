# Dump app role assignments of a given service principal
$template  = Get-ServicePrincipalAppRoleAssignmentsById -id "..."
$template | Select-Object -Property resourceId,appRoleId |  ForEach-Object { $_ | ConvertTo-Json -Depth 6 > ($_.appRoleId + ".json") }
