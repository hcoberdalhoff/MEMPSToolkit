# Dump app role assignments of a given service principal
$template  = Get-ServicePrincipalAppRoleAssignmentsById -id "7cb73b7a-09f7-4561-9b38-0ca603b78975"
$template | Select-Object -Property resourceId,appRoleId |  % { $_ | ConvertTo-Json -Depth 6 > ($_.appRoleId + ".json") }
