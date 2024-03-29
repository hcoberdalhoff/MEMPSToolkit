# Since no custom app exists yet, use device login flow
# Make sure to use the an identity + scopes that allow to create/manage applications. Recommendation: Use "Azure Powershell"
$token = Get-DeviceLoginToken -clientID "..." -tenant "..."
Save-AppLoginToken -authToken $token

# Create ann App registration and service principal
$appDescription = Import-PolicyObject -filename ".\app.json"
$app = Add-AADApp -appObject $appDescription
$sp = Add-ServicePrincipalByAppId -id $app.appId

# Add AppRoleAssignments (App Permissions) from template
Get-ChildItem -Path ".\approles\*.json" | ForEach-Object {
    $permission = Import-PolicyObject -filename $_.FullName
    Add-Member -InputObject $permission -MemberType NoteProperty -Name "principalId" -Value $sp.id
    Add-ServicePrincipalAppRoleAssignment -permissionObject $permission
}

# TODO Currently creating a password / client secret not working interactively
# Please use portal for this step

