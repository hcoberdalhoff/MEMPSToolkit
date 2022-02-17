#TODO: Use "mandatory" parameters

#region Authentication

# Save a Service Principal secret in an encrypted file 
function Export-AppLoginSecret {
    param (
        [Parameter(Mandatory = $true)]
        [string]$clientId,
        [Parameter(Mandatory = $true)]
        [string]$tenant,
        #String or SecureString
        [Parameter(Mandatory = $true)]
        $secretValue,
        $path = "",
        $asDefault = $true
    )

    # Default filename and location
    if ($path -eq "") {
        if ($asDefault) {
            $path = $env:APPDATA + "\MEMPSToolkit_default_login.xml"
        }
        else {
            $path = $env:APPDATA + "\" + $tenant + "_" + $clientId + ".xml"
        }
    }

    if ($null -eq $secretValue) {
        return "Please specify a secret to store"
    }

    # Encrypt secret
    if ($secretValue.GetType().Name -eq "String") {
        $secretValue = ConvertTo-SecureString -String $secretValue -AsPlainText -Force
    }
    elseif ($secretValue.GetType().Name -ne "SecureString") {
        return "Please specify a secret as SecureString or String"
    }

    if (-not (Test-Path -Path $path)) {
        @(
            $clientId,
            $tenant,
            $secretValue
        ) | Export-Clixml -Path $path
    }
    else {
        return ($path + " exists. Will not overwrite")
    }
    Write-Output ("Saved to " + $path)
}

# Load Service Principal secret from an encrypted file and authenticate
function Get-AppLoginFromSavedSecret {
    param (
        $path = $env:APPDATA + "\MEMPSToolkit_default_login.xml",
        [switch]$returnRawToken = $false
    )

    if (-not (test-path -Path $path)) {
        throw "File not found"
    }

    $data = Import-Clixml -Path $path

    $clientId = $data[0]
    $tenant = $data[1]
    $secretValue = [System.Net.NetworkCredential]::new('', $data[2]).Password

    Get-AppLoginToken -tenant $tenant -clientId $clientId -secretValue $secretValue -returnRawToken:$returnRawToken
} 

# Authenticate non-interactively against a service principal / app registration with app permissions. 
# Can be used headless, no libraries needed. Recommended. 
function Get-AppLoginToken {
    param (
        [Parameter(Mandatory = $true)]
        $tenant,
        [Parameter(Mandatory = $true)]
        $clientId,
        [Parameter(Mandatory = $true)]
        $secretValue,
        [switch]$returnRawToken = $false,
        [int]$version = 2
    )

    # Which version of the auth. endpoint to use?
    if ($version -eq 2) {
        $LoginRequestParams = @{
            Method = 'POST'
            Uri    = "https://login.microsoftonline.com/" + $tenant + "/oauth2/v2.0/token"
            Body   = @{ 
                grant_type    = "client_credentials"; 
                scope         = "https://graph.microsoft.com/.default"; #v2.0 needs a scope
                client_id     = $clientId; 
                client_secret = $secretValue 
            }
        }
    }
    else {
        $LoginRequestParams = @{
            Method = 'POST'
            Uri    = "https://login.microsoftonline.com/" + $tenant + "/oauth2/token?api-version=1.0"
            Body   = @{ 
                grant_type    = "client_credentials"; 
                resource      = "https://graph.microsoft.com"; #v1.0 needs a resource
                client_id     = $clientId; 
                client_secret = $secretValue 
            }
        }
    }
    try {
        $result = Invoke-RestMethod @LoginRequestParams
    }
    catch {
        #Write-Output ("StatusCode:" + $_.Exception.Response.StatusCode.value__ ) 
        #Write-Output ("StatusDescription:" + $_.Exception.Response.StatusDescription)
        #Write-Output ("Message: " + $_.Exception.Message)
        #Write-Output ("Inner Error: " + $_.ErrorDetails.Message)
        Write-Error $_
        throw "Login with MS Graph API failed. See Error Log."
    }

    # If you want to use the token otherwise (e.g. Connect-MgGraph)
    if ($returnRawToken) {
        return $result.access_token
    }
    else {
        if ($version -eq 2) {
            return @{
                'Content-Type'  = 'application/json'
                'Authorization' = "Bearer " + $result.access_token
                #'ExpiresOn'     = $result.expires_on # Not available in v2.0 endpoint
            }    
        }
        else {
            return @{
                'Content-Type'  = 'application/json'
                'Authorization' = "Bearer " + $result.access_token
                'ExpiresOn'     = $result.expires_on
            }
        }
    }
}

# Can be used in Azure Automation Runbooks to authenticate using a runbooks's stored credentials
function Get-AzAutomationCredLoginToken {
    param (
        $resource = "https://graph.microsoft.com",
        [Parameter(Mandatory = $true)]
        $tenant,
        $automationCredName = "RunbookStoredCred"
    )

    $cred = Get-AutomationPSCredential -Name $automationCredName
    $clientId = $cred.UserName
    $secrectValue = [System.Net.NetworkCredential]::new('', $cred.Password).Password

    return (Get-AppLoginToken -resource $resource -tenant $tenant -clientId $clientId -secretValue $secrectValue)
}

# Store a current token as default token in an encrypted file. 
function Export-AppLoginToken {
    param (
        [Parameter(Mandatory = $true)]
        $authToken,
        $path = $env:APPDATA + "\MEMPSToolkit_default_token.xml",
        [bool]$overwrite = $true
    )

    if ($null -eq $authToken) {
        throw "Please provide an AuthToken object."
    }

    $encToken = ConvertTo-SecureString -String $authToken.Authorization -AsPlainText -Force

    if (Test-Path -Path $path) {
        if ($overwrite) {
            Remove-Item -Path $path           
        }
        else {
            return "File " + $path + " exists. Will not overwrite."
        }
    }

    $encToken | Export-Clixml -Path $path
}

# Load the default token from an encrypted file
function Import-AppLoginToken {
    param(
        $path = $env:APPDATA + "\MEMPSToolkit_default_token.xml"
    )
    if (-not (Test-Path -Path $path)) {
        # Well, nothing there. 
        return $null
    } 

    $encToken = Import-Clixml -Path $path

    $token = @{
        "Content-Type"  = "application/json"
        "Authorization" = [System.Net.NetworkCredential]::new('', $encToken).Password
    }

    return $token
}

function Remove-AppLoginToken {
    param(
        $path = $env:APPDATA + "\MEMPSToolkit_default_token.xml"
    )

    if (Test-Path -Path $path) {
        Remove-Item -Path $path
    }
    else {
        return "File " + $path + " does not exists."
    }

}

# Interactively sign in using "device login flow". No libraries or GUI needed.
# Adapted from https://github.com/microsoftgraph/powershell-intune-samples
function Get-DeviceLoginToken {

    <#
    .SYNOPSIS
    This function is used to authenticate with the Graph API REST interface
    .DESCRIPTION
    The function authenticates with the Graph API Interface with the tenant name given using the OAUTH DeviceLogin flow.
    .EXAMPLE
    Get-DeviceLoginToken
    Authenticates you with the Graph API interface
    .NOTES
    NAME: Get-DeviceLoginToken
    #>
    
    [cmdletbinding()]
    
    param (
        [Parameter(Mandatory = $true)]
        $clientID,
        [Parameter(Mandatory = $true)]
        $tenant,
        $resource = "https://graph.microsoft.com",
        $scope = "https://graph.microsoft.com/.default https://graph.microsoft.com/Policy.Read.All"
    )

    $DeviceCodeRequestParams = @{
        Method = 'POST'
        Uri    = "https://login.microsoftonline.com/$tenant/oauth2/devicecode"
        Body   = @{
            client_id = $clientId
            resource  = $resource
        }
    }

    $DeviceCodeRequest = Invoke-RestMethod @DeviceCodeRequestParams
    Write-Host $DeviceCodeRequest.message -ForegroundColor Yellow
    Write-Host "Hit Enter when done signing in"
    Read-Host | Out-Null

    $TokenRequestParams = @{
        Method = 'POST'
        Uri    = "https://login.microsoftonline.com/$tenant/oauth2/token"
        Body   = @{
            grant_type = "urn:ietf:params:oauth:grant-type:device_code"
            code       = $DeviceCodeRequest.device_code
            client_id  = $ClientId
            scope      = $scope
        }
    }
    $TokenRequest = Invoke-RestMethod @TokenRequestParams

    $authHeader = @{
        'Content-Type'  = 'application/json'
        'Authorization' = "Bearer " + $TokenRequest.access_token
        'ExpiresOn'     = $TokenRequest.expires_on
    }

    return $authHeader
   
}

# Convert/Load a raw bearer token into an authHeader token.
function New-AppLoginToken {
    param(
        [Parameter(Mandatory = $true)]
        [string]$rawToken
    )

    $authHeader = @{
        'Content-Type'  = 'application/json'
        'Authorization' = "Bearer " + $rawToken
    }

    return $authHeader
}

#endregion Authentication

#region Basic API and File interaction

# Standardize Graph API calls / Trigger a REST-Call against MS Graph API and return the result 
function Invoke-GraphRestRequest {
    param (
        $method = "GET",
        $prefix = "https://graph.microsoft.com/v1.0/",
        $resource = "users",
        $body = $null,
        $authToken = $null,
        $onlyValues = $true,
        $writeToFile = $false,
        $outFile = "MSGraphOutput.json"
    )
    
    if ($null -eq $authToken) {
        $authToken = Import-AppLoginToken
        if ($null -eq $authToken) {
            "Please provide an authentication token. You can use Get-DeviceLoginToken to acquire one."
        }
    }

    if ($prefix -eq "v1.0") {
        $prefix = "https://graph.microsoft.com/v1.0/"
    }
    elseif ($prefix -eq "beta") {
        $prefix = "https://graph.microsoft.com/beta/"
    }

    try {
        if ($writeToFile) {
            # TODO: Handle paging
            $result = Invoke-RestMethod -Uri ($prefix + $resource) -Headers $authToken -Method $method -Body $body -ContentType "application/json" -OutFile $outfile
        }
        else {
            $result = Invoke-RestMethod -Uri ($prefix + $resource) -Headers $authToken -Method $method -Body $body -ContentType "application/json"

            # Handle Paging
            $newresult = $result
            while ($newresult.PSObject.Properties.Name -contains "@odata.nextLink") {
                # actively ignore other parameters
                $newresult = Invoke-RestMethod -Uri ($newresult."@odata.nextLink") -Headers $authToken -Method $method -ContentType "application/json"
                $result.value += $newresult.value
            }
        }
    }
    catch {
        Write-Output ("StatusCode:" + $_.Exception.Response.StatusCode.value__ ) 
        Write-Output ("StatusDescription:" + $_.Exception.Response.StatusDescription)
        Write-Output ("Message: " + $_.Exception.Message)
        Write-Output ("Inner Error: " + $_.ErrorDetails.Message)
        Write-Error $_
        throw "Executing Graph Rest Call against " + $prefix + $resource + " failed. See Error Log."
    }

    if ($onlyValues) {
        return $result.Value
    }
    else {
        return $result
    }

}

# Write a JSON file from a Policy / group description object
function Export-PolicyObjects {
    param (
        [Parameter(Mandatory = $true)]
        [array]$policies
    )

    $policies | ForEach-Object {
        $name = $_.displayName -replace "[$([RegEx]::Escape([string][IO.Path]::GetInvalidFileNameChars()))]+", "_"
        if (-not (Test-Path ($name + ".json"))) {
            $_ | ConvertTo-Json -Depth 6 > ($name + ".json")
        }
        else {
            "Will not overwrite " + ($name + ".json") + ". Skipping."
        }
     
    }

}

# Load a Policy / group description object from a JSON file
function Import-PolicyObject {
    param (
        [Parameter(Mandatory = $true)]
        $filename
    )

    $JSON_Convert = Get-Content -Raw -Path $filename | ConvertFrom-Json -Depth 6

    return $JSON_Convert
}

#endregion 

#region AAD group management

function Get-AADGroups {
    param(
        $authToken = $null,
        $prefix = "https://graph.microsoft.com/V1.0/"
    )

    $resource = "groups"

    Invoke-GraphRestRequest -method "GET" -prefix $prefix -resource $resource -authToken $authToken
}

function Add-AADGroupFromObject {
    param(
        $authToken = $null,
        [Parameter(Mandatory = $true)]
        $groupObject = $null
    )

    if ($null -eq $groupObject) {
        return "Please provide a AAD group description object containing at least displayName, mailNickname, securityEnabled, mailEnabled properties" 
    }

    Add-AADGroup -mailNickName $groupObject.mailNickname -displayName $groupObject.displayName -securityEnabled $groupObject.securityEnabled -mailEnabled $groupObject.mailEnabled
}
function Add-AADGroup {
    param(
        $authToken = $null,
        [Parameter(Mandatory = $true)]
        $displayName,
        [Parameter(Mandatory = $true)]
        $mailNickName,
        $prefix = "https://graph.microsoft.com/V1.0/",
        $securityEnabled = "true",
        $mailEnabled = "false"
    )

    $resource = "groups"

    $groupDescription = @{
        displayName     = $displayName
        mailNickname    = $mailNickName
        securityEnabled = $securityEnabled
        mailEnabled     = $mailEnabled
    }

    $JSON = $groupDescription | ConvertTo-Json -Depth 6

    Invoke-GraphRestRequest -method "POST" -prefix $prefix -resource $resource -authToken $authToken -body $JSON -onlyValues $false
}

function Get-AADGroupById {
    param(
        $authToken = $null,
        $prefix = "https://graph.microsoft.com/V1.0/",
        [Parameter(Mandatory = $true)]
        $groupId = ""
    )

    $resource = "groups"

    Invoke-GraphRestRequest -method "GET" -prefix $prefix -resource ($resource + "/" + $groupId) -authToken $authToken -onlyValues $false
}

function Get-AADGroupByName {
    param(
        $authToken = $null,
        $prefix = "https://graph.microsoft.com/V1.0/",
        [Parameter(Mandatory = $true)]
        $groupName = $null
    )

    $resource = "groups"

    Invoke-GraphRestRequest -method "GET" -prefix $prefix -resource ($resource + "?`$filter=displayName eq `'" + $groupName + "`'") -authToken $authToken -onlyValues $true
}

function Add-AADGroupFromFile {
    param(
        $importFile = "group.json",
        $authToken = $null
    )

    if (-not (Test-Path -Path $importFile)) {
        return     'Please provide a group description file as JSON, like:
{
    "mailNickname": "MEMTestGroup",
    "displayName": "MEMTestGroup",
    "mailEnabled": "false",
    "securityEnabled": "true"
}'
    }

    $groupData = Get-Content -Raw -Path $importFile | ConvertFrom-Json -Depth 6

    $group = Get-AADGroupByName -authToken $authToken -groupName $groupData.displayName

    if ($null -eq $group) {
        Add-AADGroup -authToken $authToken -displayName $groupData.displayName -mailNickName $groupData.mailNickname -securityEnabled $groupData.securityEnabled -mailEnabled $groupData.mailEnabled
    }
    else {
        "Group " + $groupData.displayName + " exists. Will skip. "
    }

}

function Update-AADGroupById {
    param(
        $authToken = $null,
        $prefix = "https://graph.microsoft.com/V1.0/",
        [Parameter(Mandatory = $true)]
        $groupId = "",
        $valuePairs = @{}
    )

    $resource = "groups/$groupId"

    $body = $valuePairs | ConvertTo-Json

    Invoke-GraphRestRequest -method "PATCH" -prefix $prefix -resource $resource -authToken $authToken -onlyValues $false -body $body
}

function Get-AADGroupMembers {
    param (
        [Parameter(Mandatory = $true)]
        $groupID,
        $authToken = $null,
        $prefix = "https://graph.microsoft.com/V1.0/"
    )

    $resource = "groups"

    Invoke-GraphRestRequest -method "GET" -prefix $prefix -resource ($resource + "/" + $groupID + "/members") -authToken $authToken -onlyValues $true
}

function Add-AADGroupMember {
    param(
        [Parameter(Mandatory = $true)]
        $groupID,
        [Parameter(Mandatory = $true)]
        $userID,
        $authToken = $null,
        $prefix = "https://graph.microsoft.com/V1.0/"
    )

    $resource = "groups"

    $body = @"
{
    "@odata.id": "https://graph.microsoft.com/v1.0/directoryObjects/$userID"
}
"@

    Invoke-GraphRestRequest -method "POST" -prefix $prefix -resource ($resource + "/" + $groupID + "/members/`$ref") -body $body -authToken $authToken -onlyValues $false
}

function Remove-AADGroupMember {
    param(
        [Parameter(Mandatory = $true)]
        $groupID,
        [Parameter(Mandatory = $true)]
        $userID,
        $authToken = $null,
        $prefix = "https://graph.microsoft.com/V1.0/"
    )

    $resource = "groups"

    Invoke-GraphRestRequest -method "DELETE" -prefix $prefix -resource ($resource + "/" + $groupID + "/members/" + $userID + "/`$ref") -authToken $authToken -onlyValues $false
}


#endregion 

#region devices
function Get-AADDevices {
    param (
        [string]$deviceId,
        $authToken = $null,
        [string]$prefix = "https://graph.microsoft.com/V1.0/"
    )
    
    $resource = "devices"

    if ($deviceId) {
        $resource = $resource + "?`$filter=deviceId eq '" + $deviceId + "`'"
    }

    Invoke-GraphRestRequest -method "GET" -prefix $prefix -resource $resource -authToken $authToken -onlyValues $true
}

# Be aware - Only work with "delegated" permissions
function Disable-AADDevice {
    param (
        [Parameter(Mandatory = $true)]
        [string] $ObjectId,
        $authToken = $null,
        [string]$prefix = "https://graph.microsoft.com/V1.0/"
    )

    $resource = "devices/$ObjectId"

    $body = @{"accountEnabled" = $false } | ConvertTo-Json

    Invoke-GraphRestRequest -method "PATCH" -prefix $prefix -resource $resource -authToken $authToken -body $body -onlyValues $false

}

function Remove-AADDevice {
    param (
        [Parameter(Mandatory = $true)]
        [string] $ObjectId,
        $authToken = $null,
        [string]$prefix = "https://graph.microsoft.com/V1.0/"
    )

    $resource = "devices/$ObjectId"

    Invoke-GraphRestRequest -method "DELETE" -prefix $prefix -resource $resource -authToken $authToken -onlyValues $false

}

#endregion

#region AuthMethods

function Get-AADUserAuthMethods {
    param (
        $authToken = $null,
        [Parameter(Mandatory = $true)]
        [string] $userID,
        $prefix = "https://graph.microsoft.com/V1.0/"
    )

    $resource = "users"

    Invoke-GraphRestRequest -method "GET" -prefix $prefix -resource ($resource + "/" + $userID + "/authentication/methods") -authToken $authToken -onlyValues $true
    
}

function Get-AADUserMSAuthenticatorMethods {
    param (
        $authToken = $null,
        [Parameter(Mandatory = $true)]
        [string] $userID,
        $prefix = "https://graph.microsoft.com/V1.0/"
    )

    $resource = "users"

    Invoke-GraphRestRequest -method "GET" -prefix $prefix -resource ($resource + "/" + $userID + "/authentication/microsoftAuthenticatorMethods") -authToken $authToken -onlyValues $true
    
}

# These currently only work in "beta"
function Get-AADUserPhoneAuthMethods {
    param (
        $authToken = $null,
        [Parameter(Mandatory = $true)]
        [string] $userID,
        $prefix = "https://graph.microsoft.com/beta/"
    )

    $resource = "users"

    Invoke-GraphRestRequest -method "GET" -prefix $prefix -resource ($resource + "/" + $userID + "/authentication/phoneMethods") -authToken $authToken -onlyValues $true
   
}


function Remove-AADUserMSAuthenticatorMethod {
    param (
        $authToken = $null,
        [Parameter(Mandatory = $true)]
        [string] $userID,
        [Parameter(Mandatory = $true)]
        [string] $authId,
        $prefix = "https://graph.microsoft.com/V1.0/"
    )

    $resource = "users"
    
    Invoke-GraphRestRequest -method "DELETE" -prefix $prefix -resource ($resource + "/" + $userID + "/authentication/microsoftAuthenticatorMethods/" + $authId) -authToken $authToken -onlyValues $true
}

# Currently only works in "beta"
function Remove-AADUserPhoneAuthMethod {
    param (
        $authToken = $null,
        [Parameter(Mandatory = $true)]
        [string] $userID,
        [Parameter(Mandatory = $true)]
        [string] $authId,
        $prefix = "https://graph.microsoft.com/beta/"
    )

    $resource = "users"
    
    Invoke-GraphRestRequest -method "DELETE" -prefix $prefix -resource ($resource + "/" + $userID + "/authentication/phoneMethods/" + $authId) -authToken $authToken -onlyValues $true
}

# Currently only works with beta endpoint
# Will fail if a phoneAuthMethod already exists.
# TODO: support "alternateMobile" phoneType?
function Add-AADUserPhoneAuthMethod {
    param (
        $authToken = $null,
        [Parameter(Mandatory = $true)]
        [string] $userID,
        [Parameter(Mandatory = $true)]
        [string] $phoneNumber,
        $prefix = "https://graph.microsoft.com/beta/"
    )

    $resource = "users"

    # Check if a phoneAuthMethod already exists
    $method = Get-AADUserPhoneAuthMethods -userID $userID -authToken $authToken
    if ($method) {
        throw "User already has a phoneAuthMethod."
    }

    $body = @"
{
  "phoneNumber": "$phoneNumber",
  "phoneType": "mobile"
}
"@
    Invoke-GraphRestRequest -method "POST" -prefix $prefix -resource ($resource + "/" + $userID + "/authentication/phoneMethods") -body $body -authToken $authToken -onlyValues $true
}

# Currently only works in "beta"
# Will update a phoneAuthenticationMethod to a new phone number
function Update-AADUserPhoneAuthMethod {
    param (
        $authToken = $null,
        [Parameter(Mandatory = $true)]
        [string] $userID,
        [string] $authId = $null,
        [Parameter(Mandatory = $true)]
        [string] $phoneNumber,
        $prefix = "https://graph.microsoft.com/beta/",
        [bool]$createIfNeeded = $false
    )

    # If no authId is given, update primary one.
    if (-not $authId) {
        $method = Get-AADUserPhoneAuthMethods -userID $userID -authToken $authToken
        if ($method) {
            $authId = ($method | Where-Object { $_.phoneType -eq "mobile" }).id
        }
        else {
            Write-Output "No phoneAuthMethod exists."
            if ($createIfNeeded) {
                Write-Output "Adding as new phoneAuthMethod."
                Add-AADUserPhoneAuthMethod -authToken $authToken -userID $userID -phoneNumber $phoneNumber
                return
            }
            else {
                throw "Can not update a non existing phoneAuthMethod. "
            }
            
        }
    }

    $resource = "users"

    $body = @"
{
  "phoneNumber": "$phoneNumber",
  "phoneType": "mobile"
}
"@
    
    Invoke-GraphRestRequest -method "PUT" -prefix $prefix -resource ($resource + "/" + $userID + "/authentication/phoneMethods/" + $authId) -body $body -authToken $authToken -onlyValues $true
}

# This will reset a user's password. The new password will be returned in clear text(!). The user should immediately change that password.
#
# Currently only available in MS Graph BETA Api
function Get-AADUserPasswordAuthMethods {
    param (
        $authToken = $null,
        [Parameter(Mandatory = $true)]
        [string] $userID,
        $prefix = "https://graph.microsoft.com/beta/"
    )

    $resource = "users"

    Invoke-GraphRestRequest -method "GET" -prefix $prefix -resource ($resource + "/" + $userID + "/authentication/passwordMethods") -authToken $authToken -onlyValues $true
}

function Update-AADUserProperty {
    param (
        $authToken = $null,
        [Parameter(Mandatory = $true)]
        [string] $userID,
        [Parameter(Mandatory = $true)]
        [string] $property,
        # Can be a string or array
        [Parameter(Mandatory = $true)]
        $value,
        $prefix = "https://graph.microsoft.com/v1.0/"
    )

    $resource = "users"

    $body = (@{$property = $value } | ConvertTo-Json -Depth 6)

    Invoke-GraphRestRequest -method "PATCH" -prefix $prefix -body $body -resource ($resource + "/" + $userID) -authToken $authToken -onlyValues $false

}

# This will reset a user's password. The new password will be returned in clear text(!). The user should immediately change that password.
#
# Currently only available in MS Graph BETA Api
# Currently not supported using AppPermissions, only in delegated operation.
function Reset-AADUserPasswordAuthMethod {
    param (
        $authToken = $null,
        [Parameter(Mandatory = $true)]
        [string] $userID,
        $prefix = "https://graph.microsoft.com/beta/"
    )
    
    # Let us assume there is only one password per user, as described in https://docs.microsoft.com/en-us/graph/api/authentication-list-passwordmethods?view=graph-rest-beta&tabs=http
    $method = Get-AADUserPasswordAuthMethods -authToken $authToken -userID $userID -prefix $prefix
    if (-not $method) {
        throw "No password auth method found. Is this a regular user?"
    }

    # Can not operate on blocked users. Check!
    if (-not (get-AADUserIsEnabled -authToken $authToken -userId $userID)) {
        # Make sure, user is enabled
        update-AADUserProperty -userID $userID -property "accountEnabled" -value "True" -authToken $authToken
    }

    $resource = "users"
    
    Invoke-GraphRestRequest -method "POST" -prefix $prefix -resource ($resource + "/" + $userID + "/authentication/passwordMethods/" + $method.id + "/resetPassword") -authToken $authToken -onlyValues $true
}

# Currently only possible with beta API
function Get-AADUserTemporaryAccessPass {
    param (
        $authToken = $null,
        [Parameter(Mandatory = $true)]
        [string] $userID,
        $prefix = "https://graph.microsoft.com/beta/"
    )

    $resource = "users"

    Invoke-GraphRestRequest -method "GET" -prefix $prefix -resource ($resource + "/" + $userID + "/authentication/temporaryAccessPassMethods") -authToken $authToken -onlyValues $true
}

# Currently only possible with beta API
function Remove-AADUserTemporaryAccessPass {
    param (
        $authToken = $null,
        [Parameter(Mandatory = $true)]
        [string] $userID,
        $prefix = "https://graph.microsoft.com/beta/"
    )

    # Current assumption: A user can only have one temp. access pass. But well, be safe.
    $authId = Get-AADUserTemporaryAccessPass -authToken $authToken -userID $userID -prefix $prefix

    $resource = "users"

    $authId | ForEach-Object {
        Invoke-GraphRestRequest -method "DELETE" -prefix $prefix -resource ($resource + "/" + $userID + "/authentication/temporaryAccessPassMethods/" + $_.id) -authToken $authToken -onlyValues $true
    }

}

# Currently only possible with beta API
# Currently does not implement "delayed start time"
function New-AADUserTemporaryAccessPass {
    param (
        $authToken = $null,
        [Parameter(Mandatory = $true)]
        [string] $userID,
        [bool] $oneTimeUse = $false,
        [int]$lifetimeInMinutes = "120",
        $prefix = "https://graph.microsoft.com/beta/"
    )

    # Make sure no other temp. access pass exists
    Remove-AADUserTemporaryAccessPass -authToken $authToken -userID $userID -prefix $prefix

    $resource = "users"

    $body = @{
        "@odata.type"       = "#microsoft.graph.temporaryAccessPassAuthenticationMethod";
        "lifetimeInMinutes" = $lifetimeInMinutes;
        "isUsableOnce"      = $oneTimeUse
    }

    $json = $body | ConvertTo-Json -Depth 6

    Invoke-GraphRestRequest -method "POST" -prefix $prefix -resource ($resource + "/" + $userID + "/authentication/temporaryAccessPassMethods") -body $json -authToken $authToken -onlyValues $false

}

#endregion

#region identityProtection

function Get-RiskyUsers {
    param(
        $authToken = $null,
        $prefix = "https://graph.microsoft.com/v1.0"
    )

    $resource = "/identityProtection/riskyUsers"

    Invoke-GraphRestRequest -method "GET" -prefix $prefix -resource $resource -authToken $authToken -onlyValues $true
}

function Set-DismissRiskyUser {
    param(
        $authToken = $null,
        [Parameter(Mandatory = $true)]
        [string]$userId, 
        $prefix = "https://graph.microsoft.com/v1.0"
    )

    $resource = "/identityProtection/riskyUsers/dismiss"

    $body = (@{ "userIds" = ([array]$userId) } | ConvertTo-Json -Depth 6 )
    
    Invoke-GraphRestRequest -method "POST" -prefix $prefix -resource $resource -body $body -authToken $authToken -onlyValues $false
}

function Set-ConfirmCompromisedRiskyUser {
    param(
        $authToken = $null,
        [Parameter(Mandatory = $true)]
        [string]$userId, 
        $prefix = "https://graph.microsoft.com/v1.0"
    )

    $resource = "/identityProtection/riskyUsers/confirmCompromised"

    $body = (@{ "userIds" = ([array]$userId) } | ConvertTo-Json -Depth 6 )
    
    Invoke-GraphRestRequest -method "POST" -prefix $prefix -resource $resource -body $body -authToken $authToken -onlyValues $false
}
#endregion

#region Users


function Get-AADUsers {
    param(
        $authToken = $null,
        $prefix = "https://graph.microsoft.com/V1.0/"
    )

    $resource = "users"

    Invoke-GraphRestRequest -method "GET" -prefix $prefix -resource $resource -authToken $authToken -onlyValues $true
}

function Get-AADUserIsEnabled {
    param(
        $authToken = $null,
        $prefix = "https://graph.microsoft.com/V1.0/",
        [Parameter(Mandatory = $true)]
        $userId,
        [switch]$WhatIf = $false
    )

    $resource = "users"

    $query = ($resource + "/" + $userID + "?`$select=displayName,accountEnabled")
    if ($WhatIf) { "query: " + $prefix + $query }

    if (-not $WhatIf) {
        $result = Invoke-GraphRestRequest -method "GET" -prefix $prefix -resource $query -authToken $authToken -onlyValues $false
        if ($result.accountEnabled -eq "True") {
            return $true
        }
        else {
            return $false
        }
    }
}

function Get-AADUserByUPN {
    param(
        $authToken = $null,
        $prefix = "https://graph.microsoft.com/V1.0/",
        [Parameter(Mandatory = $true)]
        $userName
    )

    get-AADUserByID -authToken $authToken -prefix $prefix -userID $userName
}

function Get-AADUserByID {
    param(
        $authToken = $null,
        $prefix = "https://graph.microsoft.com/V1.0/",
        [Parameter(Mandatory = $true)]
        [string]$userID
    )

    $resource = "users"

    Invoke-GraphRestRequest -method "GET" -prefix $prefix -resource ($resource + "/" + $userID ) -authToken $authToken -onlyValues $false
}

function Remove-AADUserById {
    param(
        $authToken = $null,
        $prefix = "https://graph.microsoft.com/V1.0/",
        [Parameter(Mandatory = $true)]
        [string]$userID,
        [switch]$force = $false
    )

    $resource = "users"

    # Be really sure about this one.
    if ($force) {
        Invoke-GraphRestRequest -method "DELETE" -prefix $prefix -resource ($resource + "/" + $userID ) -authToken $authToken -onlyValues $false
    }
    else {
        "No action taken. Use -force to enforce a user deletion."
    }
}

#endregion

#region Compliance Policies

function Get-CompliancePolicies {
    param (
        $authToken = $null,
        $prefix = "https://graph.microsoft.com/Beta/",
        $resource = "deviceManagement/deviceCompliancePolicies"
        
    )

    Invoke-GraphRestRequest -authToken $authToken -prefix $prefix -resource $resource -method "GET"   
   
}

function Get-CompliancePolicyByName {
    param (
        $authToken = $null,
        $policyName = $null
    )

    $policies = Get-CompliancePolicies -authToken $token

    $policies | Where-Object { $_.displayName -like $policyName }

}

function Add-CompliancePolicy {
    param (
        $policy = $null,
        $authToken = $null,
        $prefix = "https://graph.microsoft.com/Beta/",
        $action = "block",
        $gracePeriodHours = 12
    )

    $resource = "deviceManagement/deviceCompliancePolicies"

    if ($null -eq $policy) {
        "Please provide a Compliance Policy. You can create those using Import-PolicyObject."
        return
    }

    $policy = $policy | Select-Object -Property * -ExcludeProperty id, createdDateTime, lastModifiedDateTime, version

    if ($null -eq $policy.scheduledActionsForRule) {
        # Adding Scheduled Actions Rule to JSON
        Add-Member -InputObject $policy -MemberType NoteProperty -Name "scheduledActionsForRule" -Value $null
        $policy.scheduledActionsForRule = [array]@{
            ruleName                      = "NonCompliantRule1"
            scheduledActionConfigurations = [array]@{
                actionType                = $action
                gracePeriodHours          = $gracePeriodHours
                notificationTemplateId    = ""
                notificationMessageCCList = [array]@()
            }
        }
    }

    $JSON = $policy | ConvertTo-Json -Depth 6

    Invoke-GraphRestRequest -authToken $authToken -prefix $prefix -resource $resource -method "POST" -body $JSON -onlyValues $false
}

#TODO: Currently overwrites all other assignments
function Set-CompliancePolicyToGroupAssignment {
    param (
        $authToken = $null,
        $prefix = "https://graph.microsoft.com/V1.0/",
        $CompliancePolicyId = "",
        $TargetGroupId = "",
        $TargetGroupName = ""
    )

    if ($CompliancePolicyId -eq "") {
        "Please provide a Compliance Policy ID. You get those from the objects returned by Get-CompliancePolicies"
        return
    }

    if (($TargetGroupId -eq "") -and ($TargetGroupName -eq "")) {
        "Please provide an AzureAD group ID or DisplayName. You can get those from the objects returned by Get-AADGroups"
        return
    }

    if ($TargetGroupId -eq "") {
        $TargetGroupId = (Get-AADGroupByName -groupName $TargetGroupName -authToken $authToken).id
    }
 
    $resource = "deviceManagement/deviceCompliancePolicies/$CompliancePolicyId/assign"

    $JSON = @"

    {
        "assignments": [
        {
            "target": {
            "@odata.type": "#microsoft.graph.groupAssignmentTarget",
            "groupId": "$TargetGroupId"
            }
        }
        ]
    }
    
"@

    ##TODO: This should work. Why does it not?
    #$resource = "deviceManagement/deviceCompliancePolicies/" + $CompliancePolicyId + "/assignments"

    #$JSON = '{
    #    "target": {
    #        "@odata.type": "#microsoft.graph.groupAssignmentTarget",
    #        "groupId": "' + $TargetGroupId + '"
    #        }
    #}'


    Invoke-GraphRestRequest -method "POST" -prefix $prefix -resource $resource -body $JSON -authToken $authToken -onlyValues $false

}

#TODO: Currently overwrites all other assignments. Not usefull. Leaving it private for now.
#FIXME
function Set-CompliancePolicyFromGroupExclusion {
    param (
        $authToken = $null,
        $prefix = "https://graph.microsoft.com/V1.0/",
        $CompliancePolicyId = "",
        $TargetGroupId = "",
        $TargetGroupName = ""
    )

    if ($CompliancePolicyId -eq "") {
        "Please provide a Compliance Policy ID. You get those from the objects returned by Get-CompliancePolicies"
        return
    }

    if (($TargetGroupId -eq "") -and ($TargetGroupName -eq "")) {
        "Please provide an AzureAD group ID or DisplayName. You can get those from the objects returned by Get-AADGroups"
        return
    }

    if ($TargetGroupId -eq "") {
        $TargetGroupId = (Get-AADGroupByName -groupName $TargetGroupName -authToken $authToken).id
    }
 
    $resource = "deviceManagement/deviceCompliancePolicies/$CompliancePolicyId/assign"

    $JSON = @"

    {
        "assignments": [
        {
            "target": {
            "@odata.type": "#microsoft.graph.exclusionGroupAssignmentTarget",
            "groupId": "$TargetGroupId"
            }
        }
        ]
    }
    
"@

    Invoke-GraphRestRequest -method "POST" -prefix $prefix -resource $resource -body $JSON -authToken $authToken

}

#endregion 

#region Conditional Access Policies
function Get-ConditionalAccessPolicies {
    param (
        $authToken = $null,
        $prefix = "https://graph.microsoft.com/V1.0/"
    )

    $resource = "identity/conditionalAccess/policies"

    Invoke-GraphRestRequest -method "GET" -prefix $prefix -resource $resource -authToken $authToken
}

function Add-ConditionalAccessPolicy {
    param(
        $authToken = $null,
        $policy = $null,
        $prefix = "https://graph.microsoft.com/V1.0/"
    )

    $resource = "identity/conditionalAccess/policies"

    if ($null -eq $policy) {
        "Please provide a Conditional Access Policy. You can create those using Import-PolicyObject."
        return
    }

    $policy = $policy | Select-Object -Property * -ExcludeProperty id, createdDateTime, lastModifiedDateTime, version

    $JSON = $policy | ConvertTo-Json -Depth 6

    Invoke-GraphRestRequest -authToken $authToken -prefix $prefix -resource $resource -method "POST" -body $JSON -onlyValues $false
}

#TODO: Allow to assign to groups by name

#endregion 

#region Device Configurations

# Get/Fetch all existing Device Configuration Policies (the old ones, not the newer Config Settings)
# Has only been tested with "Beta" endpoint. Retest with "v1.0"
function Get-DeviceConfigurations {
    param(
        $authToken = $null,
        $prefix = "https://graph.microsoft.com/Beta/"
    )

    $resource = "deviceManagement/deviceConfigurations"

    Invoke-GraphRestRequest -authToken $authToken -prefix $prefix -resource $resource -method "GET"

}

# Get/Fetch an existing Device Configuration Policy by its ID (not Config Settings)
# Has only been tested with "Beta" endpoint. Retest with "v1.0"
function Get-DeviceConfigurationById {
    param(
        $authToken = $null,
        $prefix = "https://graph.microsoft.com/Beta/",
        $configId = ""
    )

    $resource = "deviceManagement/deviceConfigurations"

    if ($configId -eq "") {
        "Please provide an Device Configuration UID. You can get those from the results from Get-DeviceConfigurations"
    }

    Invoke-GraphRestRequest -authToken $authToken -prefix $prefix -resource ($resource + "/" + $configId) -method "GET" -onlyValues $false

}

function Get-DeviceConfigurationAssignmentById {
    param(
        $authToken = $null,
        #V1.0 does not support all current data fields...
        $prefix = "https://graph.microsoft.com/Beta/",
        $configId = ""
    )

    $resource = "deviceManagement/deviceConfigurations"

    if ($configId -eq "") {
        "Please provide an Device Configuration UID. You can get those from the results from Get-DeviceConfigurations"
        return
    }

    Invoke-GraphRestRequest -authToken $authToken -prefix $prefix -resource ($resource + "/" + $configId + "/assignments") -method "GET"
}

function Export-DeviceConfigurationsAndAssignments {
    param(
        $authToken = $null,
        $prefix = "https://graph.microsoft.com/Beta/"
    )

    $configs = Get-DeviceConfigurations -authToken $authToken -prefix $prefix

    Export-PolicyObjects -policies $configs

    $configs | ForEach-Object {
        $assignment = Get-DeviceConfigurationAssignmentById -authToken $authToken -prefix $prefix -configId $_.Id
        $name = $_.displayName -replace "[$([RegEx]::Escape([string][IO.Path]::GetInvalidFileNameChars()))]+", "_"
        $filename = $name + "_assignment.json"
        if (test-path -Path $filename) {
            $filename + " exists. Will not overwrite."
        }
        else {
            $assignment | ConvertTo-Json -Depth 6 > $filename
        }
        
    }

}

# Import/Create a new Device Configuration Policy
# TODO: Retest with v1.0
# ... if you can use the newer "Config Settings"...
function Add-DeviceConfiguration {
    param(
        $authToken = $null,
        $prefix = "https://graph.microsoft.com/beta/",
        $config = $null
    )

    $resource = "deviceManagement/deviceConfigurations"

    if ($null -eq $config) {
        "Please provide a Device Configuration. You can create those using Import-PolicyObject."
        return
    }

    $config = $config | Select-Object -Property * -ExcludeProperty id, createdDateTime, lastModifiedDateTime, version

    $JSON = $config | ConvertTo-Json -Depth 6

    Invoke-GraphRestRequest -authToken $authToken -prefix $prefix -resource $resource -method "POST" -body $JSON -onlyValues $false

}

function Set-DeviceConfigurationAssignment {
    param (
        $authToken = $null,
        $prefix = "https://graph.microsoft.com/Beta/",
        $configId = "",
        $target = $null
    )
    
    $resource = "deviceManagement/deviceConfigurations"

    if ($null -eq $target) {
        return "Please provide a target for the device configuration, like #microsoft.graph.allDevicesAssignmentTarget or pass an AssignmentTarget Object"
    }

    if ($configId -eq "") {
        return "Please provide a Device Configuration Id." 
    }

    if ($target.getType().Name -eq "String") {
        $JSON = '{
    "target": {
        "@odata.type": "' + $target + '"
    }        
}'
    }
    else {
        $JSON = $target | ConvertTo-Json -Depth 6 
    }

    Invoke-GraphRestRequest -authToken $authToken -prefix $prefix -resource ($resource + "/" + $configId + "/assignments") -method "POST" -body $JSON -onlyValues $false
}

function Set-DeviceConfigurationAssignmentToGroup {
    param (
        $authToken = $null,
        $prefix = "https://graph.microsoft.com/Beta/",
        $configId = "",
        $TargetGroupId = "",
        $TargetGroupName = ""
    )

    if ($configId -eq "") {
        "Please provide a Device Configuration ID. You get those from the objects returned by Get-DeviceConfigurations."
        return
    }

    if (($TargetGroupId -eq "") -and ($TargetGroupName -eq "")) {
        "Please provide an AzureAD group ID or DisplayName. You can get those from the objects returned by Get-AADGroups"
        return
    }

    if ($TargetGroupId -eq "") {
        $TargetGroupId = (Get-AADGroupByName -groupName $TargetGroupName -authToken $authToken).id
    }
 
    $target = @"
{
    "target": {
    "@odata.type": "#microsoft.graph.groupAssignmentTarget",
    "groupId": "$TargetGroupId"
    }
}
"@ | ConvertFrom-Json -Depth 6

    Set-DeviceConfigurationAssignment -configId $configId -authToken $authToken -prefix $prefix -target $target

}

function Set-DeviceConfigurationFromGroupExclusion {
    param (
        $authToken = $null,
        $prefix = "https://graph.microsoft.com/Beta/",
        $configId = "",
        $TargetGroupId = "",
        $TargetGroupName = ""
    )

    if ($configId -eq "") {
        "Please provide a Device Configuration ID. You get those from the objects returned by Get-DeviceConfigurations."
        return
    }

    if (($TargetGroupId -eq "") -and ($TargetGroupName -eq "")) {
        "Please provide an AzureAD group ID or DisplayName. You can get those from the objects returned by Get-AADGroups"
        return
    }

    if ($TargetGroupId -eq "") {
        $TargetGroupId = (Get-AADGroupByName -groupName $TargetGroupName -authToken $authToken).id
    }
 
    $target = @"
{
    "target": {
    "@odata.type": "#microsoft.graph.exclusionGroupAssignmentTarget",
    "groupId": "$TargetGroupId"
    }
}
"@ | ConvertFrom-Json -Depth 6

    Set-DeviceConfigurationAssignment -configId $configId -authToken $authToken -prefix $prefix -target $target

}

#endregion 

#region Device configurationPolicies / Device Settings (the newer ones, in contrast to the older ConfigProfiles / DeviceConfigurations)
function Get-DeviceConfigurationPolicies {
    param(
        $authToken = $null,
        $prefix = "https://graph.microsoft.com/Beta/"
    )

    $resource = "deviceManagement/configurationPolicies"

    Invoke-GraphRestRequest -authToken $authToken -prefix $prefix -resource $resource -method "GET"

}

function Get-DeviceConfigurationPolicySettingsById {
    param(
        $authToken = $null,
        $prefix = "https://graph.microsoft.com/Beta/",
        $id = ""
    )

    $resource = "deviceManagement/configurationPolicies/" + $id + "/settings"

    Invoke-GraphRestRequest -authToken $authToken -prefix $prefix -resource $resource -method "GET"
}

#TODO: Implement Add--DeviceConfigurationPolicy

#endregion

function Get-AADRoleTemplateById {
    param(
        $authToken,
        [Parameter(Mandatory = $true)]
        $id
    )

    Invoke-GraphRestRequest -resource "/directoryRoleTemplates/$id" -onlyValues $false -authToken $authToken
}

function Get-ConditionalAccessNamedLocationById {
    param(
        $authToken,
        [Parameter(Mandatory = $true)]
        $id
    )
    Invoke-GraphRestRequest -resource "/identity/conditionalAccess/namedLocations/$id" -onlyValues $false -authToken $authToken
}

function Test-GUID {
    param(
        [Parameter(Mandatory = $true)]
        [string] $guidCandidate
    )

    [guid]::TryParse($guidCandidate, $([ref][guid]::Empty))
}

#region App registration and Service Principal

# Get App registrations
function Get-AADApps {
    param(
        $authToken = $null,
        $prefix = "https://graph.microsoft.com/v1.0/"
    )

    $resource = "/applications"

    Invoke-GraphRestRequest -method "GET" -authToken $authToken -prefix $prefix -resource $resource

}

function Get-AADAppById {
    param(
        $authToken = $null,
        $prefix = "https://graph.microsoft.com/v1.0/",
        $id = ""
    )

    if ($id -eq "") {
        return "Please provied an Azure AD App ID"
    }
    
    $resource = "/applications/" + $id

    Invoke-GraphRestRequest -method "GET" -authToken $authToken -prefix $prefix -resource $resource -onlyValues $false
}

function Add-AADApp {
    param(
        $authToken = $null,
        $prefix = "https://graph.microsoft.com/v1.0/",
        $appObject = $null    
    )

    if ($null -eq $appObject) {
        return "Please provide an Azure AD App description object"
    }

    $resource = "/applications"

    $JSON = $appObject | ConvertTo-Json -Depth 6 

    Invoke-GraphRestRequest -method "POST" -authToken $authToken -prefix $prefix -resource $resource -body $JSON -onlyValues $false
        
}

function Remove-AADAppById {
    param(
        $authToken = $null,
        $prefix = "https://graph.microsoft.com/v1.0/",
        $id = ""
    )

    if ($id -eq "") {
        return "Please provied an Azure AD App ID"
    }
    
    $resource = "/applications/" + $id

    Invoke-GraphRestRequest -method "DELETE" -authToken $authToken -prefix $prefix -resource $resource -onlyValues $false
}

function Add-AADAppPassword {
    param(
        $authToken = $null,
        $prefix = "https://graph.microsoft.com/v1.0/",
        $secretFriendlyName = "automation credential",
        $appId = ""
    )

    if ($appId -eq "") {
        return "Plese provide an application id"
    }

    $resource = "/applications/" + $appId + "/addPassword"

    $JSON = @"
    {
        "passwordCredential": {
            "displayName": "$secretFriendlyName"
        }
    }
"@

    Invoke-GraphRestRequest -method "POST" -authToken $authToken -resource $resource -body $JSON -onlyValues $false
}


# Get Service Principals.. also known as "Enterprise Apps" in portal
function Get-ServicePrincipals {
    param(
        $authToken = $null,
        $prefix = "https://graph.microsoft.com/v1.0/"
    )

    $resource = "/servicePrincipals"

    Invoke-GraphRestRequest -method "GET" -authToken $authToken -prefix $prefix -resource $resource
}


function Add-ServicePrincipalByAppId {
    param(
        $authToken = $null,
        $prefix = "https://graph.microsoft.com/v1.0/",
        $id = ""
    )

    if ($id -eq "") {
        return "Please provied an Azure AD App ID"
    }
    
    $resource = "/servicePrincipals"

    $JSON = @"
    {
        "appId": "$id"
    }
"@
    
    Invoke-GraphRestRequest -method "POST" -authToken $authToken -prefix $prefix -resource $resource -body $JSON -onlyValues $false
}

# List App Permissions
function Get-ServicePrincipalAppRoleAssignmentsById {
    param(
        $authToken = $null,
        $prefix = "https://graph.microsoft.com/v1.0/",
        $id = ""
    )

    if ($id -eq "") {
        return "Please provied an Azure AD App ID"
    }
    
    $resource = "/servicePrincipals/" + $id + "/appRoleAssignments"

    Invoke-GraphRestRequest -method "GET" -authToken $authToken -prefix $prefix -resource $resource
}

function Add-ServicePrincipalAppRoleAssignment {
    param(
        $authToken = $null,
        $prefix = "https://graph.microsoft.com/v1.0/",
        $permissionObject = $null
    )

    if ($null -eq $permissionObject) {
        return "Please provide an Enterprise App (Service Principal) permission / role assignment"
    }

    $resource = "/servicePrincipals/" + $permissionObject.principalId + "/appRoleAssignments"

    $JSON = $permissionObject | ConvertTo-Json -Depth 6

    Invoke-GraphRestRequest -method "POST" -authToken $authToken -prefix $prefix -resource $resource -body $JSON -onlyValues $false
}

function Get-AADRoleById {
    param(
        $authToken = $null,
        $prefix = "https://graph.microsoft.com/v1.0/",
        $id = ""
    )

    $resource = "/directoryRoles/$id"

    Invoke-GraphRestRequest -method GET -authToken $authToken -prefix $prefix -resource $resource -onlyValues $true

}

function Add-ServicePrincipalPassword {
    param(
        $authToken = $null,
        $prefix = "https://graph.microsoft.com/v1.0/",
        $secretFriendlyName = "automation credential",
        $servicePrincipalId = ""
    )

    if ($servicePrincipalId -eq "") {
        return "Plese provide a service principal id"
    }

    $resource = "/servicePrincipals/" + $servicePrincipalId + "/addPassword"

    $JSON = @"
    {
        "passwordCredential": {
            "displayName": "$secretFriendlyName"
        }
    }
"@

    Invoke-GraphRestRequest -method "POST" -authToken $authToken -resource $resource -body $JSON -onlyValues $false
}

#endregion

#region Windows Autopilot profiles

function Get-AutopilotProfiles {
    param(
        $authToken = $null,
        $prefix = "https://graph.microsoft.com/Beta/"
    )

    $resource = "deviceManagement/windowsAutopilotDeploymentProfiles"

    Invoke-GraphRestRequest -authToken $authToken -prefix $prefix -resource $resource -method "GET"
}

#TODO: Add-AutopilotProfiles

#endregion

#region (Mobile) Imported Devices

function Get-ImportedMobileDevices {
    param(
        $authToken = $null,
        $prefix = "https://graph.microsoft.com/Beta/"
    )

    $resource = "/deviceManagement/importedDeviceIdentities"

    Invoke-GraphRestRequest -authToken $authToken -prefix $prefix -resource $resource -method "GET"
}

#endregion

#region Autopilot Devices

function Get-ImportedAutopilotDevices {
    param(
        $authToken = $null,
        $prefix = "https://graph.microsoft.com/Beta/"
    )

    $resource = "/deviceManagement/importedWindowsAutopilotDeviceIdentities"

    Invoke-GraphRestRequest -authToken $authToken -prefix $prefix -resource $resource -method "GET"
}

function Get-WindowsAutopilotDevices {
    param(
        $authToken = $null,
        $prefix = "https://graph.microsoft.com/v1.0/"
    )

    $resource = "/deviceManagement/windowsAutopilotDeviceIdentities"

    Invoke-GraphRestRequest -authToken $authToken -prefix $prefix -resource $resource -method "GET"
}

function Get-WindowsAutopilotDeviceByDeviceId {
    param(
        [Parameter(Mandatory = $true)]
        [string]$azureAdDeviceId,
        $authToken = $null,
        $prefix = "https://graph.microsoft.com/Beta/"
    )

    ## Filtering seems not to work yet on this resource. 
    #$resource = "/deviceManagement/windowsAutopilotDeviceIdentities`?`$filter=azureAdDeviceId eq `'$azureAdDeviceId`'"
    #Invoke-GraphRestRequest -authToken $authToken -prefix $prefix -resource $resource -method "GET"

    ## Let's do it the hard way then... 
    Get-WindowsAutopilotDevices -authToken $authToken -prefix $prefix | Where-Object { $_.azureAdDeviceId -eq $azureAdDeviceId }
}

function Remove-WindowsAutopilotDevice {
    param(
        [Parameter(Mandatory = $true)]
        [string]$id,
        $authToken = $null,
        $prefix = "https://graph.microsoft.com/Beta/"
    )

    $resource = "/deviceManagement/windowsAutopilotDeviceIdentities/$id"

    Invoke-GraphRestRequest -authToken $authToken -prefix $prefix -resource $resource -method "DELETE" -onlyValues $false
}


#endregion

#region Managed Devices
function Get-ManagedDevices {
    param(
        $authToken = $null,
        $prefix = "https://graph.microsoft.com/v1.0/"
    )

    $resource = "/deviceManagement/managedDevices"

    Invoke-GraphRestRequest -authToken $authToken -prefix $prefix -resource $resource -method "GET"
}

function Get-ManagedDeviceByDeviceId {
    param(
        [Parameter(Mandatory = $true)]
        [string]$azureAdDeviceId,
        $authToken = $null,
        $prefix = "https://graph.microsoft.com/v1.0/"
    )

    $resource = "/deviceManagement/managedDevices`?`$filter=azureADDeviceId eq `'$azureAdDeviceId`'"

    Invoke-GraphRestRequest -authToken $authToken -prefix $prefix -resource $resource -method "GET"
}

function Remove-ManagedDevice {
    param(
        [Parameter(Mandatory = $true)]
        [string]$id,
        $authToken = $null,
        $prefix = "https://graph.microsoft.com/v1.0/"
    )

    $resource = "/deviceManagement/managedDevices/$id"

    Invoke-GraphRestRequest -authToken $authToken -prefix $prefix -resource $resource -method "DELETE" -onlyValues $false
}

#endregion

#region Sites and Files (OneDrive, OneDriveFB/SharePoint)

function Get-SPRootSite {
    param(
        $authToken = $null,
        $prefix = "https://graph.microsoft.com/V1.0/"

    )

    $resource = "/sites/root"

    Invoke-GraphRestRequest -authToken $authToken -prefix $prefix -resource $resource -method "GET" -onlyValues $false
}

function Get-SPAllSites {
    param(
        $authToken = $null,
        $prefix = "https://graph.microsoft.com/Beta/"
    )

    $resource = '/sites'

    Invoke-GraphRestRequest -authToken $authToken -prefix $prefix -resource $resource -method "GET" -onlyValues $true
}

function Get-SPSite {
    param(
        $authToken = $null,
        $prefix = "https://graph.microsoft.com/V1.0/",
        $hostname = "",
        $site = ""
    )

    if (($site -eq "") -or ($hostname -eq "")) {
        return "Please give Hostname and SharePoint Site Name."
    }

    $resource = '/sites/' + $hostname + ":/sites/" + $site

    Invoke-GraphRestRequest -authToken $authToken -prefix $prefix -resource $resource -method "GET" -onlyValues $false
}


function Get-SPSiteDriveById {
    param(
        $authToken = $null,
        $prefix = "https://graph.microsoft.com/V1.0/",
        $siteId = ""
    )

    if ($siteId -eq "") {
        return "Please give your SharePoint Sites ID"
    }

    $resource = '/sites/' + $siteId + "/drive"

    Invoke-GraphRestRequest -authToken $authToken -prefix $prefix -resource $resource -method "GET" -onlyValues $false
}

function Get-DriveById {
    param(
        $authToken = $null,
        $prefix = "https://graph.microsoft.com/V1.0/",
        $driveId = ""
    )

    if ($driveId -eq "") {
        return "Please give your (OneDrive) Drive ID"
    }

    $resource = "/drives/" + $driveId

    Invoke-GraphRestRequest -authToken $authToken -prefix $prefix -resource $resource -method "GET" -onlyValues $false
}

function Get-DriveChildrenByPath {
    param(
        $authToken = $null,
        $prefix = "https://graph.microsoft.com/V1.0/",
        $driveId = "",
        $path = "root"
    )

    if ($driveId -eq "") {
        return "Please give your (OneDrive) Drive ID"
    }

    $resource = "/drives/" + $driveId + "/" + $path + "/children"

    Invoke-GraphRestRequest -authToken $authToken -prefix $prefix -resource $resource -method "GET" -onlyValues $true
}

function Get-DriveItemVersions {
    param(
        $authToken = $null,
        $prefix = "https://graph.microsoft.com/V1.0/",
        $driveId = "",
        $itemId = ""
    )

    if (($driveId -eq "") -or ($itemId -eq "")) {
        return "Please give your (OneDrive) Drive ID and Item ID"
    }

    $resource = "/drives/" + $driveId + "/items/" + $itemId + "/versions"

    Invoke-GraphRestRequest -authToken $authToken -prefix $prefix -resource $resource -method "GET" -onlyValues $true
}

function Get-MyDrives {
    param(
        $authToken = $null,
        $prefix = "https://graph.microsoft.com/V1.0/"
    )

    $resource = "/me/drives"

    Invoke-GraphRestRequest -authToken $authToken -prefix $prefix -resource $resource -method "GET"
}

#endregion

#region Calendars (using Delegated Permissions)

function Get-MyCalendars {
    param(
        $authToken = $null,
        $prefix = "https://graph.microsoft.com/V1.0/"

    )

    $resource = "/me/calendars"

    Invoke-GraphRestRequest -prefix $prefix -resource $resource -method "GET" -authToken $authToken -onlyValues $true

}

function Get-CalendarEvents {
    param(
        $authToken = $null,
        $prefix = "https://graph.microsoft.com/V1.0/",
        $calendarId = ""
    )

    if ($calendarId -eq "") {
        return "Please give a Calendar ID"
    }

    $resource = "/me/calendars/" + $calendarId + "/events"

    Invoke-GraphRestRequest -prefix $prefix -resource $resource -method "GET" -authToken $authToken -onlyValues $true
}

#endregion

#region Mail (using Delegated Permissions)
function Get-MyMails {
    param(
        $authToken = $null,
        $prefix = "https://graph.microsoft.com/V1.0/"
    )

    $resource = '/me/messages'

    Invoke-GraphRestRequest -prefix $prefix -resource $resource -method "GET" -authToken $authToken -onlyValues $true

}

function Get-MyMailById {
    param(
        $authToken = $null,
        $prefix = "https://graph.microsoft.com/V1.0/",
        $Id = ""
    )

    if ($Id -eq "") {
        return "Please give a mail/message ID"
    }

    $resource = '/me/messages/' + $Id + '/$value'

    Invoke-GraphRestRequest -prefix $prefix -resource $resource -method "GET" -authToken $authToken -onlyValues $false

}

#endregion

#region Teams

function Get-MyTeams {
    param(
        $authToken = $null,
        $prefix = "https://graph.microsoft.com/V1.0/"
    )

    $resource = "/me/joinedTeams"

    Invoke-GraphRestRequest -prefix $prefix -resource $resource -method "GET" -authToken $authToken -onlyValues $true
}

function Get-TeamsChannels {
    param(
        $authToken = $null,
        $prefix = "https://graph.microsoft.com/V1.0/",
        $teamId = "" 
    )

    if ($teamId -eq "") {
        return "Please provide a MS Teams Team ID"
    }

    $resource = "/teams/" + $teamId + "/channels"

    Invoke-GraphRestRequest -prefix $prefix -resource $resource -method "GET" -authToken $authToken -onlyValues $true

}

function  Get-TeamsChannelMessages {
    param (
        $authToken = $null,
        $prefix = "https://graph.microsoft.com/V1.0/",
        $teamId = "",
        $channelId = "" 
    )
    
    if (($teamId -eq "") -or ($channelId -eq "")) {
        return "Please provide a MS Teams Team and Channel ID"
    }

    $resource = "/teams/" + $teamId + "/channels/" + $channelId + "/messages"

    Invoke-GraphRestRequest -prefix $prefix -resource $resource -method "GET" -authToken $authToken -onlyValues $true
}


function  Get-TeamsChannelMessageById {
    param (
        $authToken = $null,
        $prefix = "https://graph.microsoft.com/V1.0/",
        $teamId = "",
        $channelId = "",
        $messageId = "" 
    )
    
    if (($teamId -eq "") -or ($channelId -eq "") -or ($messageId -eq "")) {
        return "Please provide a MS Teams Team, Channel and message ID"
    }

    $resource = "/teams/" + $teamId + "/channels/" + $channelId + "/messages/" + $messageId

    Invoke-GraphRestRequest -prefix $prefix -resource $resource -method "GET" -authToken $authToken -onlyValues $false
}

function  Get-TeamsChannelMessageHostedContents {
    param (
        $authToken = $null,
        $prefix = "https://graph.microsoft.com/V1.0/",
        $teamId = "",
        $channelId = "",
        $messageId = "" 
    )

    if (($teamId -eq "") -or ($channelId -eq "") -or ($messageId -eq "")) {
        return "Please provide a MS Teams Team, Channel and message ID"
    }
    
    $resource = "/teams/" + $teamId + "/channels/" + $channelId + "/messages/" + $messageId + "/hostedContents"

    Invoke-GraphRestRequest -prefix $prefix -resource $resource -method "GET" -authToken $authToken -onlyValues $true
}

function  Get-TeamsChannelMessageHostedContentsById {
    param (
        $authToken = $null,
        $prefix = "https://graph.microsoft.com/beta/",
        $teamId = "",
        $channelId = "",
        $messageId = "",
        $hostedContentsId = "" 
    )

    if (($teamId -eq "") -or ($channelId -eq "") -or ($messageId -eq "") -or ($hostedContentsId -eq "")) {
        return "Please provide a MS Teams Team, Channel, Message and HostedContent ID"
    }
    
    $resource = "/teams/" + $teamId + "/channels/" + $channelId + "/messages/" + $messageId + "/hostedContents/" + $hostedContentsId + '/$value'

    Invoke-GraphRestRequest -prefix $prefix -resource $resource -method "GET" -authToken $authToken -onlyValues $false -writeToFile $true -outFile "image.png"
}


function Get-TeamsChannelMessageReplies {
    param (
        $authToken = $null,
        $prefix = "https://graph.microsoft.com/V1.0/",
        $teamId = "",
        $channelId = "",
        $messageId = "" 
    )

    if (($teamId -eq "") -or ($channelId -eq "") -or ($messageId -eq "")) {
        return "Please provide a MS Teams Team, Channel and message ID"
    }
    
    $resource = "/teams/" + $teamId + "/channels/" + $channelId + "/messages/" + $messageId + "/replies"

    Invoke-GraphRestRequest -prefix $prefix -resource $resource -method "GET" -authToken $authToken -onlyValues $true

}

#endregion

#region Mermaid export
function Resolve-AppName {
    param(
        $authToken,
        [string]$appId
    )

    # Ignore empty AppId
    if (-not $appId) {
        return
    }

    # Well known Office apps:
    $appMapping = @{
        "00000002-0000-0000-c000-000000000000" = "AAD Graph API"	
        "00000002-0000-0ff1-ce00-000000000000" = "Office 365 Exchange Online"
        "00000003-0000-0000-c000-000000000000" = "Microsoft Graph"
        "00000004-0000-0ff1-ce00-000000000000" = "Skype for Business Online"
        "00000005-0000-0ff1-ce00-000000000000" = "Office 365 Yammer"
        "2d4d3d8e-2be3-4bef-9f87-7875a61c29de" = "OneNote"
        "797f4846-ba00-4fd7-ba43-dac1f8f63013" = "Windows Azure Service Management API"
        "c5393580-f805-4401-95e8-94b7a6ef2fc2" = "Office 365 Management APIs"
        "cc15fd57-2c6c-4117-a88c-83b1d56b4bbe" = "Microsoft Teams Services"
        "cfa8b339-82a2-471a-a3c9-0fc0be7a4093" = "Azure Key Vault"
        "All"                                  = "All"
    }

    if ($appMapping.ContainsKey($appId)) {
        $appMapping[$appId]
    }
    else {
        $app = Invoke-GraphRestRequest -authToken $authToken -resource "/applications?`$filter=appId eq '$appId'" -ErrorAction SilentlyContinue
        if ($app) {
            $app.displayName
        }
        else {
            $appId
        }
    }
}

function Resolve-Username {
    param(
        $authToken,
        [Parameter(Mandatory = $true)]
        [string] $userId
    )

    if (Test-GUID -guidCandidate $userId) {
        $user = Get-AADUserByID -userID $_ -ErrorAction SilentlyContinue -authToken $authToken
        if ($user -and $user.userPrincipalName) {
            $user.userPrincipalName
        }
        else {
            $userId
        }
    }
    else {
        $userId
    }
}

function Resolve-Groupname {
    param(
        $authToken,
        [Parameter(Mandatory = $true)]
        [string] $groupId
    )

    if (Test-GUID -guidCandidate $groupId) {
        $group = Get-AADGroupByID -groupID $_ -ErrorAction SilentlyContinue -authToken $authToken
        if ($group -and $group.displayName) {
            $group.displayName
        }
        else {
            $groupId
        }
    }
    else {
        $groupId
    }
}

function Resolve-RoleTemplateName {
    param(
        $authToken,
        [Parameter(Mandatory = $true)]
        [string] $roleTemplateId
    )

    if (Test-GUID -guidCandidate $roleTemplateId) {
        $roleTemplate = Get-AADRoleTemplateById -id $roleTemplateId -ErrorAction SilentlyContinue -authToken $authToken
        if ($roleTemplate) {
            $roleTemplate.displayName
        }
        else {
            $roleTemplateId
        }
    }
    else {
        $roleTemplateId
    }
}

function Resolve-ConditionalAccessNamedLocationById {
    param(
        $authToken,
        [Parameter(Mandatory = $true)]
        $id
    )

    if (Test-GUID -guidCandidate $id) {
        $namedLocation = Get-ConditionalAccessNamedLocationById -id $id -ErrorAction SilentlyContinue -authToken $authToken
        if ($namedLocation -and $namedLocation.displayName) {
            $namedLocation.displayName
        }
        else {
            $id
        }
    }
    else {
        $id
    }
}

function Write-ConditionalAccessPolicyToMermaid {
    param(
        # Conditional Access Policy
        $pol,
        # Write HTML files (with mermaid rendered in the browser)
        [bool] $asHTML = $true,
        # Write Markdown. If both are present, HTML is prefered.
        [bool] $asMarkdown = $false,
        $authToken
    )

    if ($asHTML) {
        @'
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
</head>
<body>
<div class="mermaid">
'@
    }
    elseif ($asMarkdown) {
        @'
::: mermaid
'@
    }

    "graph LR;"
    "id[`"$($pol.displayName)`"] -----> state[state: $($pol.state)]"

    if ($pol.conditions) {
        'id --> conditions'

        if ($pol.conditions.applications) {
            'conditions --> applications'
        
            if ($pol.conditions.applications.includeApplications) {
                'applications --> includeApplications'

                $pol.conditions.applications.includeApplications | ForEach-Object {
                    
                    "includeApplications --> a_$($_)[`"$(Resolve-AppName -appId $_ -authToken $authToken)`"]"
                }
            }

            if ($pol.conditions.applications.excludeApplications) {
                'applications --> excludeApplications'

                $pol.conditions.applications.excludeApplications | ForEach-Object {
                    
                    "excludeApplications --> a_$($_)[`"$(Resolve-AppName -appId $_ -authToken $authToken)`"]"
                }
            }

            if ($pol.conditions.applications.includeUserActions) {
                'applications --> includeUserActions'

                $pol.conditions.applications.includeUserActions 
            }

        }

        if ($pol.conditions.users) {
            'conditions --> users'

            if ($pol.conditions.users.includeUsers) {
                'users --> includeUsers'

                $pol.conditions.users.includeUsers | ForEach-Object {
                    "includeUsers --> u_$($_)[`"$(Resolve-Username -userId $_ -authToken $authToken)`"]"
                }
            }

            if ($pol.conditions.users.excludeUsers) {
                'users --> excludeUsers'

                $pol.conditions.users.excludeUsers | ForEach-Object {
                    "excludeUsers --> u_$($_)[`"$(Resolve-Username -userId $_ -authToken $authToken)`"]"
                }
            }

            if ($pol.conditions.users.includeGroups) {
                'users --> includeGroups'

                $pol.conditions.users.includeGroups | ForEach-Object {
                    "includeGroups --> g_$($_)[`"$(Resolve-Groupname -groupId $_ -authToken $authToken)`"]"
                }
            }

            if ($pol.conditions.users.excludeGroups) {
                'users --> excludeGroups'

                $pol.conditions.users.excludeGroups | ForEach-Object {
                    "excludeGroups --> g_$($_)[`"$(Resolve-Groupname -groupId $_ -authToken $authToken)`"]"
                }
            }

            if ($pol.conditions.users.includeRoles) {
                'users --> includeRoles'

                $pol.conditions.users.includeRoles | ForEach-Object {
                    "includeRoles --> r_$($_)[`"$(Resolve-RoleTemplateName -roleTemplateId $_ -authToken $authToken)`"]"
                }
            }

            if ($pol.conditions.users.excludeRoles) {
                'users --> excludeRoles'

                $pol.conditions.users.excludeRoles | ForEach-Object {
                    "excludeRoles --> r_$($_)[`"$(Resolve-RoleTemplateName -roleTemplateId $_ -authToken $authToken)`"]"
                }
            }
        }

        if ($pol.conditions.clientAppTypes) {
            'conditions ---> clientAppTypes'

            $pol.conditions.clientAppTypes | ForEach-Object {
                "clientAppTypes --> $($_)"
            }
        }

        if ($pol.conditions.locations) {
            'conditions --> locations'

            if ($pol.conditions.locations.includeLocations) {
                'locations --> includeLocations'
            
                $pol.conditions.locations.includeLocations | ForEach-Object {
                    "includeLocations --> l_$($_)[`"$(Resolve-ConditionalAccessNamedLocationById -id $_ -authToken $authToken)`"]"
                }
            }        

            if ($pol.conditions.locations.excludeLocations) {
                'locations --> excludeLocations'
            
                $pol.conditions.locations.excludeLocations | ForEach-Object {
                    "excludeLocations --> l_$($_)[`"$(Resolve-ConditionalAccessNamedLocationById -id $_ -authToken $authToken)`"]"
                }
            }        
        }

        if ($pol.conditions.platforms) {
            'conditions --> platforms'

            if ($pol.conditions.platforms.includePlatforms) {
                'platforms --> includePlatforms'

                $pol.conditions.platforms.includePlatforms | ForEach-Object {
                    "includePlatforms --> cap_$($_)[$($_)]"
                }
            }

            if ($pol.conditions.platforms.excludePlatforms) {
                'platforms --> excludePlatforms'

                $pol.conditions.platforms.excludePlatforms | ForEach-Object {
                    "excludePlatforms --> cap_$($_)[$($_)]"
                }
            }
        }

        if ($pol.conditions.signInRiskLevels) {
            'conditions --> signInRiskLevels'

            $pol.conditions.signInRiskLevels | ForEach-Object {
                "signInRiskLevels --> sirl_$($_)[$($_)]"
            }
        }

        if ($pol.conditions.userRiskLevels) {
            'conditions --> userRiskLevels'

            $pol.conditions.userRiskLevels | ForEach-Object {
                "userRiskLevels --> url_$($_)[$($_)]"
            }
        }
    }

    if ($pol.grantControls) {
        'id ---> grantControls'
        "grantControls --> grantControlsOperator[operator: $($pol.grantControls.operator)]"

        if ($pol.grantControls.builtInControls) {
            'grantControls --> builtInControls'

            $pol.grantControls.builtInControls | ForEach-Object {
                "builtInControls --> bic_$($_)[$($_)]"
            }
        }

        if ($pol.grantControls.customAuthenticationFactors) {
            'grantControls --> customAuthenticationFactors'

            $pol.grantControls.customAuthenticationFactors | ForEach-Object {
                "customAuthenticationFactors --> cam_$($_)[$($_)]"
            }
        }

        if ($pol.grantControls.termsOfUse) {
            'grantControls --> termsOfUse'

            $pol.grantControls.termsOfUse | ForEach-Object {
                "termsOfUse --> tou_$($_)[$($_)]"
            }

        } 
    }
    if ($pol.sessionControls) {
        'id ---> sessionControls'

        if ($pol.sessionControls.applicationEnforcedRestrictions) {
            'sessionControls --> applicationEnforcedRestrictions'
            "applicationEnforcedRestrictions --> applicationEnforcedRestrictionsIsEnabled[isEnabled: $($pol.sessionControls.applicationEnforcedRestrictions.isEnabled)]"
        }

        if ($pol.sessionControls.cloudAppSecurity) {
            'sessionControls --> cloudAppSecurity'
            "cloudAppSecurity --> cloudAppSecurityTypeIsEnabled[isEnabled: $($pol.sessionControls.cloudAppSecurity.isEnabled)]"
            "cloudAppSecurity --> cloudAppSecurityType[cloudAppSecurityType: $($pol.sessionControls.cloudAppSecurity.cloudAppSecurityType)]"
        }

        if ($pol.sessionControls.persistentBrowser) {
            'sessionControls --> persistentBrowser'
            "persistentBrowser --> persistentBrowserIsEnabled[isEnabled: $($pol.sessionControls.persistentBrowser.isEnabled)]"
            "persistentBrowser --> persistentBrowserSessionMode[mode: $($pol.sessionControls.persistentBrowser.mode)]"
        }

        if ($pol.sessionControls.signInFrequency) {
            'sessionControls --> signInFrequency'
            "signInFrequency --> signInFrequencyIsEnabled[isEnabled: $($pol.sessionControls.signInFrequency.isEnabled)]"
            "signInFrequency --> signinFrequencyType[type: $($pol.sessionControls.signInFrequency.type)]"
            "signInFrequency --> signinFrequencyValue[value: $($pol.sessionControls.signInFrequency.value)]"
        }
    }

    if ($asHTML) {
        @'
</div>
<script src="https://cdn.jsdelivr.net/npm/mermaid/dist/mermaid.min.js"></script>
<script>mermaid.initialize({startOnLoad:true});</script>
</body>
</html>
'@    
    }
    elseif ($asMarkdown) {
        @'
:::
'@
    }
}
#endregion