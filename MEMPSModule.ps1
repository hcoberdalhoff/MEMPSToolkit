
#region Authentication

# This function is used to interactively authenticate with the Graph API REST interface using ADAL (not recommended)
# taken/adapted from https://github.com/microsoftgraph/powershell-intune-samples
function Get-AuthToken {

    <#
    .SYNOPSIS
    This function is used to authenticate with the Graph API REST interface using ADAL (not recommended)
    .DESCRIPTION
    The function authenticate with the Graph API Interface with the tenant name
    This one uses ADAL - use this with (Windows-) PS5
    .EXAMPLE
    Get-AuthToken
    Authenticates you with the Graph API interface
    .NOTES
    NAME: Get-AuthToken
    #>
    
    [cmdletbinding()]
    
    param
    (
        [Parameter(Mandatory = $true)]
        $User,
        $Tenant = ""
    )
    
    $userUpn = New-Object "System.Net.Mail.MailAddress" -ArgumentList $User
    
    # Allow different tenantname...
    # TODO - Report improvement to https://github.com/microsoftgraph/powershell-intune-samples
    if ($Tenant -eq "") {
        $Tenant = $userUpn.Host
    }
        
    Write-Host "Checking for AzureAD module..."
    
    $AadModule = Get-Module -Name "AzureAD" -ListAvailable
    
    if ($null -eq $AadModule) {
    
        Write-Host "AzureAD PowerShell module not found, looking for AzureADPreview"
        $AadModule = Get-Module -Name "AzureADPreview" -ListAvailable
    
    }
    
    if ($null -eq $AadModule) {
        write-host
        write-host "AzureAD Powershell module not installed..." -f Red
        write-host "Install by running 'Install-Module AzureAD' or 'Install-Module AzureADPreview' from an elevated PowerShell prompt" -f Yellow
        write-host "Script can't continue..." -f Red
        write-host
        exit
    }
    
    # Getting path to ActiveDirectory Assemblies
    # If the module count is greater than 1 find the latest version
    
    if ($AadModule.count -gt 1) {
    
        $Latest_Version = ($AadModule | select version | Sort-Object)[-1]
    
        $aadModule = $AadModule | ? { $_.version -eq $Latest_Version.version }
    
        # Checking if there are multiple versions of the same module found
    
        if ($AadModule.count -gt 1) {
    
            $aadModule = $AadModule | select -Unique
    
        }
    
        $adal = Join-Path $AadModule.ModuleBase "Microsoft.IdentityModel.Clients.ActiveDirectory.dll"
        $adalforms = Join-Path $AadModule.ModuleBase "Microsoft.IdentityModel.Clients.ActiveDirectory.Platform.dll"
    
    }
    
    else {
    
        $adal = Join-Path $AadModule.ModuleBase "Microsoft.IdentityModel.Clients.ActiveDirectory.dll"
        $adalforms = Join-Path $AadModule.ModuleBase "Microsoft.IdentityModel.Clients.ActiveDirectory.Platform.dll"
    
    }
    
    [System.Reflection.Assembly]::LoadFrom($adal) | Out-Null
    
    [System.Reflection.Assembly]::LoadFrom($adalforms) | Out-Null
    
    $clientId = "d1ddf0e4-d672-4dae-b554-9d5bdfd93547"
    
    $redirectUri = "urn:ietf:wg:oauth:2.0:oob"
    
    $resourceAppIdURI = "https://graph.microsoft.com"
    
    $authority = "https://login.microsoftonline.com/$Tenant"
    
    try {
    
        $authContext = New-Object "Microsoft.IdentityModel.Clients.ActiveDirectory.AuthenticationContext" -ArgumentList $authority
    
        # https://msdn.microsoft.com/en-us/library/azure/microsoft.identitymodel.clients.activedirectory.promptbehavior.aspx
        # Change the prompt behaviour to force credentials each time: Auto, Always, Never, RefreshSession
    
        $platformParameters = New-Object "Microsoft.IdentityModel.Clients.ActiveDirectory.PlatformParameters" -ArgumentList "Auto"
    
        $userId = New-Object "Microsoft.IdentityModel.Clients.ActiveDirectory.UserIdentifier" -ArgumentList ($User, "OptionalDisplayableId")
    
        $authResult = $authContext.AcquireTokenAsync($resourceAppIdURI, $clientId, $redirectUri, $platformParameters, $userId).Result
    
        # If the accesstoken is valid then create the authentication header
    
        if ($authResult.AccessToken) {
    
            # Creating header for Authorization token
    
            $authHeader = @{
                'Content-Type'  = 'application/json'
                'Authorization' = "Bearer " + $authResult.AccessToken
                'ExpiresOn'     = $authResult.ExpiresOn
            }
    
            return $authHeader
    
        }
    
        else {
    
            Write-Host
            Write-Host "Authorization Access Token is null, please re-run authentication..." -ForegroundColor Red
            Write-Host
            break
    
        }
    
    }
    
    catch {
    
        write-host $_.Exception.Message -f Red
        write-host $_.Exception.ItemName -f Red
        write-host
        break
    
    }
    
}

# The following function is taken/adapted from https://danielchronlund.com but has been modified for this context.
# Will interactively authenticate against a Service Principal with delegated perms. 
function Connect-DCMsGraphAsDelegated {
    <#
        .SYNOPSIS
            Connect to Microsoft Graph with delegated credentials (interactive login will popup).

        .DESCRIPTION
            The following function is taken from https://danielchronlund.com but has been modified for this context.

            This CMDlet will prompt you to sign in to Azure AD. If successfull an access token is returned that can be used with other Graph CMDlets. Make sure you store the access token in a variable according to the example.

            Before running this CMDlet, you first need to register a new application in your Azure AD according to this article:
            https://danielchronlund.com/2018/11/19/fetch-data-from-microsoft-graph-with-powershell-paging-support/
            
        .PARAMETER ClientID
            Client ID for your Azure AD application with Conditional Access Graph permissions.
        
        .PARAMETER ClientSecret
            Client secret for the Azure AD application with Conditional Access Graph permissions.
            
        .INPUTS
            None

        .OUTPUTS
            None

        .NOTES
            Author:   Daniel Chronlund
            GitHub:   https://github.com/DanielChronlund/DCToolbox
            Blog:     https://danielchronlund.com/
        
        .EXAMPLE
            $AccessToken = Connect-DCMsGraphAsDelegated -ClientID '8a85d2cf-17c7-4ecd-a4ef-05b9a81a9bba' -ClientSecret 'j[BQNSi29Wj4od92ritl_DHJvl1sG.Y/'
    #>


    param (
        [parameter(Mandatory = $true)]
        [string]$ClientID,

        [parameter(Mandatory = $true)]
        [string]$ClientSecret
    )


    # Declarations.
    $Resource = "https://graph.microsoft.com"
    $RedirectUri = "https://login.microsoftonline.com/common/oauth2/nativeclient"


    # Force TLS 1.2.
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12


    # UrlEncode the ClientID and ClientSecret and URL's for special characters.
    Add-Type -AssemblyName System.Web
    $ClientSecretEncoded = [System.Web.HttpUtility]::UrlEncode($ClientSecret)
    $ResourceEncoded = [System.Web.HttpUtility]::UrlEncode($Resource)
    $RedirectUriEncoded = [System.Web.HttpUtility]::UrlEncode($RedirectUri)


    # Function to popup Auth Dialog Windows Form.
    function Get-AuthCode {
        Add-Type -AssemblyName System.Windows.Forms
        $Form = New-Object -TypeName System.Windows.Forms.Form -Property @{Width = 440; Height = 640 }
        $Web = New-Object -TypeName System.Windows.Forms.WebBrowser -Property @{Width = 420; Height = 600; Url = ($Url -f ($Scope -join "%20")) }
        $DocComp = {
            $Global:uri = $Web.Url.AbsoluteUri        
            if ($Global:uri -match "error=[^&]*|code=[^&]*") {
                $Form.Close() 
            }
        }

        $Web.ScriptErrorsSuppressed = $true
        $Web.Add_DocumentCompleted($DocComp)
        $Form.Controls.Add($Web)
        $Form.Add_Shown( { $Form.Activate() })
        $Form.ShowDialog() | Out-Null
        $QueryOutput = [System.Web.HttpUtility]::ParseQueryString($Web.Url.Query)
        $Output = @{ }

        foreach ($Key in $QueryOutput.Keys) {
            $Output["$Key"] = $QueryOutput[$Key]
        }
    }


    # Get AuthCode.
    $Url = "https://login.microsoftonline.com/common/oauth2/authorize?response_type=code&redirect_uri=$RedirectUriEncoded&client_id=$ClientID&resource=$ResourceEncoded&prompt=admin_consent&scope=$ScopeEncoded"
    Get-AuthCode


    # Extract Access token from the returned URI.
    $Regex = '(?<=code=)(.*)(?=&)'
    $AuthCode = ($Uri | Select-String -Pattern $Regex).Matches[0].Value


    # Get Access Token.
    $Body = "grant_type=authorization_code&redirect_uri=$RedirectUri&client_id=$ClientId&client_secret=$ClientSecretEncoded&code=$AuthCode&resource=$Resource"
    $TokenResponse = Invoke-RestMethod https://login.microsoftonline.com/common/oauth2/token -Method Post -ContentType "application/x-www-form-urlencoded" -Body $Body -ErrorAction "Stop"


    # Return the access token.
    #$TokenResponse.access_token

    # (Hans-Carl) Modified output 
    return @{
        'Content-Type'  = 'application/json'
        'Authorization' = "Bearer " + $TokenResponse.access_token
    }
}

# Save a Service Principal secret in an encrypted file 
function Save-AppLoginSecret {
    param (
        [string]$clientId = "",
        [string]$tenant = "",
        #String or SecureString
        $secretValue,
        $path = ""
    )

    # Default filename and location
    if ($path -eq "") {
        $path = $env:APPDATA + "\" + $tenant + "_" + $clientId + ".xml"
    }

    if ($null -eq $secretValue) {
        return "Please specify a secret to store"
    }

    # Encrypt secret
    if ($secretValue.GetType().Name -eq "String") {
        $secretValue = ConvertTo-SecureString -String $secretValue -AsPlainText
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
}

# Load Service Principal secret in an encrypted file and authenticate
function Get-AppLoginFromFile {
    param (
        $path = $env:APPDATA + "\primepulse.de_aafd13a1-18ca-4c6a-894c-e0794214aba9.xml"
    )

    if (-not (test-path -Path $path)) {
        return "File not found"
    }

    $data = Import-Clixml -Path $path

    $clientId = $data[0]
    $tenant = $data[1]
    $secretValue = [System.Net.NetworkCredential]::new('', $data[2]).Password

    Get-AppLoginToken -tenant $tenant -clientId $clientId -secretValue $secretValue
} 

# Authenticate non-interactively against a service principal / app registration with app permissions. 
# Can be used headless, no libraries needed. Recommended. 
function Get-AppLoginToken {
    param (
        $resource = "https://graph.microsoft.com",
        $tenant = "primepulse.de",
        $clientId = "",
        $secretValue = ""
    )

    $LoginRequestParams = @{
        Method = 'POST'
        Uri    = "https://login.microsoftonline.com/" + $tenant + "/oauth2/token?api-version=1.0"
        Body   = @{ 
            grant_type    = "client_credentials"; 
            resource      = $resource; 
            client_id     = $clientId; 
            client_secret = $secretValue 
        }
    }

    $result = Invoke-RestMethod @LoginRequestParams

    return @{
        'Content-Type'  = 'application/json'
        'Authorization' = "Bearer " + $result.access_token
        'ExpiresOn'     = $result.expires_on
    }

}

# Store a current token as default in an encrypted file
function Save-AppLoginToken {
    param (
        $authToken = $null,
        $path = $env:APPDATA + "\PPImport_current_token.xml",
        [bool]$overwrite = $true
    )

    $encToken = ConvertTo-SecureString -String $authToken.Authorization -AsPlainText

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
function Load-AppLoginToken {
    param(
        $path = $env:APPDATA + "\PPImport_current_token.xml"
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

# Interactively sign in using "device login flow". No libraries or GUI needed.
# taken/adapted from https://github.com/microsoftgraph/powershell-intune-samples
function Get-DeviceLoginToken {

    <#
    .SYNOPSIS
    This function is used to authenticate with the Graph API REST interface
    .DESCRIPTION
    The function authenticates with the Graph API Interface with the tenant name given
    This one uses DeviceLogin -> interactive session, needs a browser.
    Uses raw OAuth REST requests - use this with PS6/7
    .EXAMPLE
    Get-DeviceLoginToken
    Authenticates you with the Graph API interface
    .NOTES
    NAME: Get-DeviceLoginToken
    #>
    
    [cmdletbinding()]
    
    param (
        $clientID = 'd1ddf0e4-d672-4dae-b554-9d5bdfd93547',
        $tenant = "primepulse.de",
        $resource = "https://graph.microsoft.com"
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
            scope      = "https://graph.microsoft.com/.default https://graph.microsoft.com/Policy.Read.All"
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

#endregion Authentication

#region Basic API and File interaction

# Standardize Graph API calls
function Execute-GraphRestRequest {
    param (
        $method = "GET",
        $prefix = "https://graph.microsoft.com/Beta/",
        $resource = "deviceManagement/deviceCompliancePolicies",
        $body = $null,
        $authToken = $null,
        $onlyValues = $true
    )
    
    if ($null -eq $authToken) {
        $authToken = Load-AppLoginToken
        if ($null -eq $authToken) {
            "Please provide an authentication token. You can use Get-DeviceLoginToken to acquire one."
        }
    }

    $result = Invoke-RestMethod -Uri ($prefix + $resource) -Headers $authToken -Method $method -Body $body -ContentType "application/json"

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
        [array]$policies = $null
    )

    if ($null -eq $policies) {
        "Please provide policies to export. You can acquire these i.e. using Get-CompliancePolicies"
        return
    }

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
        $filename = $null
    )

    if ($null -eq $filename) {
        "Please provide a (JSON) file containing a Policy Export. You can create those using Export-PolicyObjects"
        return
    }

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

    Execute-GraphRestRequest -method "GET" -prefix $prefix -resource $resource -authToken $authToken
}

function Add-AADGroupFromObject {
    param(
        $authToken = $null,
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
        $displayName = "",
        $mailNickName = "",
        $prefix = "https://graph.microsoft.com/V1.0/",
        $securityEnabled = "true",
        $mailEnabled = "false"
    )

    $resource = "groups"

    if (($displayName -eq "") -or ($mailNickName -eq "")) {
        return "Please provide a DisplayName and MailNickname for the new group."
    }

    $JSON = '{
        "displayName": "' + $displayName + '",
        "mailNickname": "' + $mailNickName + '",
        "securityEnabled": ' + $securityEnabled + ',
        "mailEnabled": ' + $mailEnabled + '
    }'

    Execute-GraphRestRequest -method "POST" -prefix $prefix -resource $resource -authToken $authToken -body $JSON -onlyValues $false
}

function Get-AADGroupById {
    param(
        $authToken = $null,
        $prefix = "https://graph.microsoft.com/V1.0/",
        $resource = "groups",
        $groupId = ""
    )

    if ($groupId -eq "") {
        return "Please provide a AzureAD Group ID."
    }

    Execute-GraphRestRequest -method "GET" -prefix $prefix -resource ($resource + "/" + $groupId) -authToken $authToken -onlyValues $false
}

function Get-AADGroupByName {
    param(
        $authToken = $null,
        $groupName = $null
    )

    $groups = get-AADGroups -authToken $authToken

    $groups | Where-Object { $_.displayName -like $groupName }
}

function Import-AADGroupFromFile {
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
    } else {
        "Group " + $groupData.displayName + " exists. Will skip. "
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

    Execute-GraphRestRequest -authToken $authToken -prefix $prefix -resource $resource -method "GET"   
   
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

    Execute-GraphRestRequest -authToken $authToken -prefix $prefix -resource $resource -method "POST" -body $JSON -onlyValues $false
}

#TODO: Currently overwrites all other assignments
function Assign-CompliancePolicyToGroup {
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


Execute-GraphRestRequest -method "POST" -prefix $prefix -resource $resource -body $JSON -authToken $authToken -onlyValues $false

}

#TODO: Currently overwrites all other assignments. Not usefull.
function Exclude-CompliancePolicyFromGroup {
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

    Execute-GraphRestRequest -method "POST" -prefix $prefix -resource $resource -body $JSON -authToken $authToken

}

#endregion 

#region Conditional Access Policies
function Get-ConditionalAccessPolicies {
    param (
        $authToken = $null,
        $prefix = "https://graph.microsoft.com/V1.0/"
    )

    $resource = "identity/conditionalAccess/policies"

    Execute-GraphRestRequest -method "GET" -prefix $prefix -resource $resource -authToken $authToken
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

    Execute-GraphRestRequest -authToken $authToken -prefix $prefix -resource $resource -method "POST" -body $JSON -onlyValues $false
}

#TODO: Allow to assign to groups by name

#endregion 

#region Device Configurations
function Get-DeviceConfigurations {
    param(
        $authToken = $null,
        $prefix = "https://graph.microsoft.com/Beta/"
    )

    $resource = "deviceManagement/deviceConfigurations"

    Execute-GraphRestRequest -authToken $authToken -prefix $prefix -resource $resource -method "GET"

}

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

    Execute-GraphRestRequest -authToken $authToken -prefix $prefix -resource ($resource + "/" + $configId) -method "GET" -onlyValues $false

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
    }

    Execute-GraphRestRequest -authToken $authToken -prefix $prefix -resource ($resource + "/" + $configId + "/assignments") -method "GET"
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

function Add-DeviceConfiguration {
    param(
        $authToken = $null,
        $prefix = "https://graph.microsoft.com/Beta/",
        $config = $null
    )

    $resource = "deviceManagement/deviceConfigurations"

    if ($null -eq $config) {
        "Please provide a Device Configuration. You can create those using Import-PolicyObject."
        return
    }

    $config = $config | Select-Object -Property * -ExcludeProperty id, createdDateTime, lastModifiedDateTime, version

    $JSON = $config | ConvertTo-Json -Depth 6

    Execute-GraphRestRequest -authToken $authToken -prefix $prefix -resource $resource -method "POST" -body $JSON -onlyValues $false

}

function Assign-DeviceConfiguration {
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

    Execute-GraphRestRequest -authToken $authToken -prefix $prefix -resource ($resource + "/" + $configId + "/assignments") -method "POST" -body $JSON -onlyValues $false
}

function Assign-DeviceConfigurationToGroup {
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

    Assign-DeviceConfiguration -configId $configId -authToken $authToken -prefix $prefix -target $target

}

function Exclude-DeviceConfigurationFromGroup {
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

    Assign-DeviceConfiguration -configId $configId -authToken $authToken -prefix $prefix -target $target

}

#endregion 

## Experiments from here on down

#region Windows Autopilot profiles

function Get-AutopilotProfiles {
    param(
        $authToken = $null,
        $prefix = "https://graph.microsoft.com/Beta/"
    )

    $resource = "deviceManagement/windowsAutopilotDeploymentProfiles"

    Execute-GraphRestRequest -authToken $authToken -prefix $prefix -resource $resource -method "GET"
}

#TODO: Add-AutopilotProfiles

#endregion

#region (not used) (Mobile) Imported Devices

function Get-ImportedMobileDevices {
    param(
        $authToken = $null,
        $prefix = "https://graph.microsoft.com/Beta/"
    )

    $resource = "/deviceManagement/importedDeviceIdentities"

    Execute-GraphRestRequest -authToken $authToken -prefix $prefix -resource $resource -method "GET"
}

#endregion

#region (not used) Autopilot Imported Devices

function Get-ImportedAutopilotDevices {
    param(
        $authToken = $null,
        $prefix = "https://graph.microsoft.com/Beta/"
    )

    $resource = "/deviceManagement/importedWindowsAutopilotDeviceIdentities"

    Execute-GraphRestRequest -authToken $authToken -prefix $prefix -resource $resource -method "GET"
}

#endregion

#region Managed Devices
function Get-ManagedDevices {
    param(
        $authToken = $null,
        $prefix = "https://graph.microsoft.com/Beta/"
    )

    $resource = "/deviceManagement/managedDevices"

    Execute-GraphRestRequest -authToken $authToken -prefix $prefix -resource $resource -method "GET"
}

#endregion

#region (SharePoint) Sites

function Get-RootSite {
    param(
        $authToken = $null,
        $prefix = "https://graph.microsoft.com/V1.0/"

    )

    $resource = "/sites/root"

    Execute-GraphRestRequest -authToken $authToken -prefix $prefix -resource $resource -method "GET" -onlyValues $false
}

#endregion

#region Files (OneDrive, OneDriveFB/SharePoint)

function Get-MyDrives {
    param(
        $authToken = $null,
        $prefix = "https://graph.microsoft.com/V1.0/"

    )

    $resource = "/me/drives"

    Execute-GraphRestRequest -authToken $authToken -prefix $prefix -resource $resource -method "GET"
}

#endregion