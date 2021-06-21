# This script will create a visual representation of your Conditional Access Policies in mermaid.
# 
# It will dump every policy to one file in the current directory.
#
# (c) 2021 Hans-Carl Oberdalhoff
#
# Version 0.1

Import-Module MEMPSToolkit -MinimumVersion "0.0.19"

param(
    # Use Get-AppLoginToken to authenticate to MS Graph
    $authToken,
    # Write HTML files (with mermaid rendered in the browser)
    [bool] $asHTML = $true,
    # Write Markdown. If both are present, HTML is prefered.
    [bool] $asMarkdown = $false
)

# Create Application Mapping table
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
}
# Add our own
$apps = Invoke-GraphRestRequest -resource "/applications" -authToken $authToken
$apps | ForEach-Object {
    $appMapping[$_.appId] = $_.displayName
}

function Resolve-AppName {
    param(
        [string]$appId
    )

    if ($appMapping.ContainsKey($appId)) {
        '"' + $appMapping[$appId] + '"'
    }
    else {
        $appId
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
            '"' + $user.userPrincipalName + '"'
        }
        else {
            $_
        }
    }
    else {
        $_
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
            '"' + $group.displayName + '"'
        }
        else {
            $_
        }
    }
    else {
        $_
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
            '"' + $roleTemplate.displayName + '"'
        }
        else {
            $_
        }
    }
    else {
        $_
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
            '"' + $namedLocation.displayName + '"'
        }
        else {
            $_
        }
    }
    else {
        $_
    }
}


function Write-MermaidCAPol {
    param(
        $pol,
        [bool] $asHTML = $true,
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
    "id(`"$($pol.displayName)`") -----> state(state: $($pol.state))"

    if ($pol.conditions) {
        'id --> conditions'

        if ($pol.conditions.applications) {
            'conditions --> applications'
        
            if ($pol.conditions.applications.includeApplications) {
                'applications --> includeApplications'

                $pol.conditions.applications.includeApplications | ForEach-Object {
                    
                    "includeApplications --> a_$($_)($(Resolve-AppName -appId $_))"
                }
            }

            if ($pol.conditions.applications.excludeApplications) {
                'applications --> excludeApplications'

                $pol.conditions.applications.excludeApplications | ForEach-Object {
                    
                    "excludeApplications --> a_$($_)($(Resolve-AppName -appId $_))"
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
                    "includeUsers --> u_$($_)($(Resolve-Username -userId $_ -authToken $authToken))"
                }
            }

            if ($pol.conditions.users.excludeUsers) {
                'users --> excludeUsers'

                $pol.conditions.users.excludeUsers | ForEach-Object {
                    "excludeUsers --> u_$($_)($(Resolve-Username -userId $_ -authToken $authToken))"
                }
            }

            if ($pol.conditions.users.includeGroups) {
                'users --> includeGroups'

                $pol.conditions.users.includeGroups | ForEach-Object {
                    "includeGroups --> g_$($_)($(Resolve-Groupname -groupId $_ -authToken $authToken))"
                }
            }

            if ($pol.conditions.users.excludeGroups) {
                'users --> excludeGroups'

                $pol.conditions.users.excludeGroups | ForEach-Object {
                    "excludeGroups --> g_$($_)($(Resolve-Groupname -groupId $_ -authToken $authToken))"
                }
            }

            if ($pol.conditions.users.includeRoles) {
                'users --> includeRoles'

                $pol.conditions.users.includeRoles | ForEach-Object {
                    "includeRoles --> r_$($_)($(Resolve-RoleTemplateName -roleTemplateId $_ -authToken $authToken))"
                }
            }

            if ($pol.conditions.users.excludeRoles) {
                'users --> excludeRoles'

                $pol.conditions.users.excludeRoles | ForEach-Object {
                    "excludeRoles --> r_$($_)($(Resolve-RoleTemplateName -roleTemplateId $_ -authToken $authToken))"
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
                    "includeLocations --> l_$($_)($(Resolve-ConditionalAccessNamedLocationById -id $_ -authToken $authToken))"
                }
            }        

            if ($pol.conditions.locations.excludeLocations) {
                'locations --> excludeLocations'
            
                $pol.conditions.locations.excludeLocations | ForEach-Object {
                    "excludeLocations --> l_$($_)($(Resolve-ConditionalAccessNamedLocationById -id $_ -authToken $authToken))"
                }
            }        
        }

        if ($pol.conditions.platforms) {
            'conditions --> platforms'

            if ($pol.conditions.platforms.includePlatforms) {
                'platforms --> includePlatforms'

                $pol.conditions.platforms.includePlatforms | ForEach-Object {
                    "includePlatforms --> cap_$($_)($($_))"
                }
            }

            if ($pol.conditions.platforms.excludePlatforms) {
                'platforms --> excludePlatforms'

                $pol.conditions.platforms.excludePlatforms | ForEach-Object {
                    "excludePlatforms --> cap_$($_)($($_))"
                }
            }
        }

        if ($pol.conditions.signInRiskLevels) {
            'conditions --> signInRiskLevels'

            $pol.conditions.signInRiskLevels | ForEach-Object {
                "signInRiskLevels --> sirl_$($_)($($_))"
            }
        }

        if ($pol.conditions.userRiskLevels) {
            'conditions --> userRiskLevels'

            $pol.conditions.userRiskLevels | ForEach-Object {
                "userRiskLevels --> url_$($_)($($_))"
            }
        }
    }

    if ($pol.grantControls) {
        'id ---> grantControls'
        "grantControls --> grantControlsOperator(operator: $($pol.grantControls.operator))"

        if ($pol.grantControls.builtInControls) {
            'grantControls --> builtInControls'

            $pol.grantControls.builtInControls | ForEach-Object {
                "builtInControls --> bic_$($_)($($_))"
            }
        }

        if ($pol.grantControls.customAuthenticationFactors) {
            'grantControls --> customAuthenticationFactors'

            $pol.grantControls.customAuthenticationFactors | ForEach-Object {
                "customAuthenticationFactors --> cam_$($_)($($_))"
            }
        }

        if ($pol.grantControls.termsOfUse) {
            'grantControls --> termsOfUse'

            $pol.grantControls.termsOfUse | ForEach-Object {
                "termsOfUse --> tou_$($_)($($_))"
            }

        } 
    }
    if ($pol.sessionControls) {
        'id ---> sessionControls'

        if ($pol.sessionControls.applicationEnforcedRestrictions) {
            'sessionControls --> applicationEnforcedRestrictions'
            "applicationEnforcedRestrictions --> applicationEnforcedRestrictionsIsEnabled(isEnabled: $($pol.sessionControls.applicationEnforcedRestrictions.isEnabled))"
        }

        if ($pol.sessionControls.cloudAppSecurity) {
            'sessionControls --> cloudAppSecurity'
            "cloudAppSecurity --> cloudAppSecurityTypeIsEnabled(isEnabled: $($pol.sessionControls.cloudAppSecurity.isEnabled))"
            "cloudAppSecurity --> cloudAppSecurityType(cloudAppSecurityType: $($pol.sessionControls.cloudAppSecurity.cloudAppSecurityType))"
        }

        if ($pol.sessionControls.persistentBrowser) {
            'sessionControls --> persistentBrowser'
            "persistentBrowser --> persistentBrowserIsEnabled(isEnabled: $($pol.sessionControls.persistentBrowser.isEnabled))"
            "persistentBrowser --> persistentBrowserSessionMode(mode: $($pol.sessionControls.persistentBrowser.mode))"
        }

        if ($pol.sessionControls.signInFrequency) {
            'sessionControls --> signInFrequency'
            "signInFrequency --> signInFrequencyIsEnabled(isEnabled: $($pol.sessionControls.signInFrequency.isEnabled))"
            "signInFrequency --> signinFrequencyType(type: $($pol.sessionControls.signInFrequency.type))"
            "signInFrequency --> signinFrequencyValue(value: $($pol.sessionControls.signInFrequency.value))"
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


#region main script
$pols = Get-ConditionalAccessPolicies -authToken $authToken

$pols | ForEach-Object {
    $outfile = ($_.displayName -replace "[$([RegEx]::Escape([string][IO.Path]::GetInvalidFileNameChars()))]+", "_") 
    if ($asHTML) {
        $outfile += ".html"
    } elseif ($asMarkdown) {
        $outfile += ".md"
    } else {
        # "official file type for mermaid?"
        $outfile += ".mmd"
    }
    Write-MermaidCAPol -pol $_ -authToken $authToken -asHTML $asHTML -asMarkdown $asMarkdown > $outfile
}
#endregion
