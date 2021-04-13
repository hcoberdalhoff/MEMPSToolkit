#
# Module manifest for module 'MEMPSToolkit'
#
# Generated by: Hans-Carl Oberdalhoff
#
# Generated on: 09.04.2021
#
<#

.SYNOPSIS
    MEMPSToolkit is a collection of functions to interact with MS Graph API.
    
.DESCRIPTION
    It was designed to not use external dependencies and to purely use REST Calls.

.DISCLAIMER
	THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
	ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED TO
	THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
	PARTICULAR PURPOSE.

#>

@{

# Script module or binary module file associated with this manifest.
RootModule = 'MEMPSToolkit.psm1'

# Version number of this module.
ModuleVersion = '0.0.7'

# Supported PSEditions
# CompatiblePSEditions = @()

# ID used to uniquely identify this module
GUID = 'd6083b6e-d224-4c2f-b93a-569654b34221'

# Author of this module
Author = 'Hans-Carl Oberdalhoff'

# Company or vendor of this module
CompanyName = 'PRIMEPULSE SE, glueckkanja-GAB AG'

# Copyright statement for this module
Copyright = '(c) PRIMEPULSE SE and glueckkanja-GAB AG. All rights reserved.'

# Description of the functionality provided by this module
Description = 'Simple, inclomplete toolkit to interact with MS Graph. 
It was designed to not use external dependencies and to purely use REST Calls.'

# Minimum version of the PowerShell engine required by this module
PowerShellVersion = '5.1'

# Name of the PowerShell host required by this module
# PowerShellHostName = ''

# Minimum version of the PowerShell host required by this module
# PowerShellHostVersion = ''

# Minimum version of Microsoft .NET Framework required by this module. This prerequisite is valid for the PowerShell Desktop edition only.
# DotNetFrameworkVersion = ''

# Minimum version of the common language runtime (CLR) required by this module. This prerequisite is valid for the PowerShell Desktop edition only.
# ClrVersion = ''

# Processor architecture (None, X86, Amd64) required by this module
# ProcessorArchitecture = ''

# Modules that must be imported into the global environment prior to importing this module
# RequiredModules = @()

# Assemblies that must be loaded prior to importing this module
# RequiredAssemblies = @()

# Script files (.ps1) that are run in the caller's environment prior to importing this module.
# ScriptsToProcess = @()

# Type files (.ps1xml) to be loaded when importing this module
# TypesToProcess = @()

# Format files (.ps1xml) to be loaded when importing this module
# FormatsToProcess = @()

# Modules to import as nested modules of the module specified in RootModule/ModuleToProcess
# NestedModules = @()

# Functions to export from this module, for best performance, do not use wildcards and do not delete the entry, use an empty array if there are no functions to export.
FunctionsToExport = @(
    "Export-AppLoginSecret",
    "Get-AppLoginFromSavedSecret",
    "Get-AppLoginToken",
    "Get-AzAutomationCredLoginToken",
    "Export-AppLoginToken",
    "Import-AppLoginToken",
    "Remove-AppLoginToken",
    "Get-DeviceLoginToken",
    "Invoke-GraphRestRequest",
    "Export-PolicyObjects",
    "Import-PolicyObject",
    "Get-AADGroups",
    "Add-AADGroupFromObject",
    "Add-AADGroup",
    "Get-AADGroupById",
    "Get-AADGroupByName",
    "Add-AADGroupFromFile",
    "Get-AADGroupMembers",
    "Add-AADGroupMember",
    "Remove-AADGroupMember",
    "Get-AADUsers",
    "Get-AADUserByID",
    "Get-AADUserByUPN",
    "Get-CompliancePolicies",
    "Get-CompliancePolicyByName",
    "Add-CompliancePolicy",
    "Set-CompliancePolicyToGroupAssignment",
    "Get-ConditionalAccessPolicies",
    "Add-ConditionalAccessPolicy",
    "Get-DeviceConfigurations",
    "Get-DeviceConfigurationById",
    "Get-DeviceConfigurationAssignmentById",
    "Export-DeviceConfigurationsAndAssignments",
    "Add-DeviceConfiguration",
    "Set-DeviceConfigurationAssignment",
    "Set-DeviceConfigurationAssignmentToGroup",
    "Set-DeviceConfigurationFromGroupExclusion",
    "Get-DeviceConfigurationPolicies",
    "Get-DeviceConfigurationPolicySettingsById",
    "Get-AADApps",
    "Get-AADAppById",
    "Add-AADApp",
    "Remove-AADAppById",
    "Add-AADAppPassword",
    "Get-ServicePrincipals",
    "Add-ServicePrincipalByAppId",
    "Get-ServicePrincipalAppRoleAssignmentsById",
    "Add-ServicePrincipalAppRoleAssignment",
    "Add-ServicePrincipalPassword",
    "Get-AutopilotProfiles",
    "Get-ImportedMobileDevices",
    "Get-ImportedAutopilotDevices",
    "Get-ManagedDevices",
    "Get-SPRootSite",
    "Get-SPAllSites",
    "Get-SPSite",
    "Get-SPSiteDriveById",
    "Get-DriveById",
    "Get-SPSite",
    "Get-SPSiteDriveById"
    "Get-DriveById",
    "Get-DriveChildrenByPath",
    "Get-DriveItemVersions",
    "Get-MyDrives",
    "Get-MyCalendars",
    "Get-CalendarEvents",
    "Get-MyMails",
    "Get-MyMailById",
    "Get-MyTeams",
    "Get-TeamsChannels",
    "Get-TeamsChannelMessages",
    "Get-TeamsChannelMessageById",
    "Get-TeamsChannelMessageHostedContents",
    "Get-TeamsChannelMessageReplies"
    )

# Cmdlets to export from this module, for best performance, do not use wildcards and do not delete the entry, use an empty array if there are no cmdlets to export.
CmdletsToExport = @()

# Variables to export from this module
VariablesToExport = '*'

# Aliases to export from this module, for best performance, do not use wildcards and do not delete the entry, use an empty array if there are no aliases to export.
AliasesToExport = @()

# DSC resources to export from this module
# DscResourcesToExport = @()

# List of all modules packaged with this module
# ModuleList = @()

# List of all files packaged with this module
# FileList = @()

# Private data to pass to the module specified in RootModule/ModuleToProcess. This may also contain a PSData hashtable with additional module metadata used by PowerShell.
PrivateData = @{

    PSData = @{

        # Tags applied to this module. These help with module discovery in online galleries.
        # Tags = @()

        # A URL to the license for this module.
        LicenseUri = 'https://github.com/hcoberdalhoff/MEMPSToolkit/blob/master/LICENSE'

        # A URL to the main website for this project.
        ProjectUri = 'https://github.com/hcoberdalhoff/MEMPSToolkit'

        # A URL to an icon representing this module.
        # IconUri = ''

        # ReleaseNotes of this module
        # ReleaseNotes = ''

        # Prerelease string of this module
        # Prerelease = ''

        # Flag to indicate whether the module requires explicit user acceptance for install/update/save
        # RequireLicenseAcceptance = $false

        # External dependent modules of this module
        # ExternalModuleDependencies = @()

    } # End of PSData hashtable

} # End of PrivateData hashtable

# HelpInfo URI of this module
# HelpInfoURI = ''

# Default prefix for commands exported from this module. Override the default prefix using Import-Module -Prefix.
# DefaultCommandPrefix = ''

}

