# MEMPSToolkit

MEMPSToolkit is a collection of functions to interact with MS Graph API.

It was designed to not use external dependencies and to purely use REST Calls.

This readme and the scripts are still under heavy initial development.

## Not official

This is not an MS-supported project. If you want the official MS-supported PowerShell-SDK for MS Graph, please visit [https://github.com/microsoftgraph/msgraph-sdk-powershell](https://github.com/microsoftgraph/msgraph-sdk-powershell)

## Basic Concepts

Where possible the `Get-` functions will return custom PowerShell objects that you can directly interact with.

```powershell
PS ~> Get-AADGroupByName -groupName "DemoGroup"

id                            : 3d9609c3-c5f0-48dd-....
deletedDateTime               :
classification                :
createdDateTime               : 02.12.2020 11:50:37
creationOptions               : {ProvisionGroupHomepage, HubSiteId:00000000-0000-0000-0000-000000000000,
                                SPSiteLanguage:1031}
description                   : DemoGroup
displayName                   : DemoGroup
...
```

And, where possible you can use this object as a template to create a new object using `Add-` functions.

```powershell
# Get a template
PS ~> $policy = Get-CompliancePolicyByName -policyName "Win10 Compliance Policy"
# Rename and modify
PS ~> $policy.displayName = "New Win10 Compliance Policy"
PS ~> $policy.passwordRequired = "True"
# Create the new policy
PS ~> Add-CompliancePolicy -policy $policy
```

Be aware, some policies will not export / import using the "v1.0" api endpoints of Intune, but only when using "beta". 

If your results are incomplete, try appending `-prefix "https://graph.microsoft.com/beta/"` to your commands. The stable "v1.0" is default where possible.


## Authenticate against MS Graph

### Using a Service Principal / AppRegistration

You will need your ClientID and Secret either in cleartext or have the Secret as PowerShell SecureString.

```powershell
$token = Get-AppLoginToken -tenant "contoso.com" -clientID "00000000-1111-2222-3333-444444444444" -secretValue $secureStringSecret
```
or
```powershell
$token = Get-AppLoginToken -tenant "contoso.com" -clientID "00000000-1111-2222-3333-444444444444" -secretValue "S3cretV@lue"
```

Be aware, right now this creates plain access tokens. There is no management / use of refresh tokens.  

### Storing credentials

Using `Export-AppLoginSecret` you can encrypt and store credentials for sign to avoid typing your secret repeatedly.

```powershell
Export-AppLoginSecret -clientId "00000000-1111-2222-3333-444444444444" -tenant "contoso.com" -secretValue "S3cretV@lue"
```
you can then use `Get-AppLoginFromSavedSecret` to authenticate directly from those credentials.

```powershell
$token = Get-AppLoginFromSavedSecret
```
With `Export-AppLoginToken` you can also store a token as default token, if you only use one identity. 

```powershell
Export-AppLoginToken -authToken $token
```

You can now omit specifying a token for all future requests, as long as the token is valid. As already mentioned - currently there is no use of refresh tokens.

## Samples

In the [samples](samples/) folder you will find short scripts, demonstrating

- importing / exporting compliance policies
- importing / exporting conditional access policies
- importing / exporting "old style" Device Configurations
- exporting "new style" Device Settings
- creating an AAD application
- assigning roles/permissions to an AAD application
- reading / creating AAD groups

## PSGallery

This module is available in the [PowerShell Gallery](https://www.powershellgallery.com/packages/MEMPSToolkit)

## Word of Warning

This toolkit is far from complete and does not do enough error handling right now. Tread carefully.
