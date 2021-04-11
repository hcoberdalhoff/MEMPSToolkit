# MEMPSToolkit

MEMPSToolkit is a collection of functions to interact with MS Graph API.

It was designed to not use external dependencies and to purely use REST Calls.

This readme and the scripts are still under heavy initial development.

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
