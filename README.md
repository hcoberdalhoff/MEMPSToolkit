# MEMPSToolkit

MEMPSToolkit is a collection of functions to interact with MS Graph API.

It was designed to not use external dependencies and to purely use REST Calls.

This readme and the scripts are still under heavy initial development.

## Authenticate 

Using a Service Principal / AppRegistration:

```powershell
$token = Get-AppLoginToken -tenant "CONTOSO" -clientID "SomeGUID" -secretValue $secureStringCred
```