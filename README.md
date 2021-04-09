# MEMPSToolkit

MEMPSToolkit is a collection of functions to interact with MS Graph API.

It was designed to not use external dependencies and to purely use REST Calls.

To authenticate 
```powershell
$token = Get-AppLoginToken -tenant "CONTOSO" -clientID "SomeGUID" -secretValue $secureStringCred
```