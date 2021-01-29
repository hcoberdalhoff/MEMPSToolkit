#Load Module
. .\MEMPSModule.ps1

# Login using App-Credentials
# (Load Client Secret from encrypted file, login, store token in encrypted file)
Save-AppLoginToken -authToken (Get-AppLoginFromFile)