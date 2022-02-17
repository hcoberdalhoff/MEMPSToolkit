# This will create a "Mermaid in HTML" visualization for a given Cond. Access Policy
# You will need the following permission at least:
# - Policy.Read.All
# To also resolve object name, also you will need:
# - Application.Read.All [for apps to be queried]# 
# - GroupMember.Read.All [for group names to be resolved]
# - User.Read [default/delegated permission]
# - User.Read.All [for user names to be resolved]

# Read the policy
$pol = Import-PolicyObject -filename .\Demo_CAP.json

# Create the visualization. If you want to resolve object id, please make sure to pass an auth token using "-authToken".
Write-ConditionalAccessPolicyToMermaid -pol $pol -asHTML $true > output.html

