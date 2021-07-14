# This will create a "Mermaid in HTML" visualization for a given Cond. Access Policy

# Read the policy
$pol = Import-PolicyObject -filename .\Demo_CAP.json

# Create the visualization. If you want to resolve object id, please make sure to pass an auth token using "-authToken".
Write-ConditionalAccessPolicyToMermaid -pol $pol -asHTML $true > output.html

