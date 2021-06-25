# This script will create a visual representation of your Conditional Access Policies in mermaid.
# 
# It will dump every policy to one file in the current directory.
#
# (c) 2021 Hans-Carl Oberdalhoff
#
# Version 0.1

#Requires -Module @{ModuleName = "MEMPSToolkit"; ModuleVersion = "0.0.21" }

param(
    # Use Get-AppLoginToken to authenticate to MS Graph
    $authToken = $null,
    # Write HTML files (with mermaid rendered in the browser)
    [bool] $asHTML = $true,
    # Write Markdown. If both are present, HTML is prefered.
    [bool] $asMarkdown = $false
)

#region main script
$pols = Get-ConditionalAccessPolicies -authToken $authToken

$pols | ForEach-Object {
    $outfile = ($_.displayName -replace "[$([RegEx]::Escape([string][IO.Path]::GetInvalidFileNameChars()))]+", "_") 
    if ($asHTML) {
        $outfile += ".html"
    }
    elseif ($asMarkdown) {
        $outfile += ".md"
    }
    else {
        # "official file type for mermaid?"
        $outfile += ".mmd"
    }
    Write-ConditionalAccessPolicyToMermaid -pol $_ -authToken $authToken -asHTML $asHTML -asMarkdown $asMarkdown > $outfile
}
#endregion
