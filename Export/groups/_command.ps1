$groupObjects = Get-AADGroups
Export-PolicyObjects -policies $groupObjects 