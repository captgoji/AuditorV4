# 13_Arborescence_OU.ps1
# Version      : 1.2
# Derniere modif : Ajout header standard
# Role         : Genere l arborescence des OUs Active Directory en fichier texte
# Usage        : Lance via main.ps1. Necessite RSAT AD sur DC.
# ============================================================
: UTF-8
$OutputEncoding = [System.Text.Encoding]::UTF8
# [Console]::OutputEncoding peut planter en contexte WinRM (pas de handle console)
try { [Console]::OutputEncoding = [System.Text.Encoding]::UTF8 } catch {}

$tempCsv = $env:AUDIT_TEMP_CSV
$CompSys  = Get-CimInstance Win32_ComputerSystem
$DomainName = $CompSys.Domain

$rootDN = (Get-ADDomain).DistinguishedName
$ous    = Get-ADOrganizationalUnit -Filter * -Properties DistinguishedName |
          Select-Object Name, DistinguishedName

$children = @{}
foreach ($ou in $ous) {
    $dn  = $ou.DistinguishedName
    $idx = $dn.IndexOf(",")
    if ($idx -gt 0) {
        $parent = $dn.Substring($idx + 1)
        if (-not $children.ContainsKey($parent)) { $children[$parent] = @() }
        $children[$parent] += $ou
    }
}

function Print_OU {
    param(
        [object]$Node,
        [string]$Prefix,
        [bool]$IsLast,
        [System.Collections.Generic.List[string]]$Lines
    )

    # Utiliser des chaines ASCII pour eviter les problemes d encodage
    $connector   = if ($IsLast) { "+--" } else { "|--" }
    $childPrefix = if ($IsLast) { $Prefix + "   " } else { $Prefix + "|  " }

    $Lines.Add("$Prefix$connector $($Node.Name)")

    if ($children.ContainsKey($Node.DistinguishedName)) {
        $childList = $children[$Node.DistinguishedName]
        for ($i = 0; $i -lt $childList.Count; $i++) {
            $lastChild = ($i -eq $childList.Count - 1)
            Print_OU -Node $childList[$i] -Prefix $childPrefix -IsLast $lastChild -Lines $Lines
        }
    }
}

$lines = New-Object System.Collections.Generic.List[string]
$lines.Add("Arborescence AD : $DomainName")
$lines.Add("")

if ($children.ContainsKey($rootDN)) {
    $rootChildren = $children[$rootDN]
    for ($i = 0; $i -lt $rootChildren.Count; $i++) {
        $isLast = ($i -eq $rootChildren.Count - 1)
        Print_OU -Node $rootChildren[$i] -Prefix "" -IsLast $isLast -Lines $lines
    }
}

# Export dans Temp_CSV comme les autres scripts
$ExportFile = "$tempCsv\$env:COMPUTERNAME.$DomainName`_AD_OU_Tree.txt"
$lines | Out-File $ExportFile -Encoding UTF8

Write-Host "Arborescence generee : $ExportFile"