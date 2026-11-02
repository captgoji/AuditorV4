# 70_Audit_Linux.ps1
# Version      : 1.0 (V3)
# Derniere modif : Creation - audit SSH Linux basique
# Role         : Audit SSH Linux : OS, hostname, utilisateurs, services, interfaces
# Usage        : Lance via main.ps1 ou via 00_Reconnaissance.ps1 (audit distant SSH)
# ============================================================

$ErrorActionPreference = "Continue"

$tempCsv    = $env:AUDIT_TEMP_CSV
$CompSys    = Get-CimInstance Win32_ComputerSystem -ErrorAction SilentlyContinue
$DomainName = if ($CompSys) { $CompSys.Domain } else { "WORKGROUP" }
$ExportFile = "$tempCsv\$env:COMPUTERNAME.${DomainName}_Audit_Linux.csv"

# Ce script est destine a etre copie et execute sur une machine distante
# via 00_Reconnaissance.ps1 -> Audit-Linux
# Il peut aussi servir a auditer la machine locale si c est un Linux sous WSL
# Dans la plupart des cas, il ne fait rien de special sur Windows

Write-Host "70_Audit_Linux : ce script est execute sur $env:COMPUTERNAME"
Write-Host "L audit Linux se fait via SSH depuis 00_Reconnaissance.ps1"
Write-Host "Aucune action locale sur une machine Windows."