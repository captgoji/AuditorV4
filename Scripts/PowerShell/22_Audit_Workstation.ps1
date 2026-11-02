# 22_Audit_Workstation.ps1
# Version      : 1.0
# Derniere modif : Derive de 21_Audit_VMs - meme schema de sortie, cible les postes Windows
# Role         : Inventaire poste Windows : OS, IP, roles, hyperviseur KVP, WinRM, activation, FSMO
#                Memes colonnes que l'audit VM, sortie CSV dediee (*_Audit_Workstation.csv,
#                feuille Workstations) ; les champs serveur (FSMO, replication, KVP) -> '-'.
# Usage        : Lance via main.ps1, ou a distance par _00_Reconnaissance.ps1 (PsExec).
# ============================================================
$tempCsv = $env:AUDIT_TEMP_CSV
$CompSys    = Get-CimInstance Win32_ComputerSystem
$OS         = Get-CimInstance Win32_OperatingSystem          # FIX : Caption est sur Win32_OperatingSystem
$NetAdapters = Get-CimInstance Win32_NetworkAdapterConfiguration -Filter "IPEnabled = True"
$BIOS       = Get-CimInstance Win32_BIOS
$IsDomainJoined = $CompSys.PartOfDomain
$DomainName = $CompSys.Domain
$ExportFile = "$tempCsv\VM\$env:COMPUTERNAME.$DomainName" + "_Audit_Workstation.csv"

# Creer le sous-dossier si absent
$null = New-Item -ItemType Directory -Force -Path (Split-Path $ExportFile)

# Test WinRM
$WinRMStatus = try {
    Test-WSMan -ComputerName localhost -ErrorAction Stop | Out-Null
    "Active"
} catch { "Desactive" }

# Activation cle windows
$WinActivate = (Get-CimInstance -ClassName SoftwareLicensingProduct |
    Where-Object { $_.PartialProductKey -and $_.LicenseStatus -eq 1 }).LicenseStatus
$WinActivateStatus = if ($WinActivate -eq 1) { "Oui" } else { "Non" }

# MAC & IP
$IPs  = $NetAdapters | ForEach-Object { $_.IPAddress } |
        Where-Object { $_ -match '^\d{1,3}(\.\d{1,3}){3}$' } | Select-Object -Unique
$MACs = $NetAdapters | ForEach-Object { $_.MACAddress } |
        Where-Object { $_ } | Select-Object -Unique

# Detection hyperviseur via KVP Hyper-V (depuis l'interieur d'une VM)
function Get-HyperVHostInfo {
    $reg  = 'HKLM:\SOFTWARE\Microsoft\Virtual Machine\Guest\Parameters'
    $info = [ordered]@{ HostFQDN=$null; HostShort=$null; Status=$null; Detail=$null }

    $svc = Get-Service -Name vmickvpexchange -ErrorAction SilentlyContinue
    if (-not $svc) {
        $info.Status = "Integrations absentes"
        $info.Detail = "Service vmickvpexchange introuvable dans l invite"
        return [pscustomobject]$info
    }
    if ($svc.Status -ne 'Running') {
        $info.Status = "KVP arrete"
        $info.Detail = "Start-Service vmickvpexchange | Set-Service vmickvpexchange -StartupType Automatic"
        return [pscustomobject]$info
    }

    try {
        $p = Get-ItemProperty -Path $reg -ErrorAction Stop
        $info.HostFQDN  = $p.PhysicalHostNameFullyQualified
        $info.HostShort = if ($p.PhysicalHostName) { $p.PhysicalHostName } else { $null }
        if ($info.HostFQDN -or $info.HostShort) {
            $info.Status = "OK"
            $info.Detail = "Lu via KVP (registre invite)"
        } else {
            $info.Status = "Valeurs vides"
            $info.Detail = "KVP actif mais l hote ne publie pas les noms"
        }
    } catch {
        $info.Status = "Cles absentes"
        $info.Detail = "Probable desactivation KVP sur cet hote"
    }

    [pscustomobject]$info
}

$hv      = Get-HyperVHostInfo
$HV_FQDN = if ($hv.HostFQDN) { $hv.HostFQDN } elseif ($hv.HostShort) { $hv.HostShort } else { "-" }

# FIX : $cs etait indefini dans le bloc default, remplace par $CompSys
$hypervisor = switch -Regex ($CompSys.Manufacturer) {
    "VMware"    { "VMware/ESXi"  ; break }
    "Microsoft" { "Hyper-V"      ; break }
    "QEMU"      { "KVM/Proxmox"  ; break }
    "Xen"       { "Xen"          ; break }
    "HPE"       { "Hyper-V HPE"  ; break }
    default {
        if ($CompSys.Model -match "VirtualBox") { "VirtualBox" }
        else { "-" }
    }
}

# Roles et fonctionnalites installes
$RolesServices = try {
    if (Get-Command Get-WindowsFeature -ErrorAction SilentlyContinue) {
        (Get-WindowsFeature | Where-Object InstallState -eq "Installed").Name -join " - "
    } else { "-" }   # OS client : pas de roles Windows Server
} catch { "-" }

# Roles FSMO (uniquement sur un DC)
$FSMORoles = "-"
try {
    $domain  = Get-ADDomain -ErrorAction Stop
    $forest  = Get-ADForest -ErrorAction Stop
    $fsmo    = @()

    if ($domain.PDCEmulator          -like "*$env:COMPUTERNAME*") { $fsmo += "PDC Emulator" }
    if ($domain.RIDMaster            -like "*$env:COMPUTERNAME*") { $fsmo += "RID Master" }
    if ($domain.InfrastructureMaster -like "*$env:COMPUTERNAME*") { $fsmo += "Infrastructure Master" }
    if ($forest.SchemaMaster         -like "*$env:COMPUTERNAME*") { $fsmo += "Schema Master" }
    if ($forest.DomainNamingMaster   -like "*$env:COMPUTERNAME*") { $fsmo += "Domain Naming Master" }

    if ($fsmo.Count -gt 0) { $FSMORoles = $fsmo -join " - " }
} catch { $FSMORoles = "-" }

function Get-ReplDestinationDSA {
    [CmdletBinding()]
    param(
        [string[]]$Lines = $null
    )

    # Appel repadmin uniquement si disponible
    if ($null -eq $Lines) {
        if (-not (Get-Command repadmin -ErrorAction SilentlyContinue)) {
            return @()
        }
        $Lines = repadmin /replsummary 2>&1
    }

    if (-not $Lines -or $Lines.Count -eq 0) { return @() }

    $norm = $Lines | ForEach-Object { ($_ -replace '[\u00A0\u2007\u202F]', ' ') -replace '\s+$','' }

    $header = $norm | Select-String -Pattern '^\s*DSA de destination\b' | Select-Object -First 1
    if (-not $header) { return @() }

    $list = New-Object System.Collections.Generic.List[string]

    for ($i = [int]$header.LineNumber; $i -lt $norm.Count; $i++) {
        $line = $norm[$i]
        if ($line -match '^\s*DSA (source|de destination)\b') { break }
        if ([string]::IsNullOrWhiteSpace($line)) { continue }

        if ($line -match '^\s*(?<DSA>\S+)\s+\d') {
            $null = $list.Add($matches.DSA.Trim())
            continue
        }
        $cells = ($line -split '\s{2,}') | Where-Object { $_ -ne '' }
        if ($cells.Count -gt 0) {
            $dsa = $cells[0].Trim()
            if ($dsa -and ($dsa -notmatch '^DSA\s')) { $null = $list.Add($dsa) }
        }
    }

    return $list | Sort-Object -Unique
}

$destList = Get-ReplDestinationDSA
if ($destList) {
    $DSAStatus = "Oui"
    $destDSA   = $destList -join ' - '
} else {
    $DSAStatus = "Non"
    $destDSA   = "-"
}

$Result = [PSCustomObject]@{
    "Nom poste"          = $env:COMPUTERNAME
    "IP"                 = ($IPs  -join " - ")
    "Adresse MAC"        = ($MACs -join " - ")
    "S/N"                = $BIOS.SerialNumber
    "OS"                 = $OS.Caption                        # FIX : Win32_OperatingSystem
    "Roles/Services"     = $RolesServices
    "Integre au domaine" = $IsDomainJoined
    "Nom de Domaine"     = $DomainName
    "Hyperviseur hote"   = $HV_FQDN
    "Type HV"            = $hypervisor
    "WinRM"              = $WinRMStatus
    "Diag HV/KVP"        = "$($hv.Status) - $($hv.Detail)"
    "Replication"        = $DSAStatus
    "Dest replication"   = $destDSA
    "Windows Active"     = $WinActivateStatus
    "Roles FSMO"         = $FSMORoles
}

$Result | Export-Csv -Path $ExportFile -NoTypeInformation -Encoding UTF8
Write-Host "Rapport genere : $ExportFile"