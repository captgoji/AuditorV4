# 20_Audit_VMs.ps1
# Version      : 1.5
# Derniere modif : Ajout de la synchronisation de l'heure (type, serveur(s) NTP configure(s), source actuelle)
# Role         : Inventaire VM : OS, IP, roles, hyperviseur KVP, WinRM, replication, activation, FSMO, NTP
# Usage        : Lance via main.ps1. Fonctionne sur tout serveur Windows.
# ============================================================
$tempCsv = $env:AUDIT_TEMP_CSV
$CompSys    = Get-CimInstance Win32_ComputerSystem
$OS         = Get-CimInstance Win32_OperatingSystem          # FIX : Caption est sur Win32_OperatingSystem
$NetAdapters = Get-CimInstance Win32_NetworkAdapterConfiguration -Filter "IPEnabled = True"
$BIOS       = Get-CimInstance Win32_BIOS
$IsDomainJoined = $CompSys.PartOfDomain
$DomainName = $CompSys.Domain
$ExportFile = "$tempCsv\VM\$env:COMPUTERNAME.$DomainName" + "Audit_VMs.csv"

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
    (Get-WindowsFeature | Where-Object InstallState -eq "Installed").Name -join " - "
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

# Synchronisation de l'heure (service W32Time)
# Configuration lue dans le registre (independant de la langue) ; une GPO
# (HKLM\SOFTWARE\Policies\Microsoft\W32Time\Parameters) prime sur la configuration locale.
function Get-NtpInfo {
    $info = [ordered]@{ Type = "-"; Serveurs = "-"; Source = "-" }
    $local  = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\Parameters' -ErrorAction SilentlyContinue
    $policy = Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\W32Time\Parameters' -ErrorAction SilentlyContinue

    $type = $local.Type; $serveurs = $local.NtpServer; $origine = ""
    if ($policy -and $policy.Type)      { $type     = $policy.Type;      $origine = " (GPO)" }
    if ($policy -and $policy.NtpServer) { $serveurs = $policy.NtpServer; $origine = " (GPO)" }

    $info.Type = switch ($type) {
        "NT5DS"   { "Hierarchie du domaine (NT5DS)" }
        "NTP"     { "Serveur(s) NTP (NTP)" }
        "AllSync" { "Domaine + NTP (AllSync)" }
        "NoSync"  { "Aucune synchronisation (NoSync)" }
        default   { if ($type) { $type } else { "-" } }
    }
    $info.Type += $origine

    # "time.windows.com,0x9 pool.ntp.org,0x1" -> "time.windows.com - pool.ntp.org"
    # En NT5DS la liste NtpServer n'est pas utilisee (l'heure vient de la hierarchie du domaine)
    if ($type -eq "NT5DS") {
        $info.Serveurs = "- (non utilise en NT5DS)"
    } elseif ($serveurs) {
        $info.Serveurs = (($serveurs -split '\s+') | Where-Object { $_ } | ForEach-Object { ($_ -split ',')[0] }) -join " - "
    }

    $svc = Get-Service -Name W32Time -ErrorAction SilentlyContinue
    if (-not $svc -or $svc.Status -ne 'Running') {
        $info.Source = "Service W32Time arrete"
    } else {
        $src = (& w32tm /query /source 2>$null | Where-Object { $_ -and $_.Trim() } | Select-Object -First 1)
        if ($LASTEXITCODE -eq 0 -and $src) { $info.Source = $src.Trim() } else { $info.Source = "Inconnue" }
    }
    return [pscustomobject]$info
}
$ntp = Get-NtpInfo

$Result = [PSCustomObject]@{
    "Nom VM"             = $env:COMPUTERNAME
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
    "NTP Type"           = $ntp.Type
    "NTP Serveur(s)"     = $ntp.Serveurs
    "NTP Source"         = $ntp.Source
}

$Result | Export-Csv -Path $ExportFile -NoTypeInformation -Encoding UTF8
Write-Host "Rapport genere : $ExportFile"