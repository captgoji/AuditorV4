# 40_Audit_Hyperviseurs.ps1
# Version      : 1.3
# Derniere modif : Ajout header standard
# Role         : Inventaire hyperviseur Hyper-V : CPU, RAM, stockage, VMs hebergees, cluster
# Usage        : Lance via main.ps1. Necessite le role Hyper-V installe.
# ============================================================
$tempCsv = $env:AUDIT_TEMP_CSV
$CompSys = Get-CimInstance Win32_ComputerSystem
$DomainName = $CompSys.Domain
$ExportFile = "$tempCsv\HV\$env:COMPUTERNAME.$DomainName" + "_Audit_Hyperviseurs.csv"
$null = New-Item -ItemType Directory -Force -Path (Split-Path $ExportFile)
$ComputerName = $env:COMPUTERNAME

$HyperVModuleLoaded = $false
$FailoverModuleLoaded = $false
try { Get-Module Hyper-V -ErrorAction Stop; $HyperVModuleLoaded = $true } catch { Write-Warning "Module Hyper-V indisponible" }
try { Get-Module FailoverClusters -ErrorAction Stop; $FailoverModuleLoaded = $true } catch { }

# Infos système (CIM)
try {
    $cs        = Get-CimInstance Win32_ComputerSystem
    $cpuNames  = (Get-CimInstance Win32_Processor | Select-Object -ExpandProperty Name -Unique)  -join " - "
    $memGB     = "{0:N2} Go" -f ($cs.TotalPhysicalMemory / 1GB)

    $adapters  = Get-CimInstance Win32_NetworkAdapterConfiguration -Filter "IPEnabled=True"
    $ipPhys    = ($adapters | Where-Object { $_.Description -notlike "*Hyper-V Virtual Ethernet Adapter*" } | ForEach-Object IPAddress | Where-Object { $_ -match '^\d+\.\d+\.\d+\.\d+$' }) -join " - "
    $ipVeth    = ($adapters | Where-Object { $_.Description -like "*Hyper-V Virtual Ethernet Adapter*" }  | ForEach-Object IPAddress | Where-Object { $_ -match '^\d+\.\d+\.\d+\.\d+$' }) -join " - "
    $macs      = ($adapters.MACAddress | Select-Object -Unique)  -join " - "

    $roles = try {
        (Get-WindowsFeature -ComputerName $ComputerName | Where-Object { $_.InstallState -eq 'Installed' }).Name -join " - "
    } catch { "Non applicable" }

    $isDomain  = $cs.PartOfDomain
    $domain    = if ($isDomain) { $cs.Domain } else { "WORKGROUP" }
}
catch {
    throw "Impossible de collecter les infos CIM sur $ComputerName : $_"
}

# VMs hebergees + IP invite (si services d’integration OK)
$vmNames = ""
if ($HyperVModuleLoaded) {
    try {
        $vms    = Get-VM -ComputerName $ComputerName
        $vmNames = ($vms | Select-Object -ExpandProperty Name) -join " - "
    } catch {
        Write-Warning "Get-VM sur $ComputerName a echoue : $_"
    }
}

# Lister les VMs clusterisees possedees par cet hote (sinon 'Standalone')
$clusterInfo = "Standalone"
if ($FailoverModuleLoaded) {
    try {
        $clFeat = Get-WindowsFeature -Name Failover-Clustering -ErrorAction SilentlyContinue
        if ($clFeat -and $clFeat.InstallState -eq 'Installed') {
            $node = Get-ClusterNode -Name $ComputerName -ErrorAction Stop
            $clusterName = $node.Cluster
            $clusteredVMs = Get-ClusterGroup -Cluster $clusterName |
                Where-Object { $_.GroupType -eq 'VirtualMachine' -and $_.OwnerNode -eq $node.Name } |
                Select-Object -ExpandProperty Name
            if ($clusteredVMs -and $clusteredVMs.Count -gt 0) {
                $clusterInfo = $clusteredVMs -join " - "
            }
        }
    } catch { }
}

$result = [PSCustomObject]@{
    "Nom"                 = $ComputerName
    "IP (Physique)"       = $ipPhys
    "IP (vEthernet)"      = $ipVeth
    "Adresse MAC"         = $macs
    "Roles"               = $roles
    "Type d'hyperviseur"  = "Microsoft Hyper-V"
    "OS"                  = $CompSys.Caption
    "Integre au domaine"  = $isDomain
    "Nom de Domaine"      = $domain
    "Cluster/Standalone"  = $clusterInfo
    "Processeurs"         = $cpuNames
    "RAM"                 = $memGB
    "Stockage"            = (
        Get-CimInstance Win32_LogicalDisk -Filter "DriveType=3" |
        ForEach-Object {
            $total = [math]::Round($_.Size / 1GB, 1)
            $free  = [math]::Round($_.FreeSpace / 1GB, 1)
            "$($_.DeviceID) $total Go (libre : $free Go)"
        }
    ) -join " | "
    "VMs hebergees"       = $vmNames
    "Description des VMs" = "A completer"
}

$result
$result | Export-Csv -Path $ExportFile -NoTypeInformation -Encoding UTF8