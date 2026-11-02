# 00_Reconnaissance.ps1
# Version      : 5.2
# Derniere modif : Decouverte en une passe, parsing XML (-oX), -O corrige (ports d'abord),
#                  audit distant : rapatriement par sous-dossier (Comptes/AD/HV/VM/NTFS),
#                  NTFS/GPO conserves hors-DC (serveurs de fichiers), splatting des plages corrige.
# v5.2          : Sous-dossier AD rapatrie ; exclusions hors DC a jour (14_, 15_, 33_), numeros
#                  corriges (23_Audit_Linux, 20_Audit_Hyperviseurs)
# v5.1          : Fallback sans WinRM via PsExec (SMB/445, Domain Admin) : comptes, comptes T0,
#                  VM (serveur) ou Workstation (poste). PsExec acquis par init.ps1.
# Role         : Scan reseau, detection OS, audit Windows (WinRM ou PsExec) et Linux (SSH)
# Usage        : Lance via main.ps1 (processus console dedie). Peut aussi etre lance directement.
# ============================================================
# AUDIT: interactive

$ErrorActionPreference = "Continue"

# ─── TRANSCRIPT (main.ps1 fournit AUDIT_SCRIPT_LOG) ─────────
$transcriptActif = $false
if ($env:AUDIT_SCRIPT_LOG) {
    try { Start-Transcript -Path $env:AUDIT_SCRIPT_LOG -Append -Force | Out-Null; $transcriptActif = $true } catch {}
}

# ─── CHEMIN RACINE ──────────────────────────────────────────
$_fichier = $MyInvocation.MyCommand.Path
if (-not $_fichier) { $_fichier = Join-Path $PSScriptRoot "00_Reconnaissance.ps1" }
$_dossier = Split-Path $_fichier -Parent
if ((Split-Path $_dossier -Leaf) -eq "PowerShell") {
    $root = Split-Path (Split-Path $_dossier -Parent) -Parent
} else {
    $root = $_dossier
}

# ─── CHEMINS ────────────────────────────────────────────────
$runId      = if ($env:AUDIT_RUN_ID) { $env:AUDIT_RUN_ID } else { Get-Date -Format "yyyyMMdd_HHmmss" }
$logsDir    = Join-Path $root "Logs"
$tempCsv    = if ($env:AUDIT_TEMP_CSV) { $env:AUDIT_TEMP_CSV } else { Join-Path $root "Temp_CSV" }
$recoDir    = Join-Path $logsDir "Reconnaissance_$runId"
$csvResultat= Join-Path $tempCsv "Reconnaissance_$runId.csv"

New-Item -ItemType Directory -Force -Path $recoDir | Out-Null
New-Item -ItemType Directory -Force -Path $tempCsv | Out-Null

$xmlDiscovery = Join-Path $recoDir "etape1_decouverte.xml"
$xmlPorts     = Join-Path $recoDir "etape2_ports.xml"
$xmlOS        = Join-Path $recoDir "etape2_os.xml"
$logGeneral   = Join-Path $recoDir "reconnaissance.log"

Write-Host ""
Write-Host "------------------------------------------------------------" -ForegroundColor Magenta
Write-Host "  RECONNAISSANCE RESEAU - Framework Audit"                   -ForegroundColor Magenta
Write-Host "------------------------------------------------------------" -ForegroundColor Magenta
Write-Host "  Logs : $recoDir" -ForegroundColor DarkGray
Write-Host "  CSV  : $csvResultat" -ForegroundColor DarkGray
Write-Host ""

# ─── UTILITAIRES ────────────────────────────────────────────
function Ecrire_Log {
    param([string]$Message)
    Add-Content -Path $logGeneral -Value "[$(Get-Date -Format 'HH:mm:ss')] $Message" -Encoding UTF8
}

function Demander_OuiNon {
    param([string]$Question, [string]$Couleur = "Yellow")
    Write-Host "$Question [O/N] : " -ForegroundColor $Couleur -NoNewline
    return (Read-Host) -match "^[OoYy]"
}

# Execute Nmap, ecrit le XML demande, journalise la sortie texte et renvoie le chemin XML (ou $null)
function Invoke-Nmap {
    param(
        [string]$NmapExe,
        [string[]]$Arguments,   # sans -oX (ajoute ici)
        [string]$XmlOut,
        [string]$Libelle
    )
    $args = @($Arguments) + @("-oX", $XmlOut)
    Ecrire_Log "nmap $($args -join ' ')"
    Write-Host "  $Libelle..." -ForegroundColor DarkCyan
    try {
        $sortie = & $NmapExe @args 2>&1
    } catch {
        Write-Warning "  Echec Nmap ($Libelle) : $_"
        Ecrire_Log "ERREUR Nmap ($Libelle) : $_"
        return $null
    }
    $sortie | ForEach-Object { Ecrire_Log "  $_" }
    if (-not (Test-Path $XmlOut)) {
        Write-Warning "  Nmap n'a pas produit de XML ($Libelle) - voir $logGeneral"
        return $null
    }
    return $XmlOut
}

# Parse un XML Nmap -> liste d'objets { IP, Hostname, Etat, OS, Precision, Ports[] }
function Lire_XmlNmap {
    param([string]$Fichier)
    $resultats = [System.Collections.Generic.List[object]]::new()
    if (-not $Fichier -or -not (Test-Path $Fichier)) { return ,$resultats }
    try {
        [xml]$doc = Get-Content -LiteralPath $Fichier -Raw -Encoding UTF8
    } catch {
        Write-Warning "  XML Nmap illisible ($Fichier) : $_"
        return ,$resultats
    }

    foreach ($h in $doc.nmaprun.host) {
        # IPv4 uniquement
        $ip = ($h.address | Where-Object { $_.addrtype -eq 'ipv4' } | Select-Object -First 1).addr
        if (-not $ip) { continue }

        $nom = $null
        if ($h.hostnames -and $h.hostnames.hostname) {
            $nom = ($h.hostnames.hostname | Select-Object -First 1).name
        }
        if (-not $nom) { $nom = $ip }

        $etat = if ($h.status) { $h.status.state } else { "unknown" }

        $os = "Inconnu"; $precision = $null
        if ($h.os -and $h.os.osmatch) {
            $meilleur  = $h.os.osmatch | Select-Object -First 1
            $os        = $meilleur.name
            $precision = $meilleur.accuracy
        }

        $ports = @()
        if ($h.ports -and $h.ports.port) {
            foreach ($p in $h.ports.port) {
                if ($p.state.state -eq 'open') {
                    $svc = if ($p.service) { $p.service.name } else { "" }
                    $ports += [PSCustomObject]@{ Port = [int]$p.portid; Service = $svc }
                }
            }
        }

        $resultats.Add([PSCustomObject]@{
            IP = $ip; Hostname = $nom; Etat = $etat; OS = $os; Precision = $precision; Ports = $ports
        })
    }
    return ,$resultats
}

# ─── GESTION NMAP (inchangee pour l'essentiel) ──────────────
function Trouver_Nmap {
    $portablePath = Join-Path $root "Tools\Nmap\nmap.exe"
    if (Test-Path $portablePath) {
        $ver = & $portablePath --version 2>&1 | Select-Object -First 1
        if ($ver -match "Nmap") {
            Write-Host "  Nmap portable : $ver" -ForegroundColor Green
            return $portablePath
        }
        Write-Warning "  Nmap portable present mais non fonctionnel (DLL manquante)"
        if (Demander_OuiNon "  Tenter une reparation automatique via l installeur ?") { return Reparer_Nmap }
        return $null
    }

    $cheminsSysteme = @(
        (Get-Command nmap -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Source),
        "$env:ProgramFiles\Nmap\nmap.exe",
        "${env:ProgramFiles(x86)}\Nmap\nmap.exe"
    ) | Where-Object { $_ -and (Test-Path $_) }

    if ($cheminsSysteme) {
        $ver = & $cheminsSysteme[0] --version 2>&1 | Select-Object -First 1
        if ($ver -match "Nmap") {
            Write-Host "  Nmap systeme : $ver" -ForegroundColor Green
            return $cheminsSysteme[0]
        }
    }

    $installeur = Get-ChildItem (Join-Path $root "Tools\Nmap") -Filter "nmap*setup*.exe" -ErrorAction SilentlyContinue |
                  Select-Object -First 1 -ExpandProperty FullName
    if ($installeur) {
        Write-Host "  Nmap introuvable - installeur disponible : $(Split-Path $installeur -Leaf)" -ForegroundColor Yellow
        if (Demander_OuiNon "  Installer Nmap maintenant ?") {
            Write-Host "  Lancement de l installeur..." -ForegroundColor Yellow
            Start-Process $installeur -Wait
            $env:PATH = [System.Environment]::GetEnvironmentVariable("PATH","Machine") + ";" +
                        [System.Environment]::GetEnvironmentVariable("PATH","User")
            return Trouver_Nmap
        }
    }

    Write-Error "Nmap introuvable. Options :`n  1. Copier nmap.exe dans Tools\Nmap\`n  2. Copier nmap-7.99-setup.exe dans Tools\Nmap\`n  3. Installer depuis https://nmap.org"
    return $null
}

function Reparer_Nmap {
    $installeur = Get-ChildItem (Join-Path $root "Tools\Nmap") -Filter "nmap*setup*.exe" -ErrorAction SilentlyContinue |
                  Select-Object -First 1 -ExpandProperty FullName
    if (-not $installeur) { Write-Warning "Installeur nmap-setup.exe introuvable dans Tools\Nmap\"; return $null }

    Write-Host "  Installation de Nmap pour reparation..." -ForegroundColor Yellow
    Start-Process $installeur -Wait
    $env:PATH = [System.Environment]::GetEnvironmentVariable("PATH","Machine") + ";" +
                [System.Environment]::GetEnvironmentVariable("PATH","User")

    $cheminsSysteme = @(
        (Get-Command nmap -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Source),
        "$env:ProgramFiles\Nmap\nmap.exe",
        "${env:ProgramFiles(x86)}\Nmap\nmap.exe"
    ) | Where-Object { $_ -and (Test-Path $_) }

    if ($cheminsSysteme) {
        $ver = & $cheminsSysteme[0] --version 2>&1 | Select-Object -First 1
        if ($ver -match "Nmap") {
            Write-Host "  Nmap installe et fonctionnel : $ver" -ForegroundColor Green
            $script:NmapInstallePourReparation = $cheminsSysteme[0]
            return $cheminsSysteme[0]
        }
    }
    Write-Warning "Reparation echouee - Nmap toujours non fonctionnel apres installation"
    return $null
}

function Desinstaller_Nmap {
    $cleReg = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
    )
    $entree = $cleReg | ForEach-Object { Get-ChildItem $_ -ErrorAction SilentlyContinue } |
              ForEach-Object { Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue } |
              Where-Object { $_.DisplayName -like "*Nmap*" } | Select-Object -First 1
    if (-not $entree) { return }

    $cmd = $entree.UninstallString
    $exe = if ($cmd -match '"([^"]+)"') { $Matches[1] } else { ($cmd -split " ")[0] }
    if (Test-Path $exe) {
        Write-Host "  Desinstallation de Nmap (reparation temporaire)..." -ForegroundColor DarkGray
        Start-Process $exe -ArgumentList "/S" -Wait -NoNewWindow
        Write-Host "  Nmap desinstalle." -ForegroundColor DarkGray
    }
}

function Verifier_Npcap {
    $service = Get-Service -Name npcap -ErrorAction SilentlyContinue
    if ($service -and $service.Status -eq "Running") {
        Write-Host "  Npcap OK." -ForegroundColor Green
        return $true
    }
    $installeur = Join-Path $root "Tools\Nmap\npcap-installer.exe"
    if (Test-Path $installeur) {
        Write-Host "  Npcap absent - lancement de l installeur..." -ForegroundColor Yellow
        Write-Host "  Cocher 'WinPcap API-compatible mode' dans l installeur." -ForegroundColor DarkGray
        Start-Process $installeur -Wait
        $service = Get-Service -Name npcap -ErrorAction SilentlyContinue
        if ($service) {
            Start-Service npcap -ErrorAction SilentlyContinue
            Write-Host "  Npcap installe." -ForegroundColor Green
            return $true
        }
    }
    Write-Warning "Npcap non disponible - placer npcap-installer.exe dans Tools\Nmap\"
    return $false
}

# ─── CLIENT SSH ─────────────────────────────────────────────
function Trouver_SSH {
    $ssh = Get-Command ssh -ErrorAction SilentlyContinue
    if ($ssh) { return $ssh.Source }

    Write-Host "  ssh.exe introuvable - tentative d installation du client OpenSSH..." -ForegroundColor Yellow
    try {
        Add-WindowsCapability -Online -Name OpenSSH.Client~~~~0.0.1.0 -ErrorAction Stop | Out-Null
        $env:PATH = [System.Environment]::GetEnvironmentVariable("PATH","Machine") + ";" +
                    [System.Environment]::GetEnvironmentVariable("PATH","User")
        $ssh = Get-Command ssh -ErrorAction SilentlyContinue
        if ($ssh) { Write-Host "  OpenSSH client installe." -ForegroundColor Green; return $ssh.Source }
    } catch {
        Write-Warning "  Impossible d installer OpenSSH client : $_"
    }

    $plink = Join-Path $root "Tools\plink.exe"
    if (Test-Path $plink) {
        Write-Host "  Plink.exe detecte (PuTTY SSH client)." -ForegroundColor Green
        return $plink
    }
    Write-Warning "Aucun client SSH disponible - audit Linux impossible.`nPlacer plink.exe dans Tools\ ou installer OpenSSH client."
    return $null
}

# ─── AVERTISSEMENT ──────────────────────────────────────────
Write-Host "/!\ AVERTISSEMENT /!\" -ForegroundColor Red
Write-Host "Ce script effectue un scan reseau actif (Nmap)." -ForegroundColor Yellow
Write-Host "Assure-toi d avoir les autorisations necessaires." -ForegroundColor Yellow
Write-Host "Le scan peut declencher des alertes sur les equipements sensibles." -ForegroundColor Yellow
Write-Host "(firewalls, IDS/IPS, equipements reseau, systemes industriels OT/ICS)" -ForegroundColor Yellow
Write-Host ""

if (-not (Demander_OuiNon "Confirmes-tu avoir les droits pour scanner ce reseau ?" "Red")) {
    Write-Host "Scan annule." -ForegroundColor DarkGray
    if ($transcriptActif) { try { Stop-Transcript | Out-Null } catch {} }
    exit 0
}

# ─── SAISIE DES PLAGES ──────────────────────────────────────
Write-Host ""
Write-Host "Plages reseau a scanner (une par ligne, ligne vide pour terminer)." -ForegroundColor Cyan
Write-Host "  Formats : 192.168.1.0/24  ou  10.0.0.1-50  ou  192.168.1.5" -ForegroundColor DarkGray
Write-Host ""

$plages = [System.Collections.Generic.List[string]]::new()
while ($true) {
    Write-Host "  Plage $($plages.Count + 1) : " -ForegroundColor Yellow -NoNewline
    $saisie = Read-Host
    if ([string]::IsNullOrWhiteSpace($saisie)) {
        if ($plages.Count -eq 0) { Write-Host "  Au moins une plage requise." -ForegroundColor Red; continue }
        break
    }
    $plages.Add($saisie.Trim())
}
$plagesArr = @($plages)   # tableau pour splatting

Write-Host ""
Write-Host "  Plages a scanner :" -ForegroundColor Cyan
$plagesArr | ForEach-Object { Write-Host "    - $_" -ForegroundColor White }

# ─── ETAPE 0 : NMAP + NPCAP ─────────────────────────────────
Write-Host ""
Write-Host "------------------------------------------------------------" -ForegroundColor Cyan
Write-Host "  ETAPE 0 : Verification Nmap et Npcap" -ForegroundColor Cyan
Write-Host "------------------------------------------------------------" -ForegroundColor Cyan

$nmapExe = Trouver_Nmap
if (-not $nmapExe) { if ($transcriptActif) { try { Stop-Transcript | Out-Null } catch {} }; exit 1 }
if (-not (Verifier_Npcap)) { if ($transcriptActif) { try { Stop-Transcript | Out-Null } catch {} }; exit 1 }

# ─── ETAPE 1 : DECOUVERTE DES HOTES (une passe) ─────────────
Write-Host ""
Write-Host "------------------------------------------------------------" -ForegroundColor Cyan
Write-Host "  ETAPE 1 : Decouverte des hotes actifs" -ForegroundColor Cyan
Write-Host "------------------------------------------------------------" -ForegroundColor Cyan

# -sn : pas de scan de ports. Sur le meme sous-reseau Nmap fait de l'ARP automatiquement ;
# ailleurs, les sondes ICMP echo/timestamp + TCP SYN/ACK couvrent les hotes derriere routeur.
$argsDecouverte = @("-sn","-T4","-R","-PE","-PP","-PS21,22,80,135,139,443,445,3389,5985","-PA80,443,3389") + $plagesArr
$fxml = Invoke-Nmap -NmapExe $nmapExe -Arguments $argsDecouverte -XmlOut $xmlDiscovery -Libelle "Decouverte (ICMP + TCP + ARP)"

$hotes = Lire_XmlNmap -Fichier $fxml | Where-Object { $_.Etat -eq 'up' }
Ecrire_Log "Hotes actifs : $($hotes.Count)"
Write-Host "  $($hotes.Count) hote(s) actif(s)" -ForegroundColor Green
$hotes | ForEach-Object { Write-Host "    - $($_.IP)  $($_.Hostname)" -ForegroundColor DarkCyan }

if ($hotes.Count -eq 0) {
    Write-Host "Aucun hote detecte. Fin du scan." -ForegroundColor Yellow
    if ($transcriptActif) { try { Stop-Transcript | Out-Null } catch {} }
    exit 0
}

$ipList = @($hotes | Select-Object -ExpandProperty IP)

# ─── ETAPE 2 : PORTS + DETECTION OS ─────────────────────────
Write-Host ""
Write-Host "------------------------------------------------------------" -ForegroundColor Cyan
Write-Host "  ETAPE 2 : Scan de ports et detection OS" -ForegroundColor Cyan
Write-Host "------------------------------------------------------------" -ForegroundColor Cyan

# 2a. Scan de ports cles (donne a -O de la matiere, et sert au typage Windows/Linux)
$portsCles = "22,135,139,445,3389,5985,5986"
$argsPorts = @("-sS","-T4","-Pn","-p",$portsCles,"--open") + $ipList
$fxmlPorts = Invoke-Nmap -NmapExe $nmapExe -Arguments $argsPorts -XmlOut $xmlPorts -Libelle "Scan de ports ($portsCles)"
$infosPorts = Lire_XmlNmap -Fichier $fxmlPorts

# 2b. Detection OS, etape separee comme demande. -Pn : hotes deja confirmes up.
$argsOS = @("-O","--osscan-guess","-T4","-Pn","--max-os-tries","1") + $ipList
$fxmlOS = Invoke-Nmap -NmapExe $nmapExe -Arguments $argsOS -XmlOut $xmlOS -Libelle "Detection OS (-O)"
$infosOS = Lire_XmlNmap -Fichier $fxmlOS

# ─── FUSION ─────────────────────────────────────────────────
function Typer_Systeme {
    param([string]$Os, [int[]]$Ports)
    if ($Os -match "Windows")                               { return "Windows" }
    if ($Os -match "Linux|Ubuntu|Debian|CentOS|Red Hat|RHEL|Unix") { return "Linux" }
    if ($Ports -contains 5985 -or $Ports -contains 5986 -or $Ports -contains 445 -or $Ports -contains 3389 -or $Ports -contains 135) { return "Windows" }
    if ($Ports -contains 22)                                { return "Linux" }
    return "Inconnu"
}

$serveurs = [System.Collections.Generic.List[object]]::new()
foreach ($h in $hotes) {
    $pInfo = $infosPorts | Where-Object { $_.IP -eq $h.IP } | Select-Object -First 1
    $oInfo = $infosOS    | Where-Object { $_.IP -eq $h.IP } | Select-Object -First 1

    $ports = @()
    if ($pInfo) { $ports = @($pInfo.Ports | Select-Object -ExpandProperty Port) }

    $os = "Inconnu"; $prec = $null
    if ($oInfo -and $oInfo.OS -ne "Inconnu") { $os = $oInfo.OS; $prec = $oInfo.Precision }

    # Nom : privilegier un FQDN resolu lors du scan de ports/OS s'il est plus precis
    $nom = $h.Hostname
    foreach ($src in @($pInfo, $oInfo)) {
        if ($src -and $src.Hostname -and $src.Hostname -ne $src.IP -and $nom -eq $h.IP) { $nom = $src.Hostname }
    }

    $type = Typer_Systeme -Os $os -Ports $ports

    $serveurs.Add([PSCustomObject]@{
        Hostname   = $nom
        IP         = $h.IP
        OS         = $os
        PrecisionOS= $prec
        Type       = $type
        Ports      = ($ports | Sort-Object -Unique)
        WinRM      = ($ports -contains 5985 -or $ports -contains 5986)
        SSH        = ($ports -contains 22)
        SMB        = ($ports -contains 445)
        Methode    = ""
        Skip       = "Non"
        SkipRaison = ""
    })
}

Write-Host ""
Write-Host "  $($serveurs.Count) systeme(s) identifie(s) :" -ForegroundColor Green
$serveurs | ForEach-Object {
    $couleur = if ($_.Type -eq "Windows") { "Cyan" } elseif ($_.Type -eq "Linux") { "Green" } else { "Yellow" }
    $precTxt = if ($_.PrecisionOS) { " (~$($_.PrecisionOS)%)" } else { "" }
    Write-Host "    - $($_.IP) [$($_.Type)] $($_.OS)$precTxt  ports: $($_.Ports -join ',')" -ForegroundColor $couleur
}

# ─── ETAPE 3 : VALIDATION UTILISATEUR ───────────────────────
Write-Host ""
Write-Host "------------------------------------------------------------" -ForegroundColor Cyan
Write-Host "  ETAPE 3 : Validation des cibles" -ForegroundColor Cyan
Write-Host "------------------------------------------------------------" -ForegroundColor Cyan

foreach ($srv in $serveurs) {
    Write-Host ""
    Write-Host "  +-- $($srv.IP) [$($srv.Type)] ------------------" -ForegroundColor Cyan
    Write-Host "  |  Hostname : $($srv.Hostname)" -ForegroundColor White
    Write-Host "  |  OS       : $($srv.OS)" -ForegroundColor White
    Write-Host "  |  WinRM    : $(if ($srv.WinRM) {'OUI'} else {'NON'})" -ForegroundColor $(if ($srv.WinRM) {"Green"} else {"DarkGray"})
    Write-Host "  |  SSH      : $(if ($srv.SSH) {'OUI'} else {'NON'})" -ForegroundColor $(if ($srv.SSH) {"Green"} else {"DarkGray"})
    Write-Host "  |  SMB(445) : $(if ($srv.SMB) {'OUI'} else {'NON'})" -ForegroundColor $(if ($srv.SMB) {"Green"} else {"DarkGray"})
    Write-Host "  +-----------------------------------------------" -ForegroundColor Cyan

    # Methode d'audit retenue, par ordre de preference
    if     ($srv.WinRM)                            { $srv.Methode = "WinRM"  }
    elseif ($srv.SSH -and $srv.Type -eq "Linux")   { $srv.Methode = "SSH"    }
    elseif ($srv.SMB -and $srv.Type -eq "Windows") { $srv.Methode = "PsExec" }
    elseif ($srv.SSH)                              { $srv.Methode = "SSH"    }

    if (-not $srv.Methode) {
        if (Demander_OuiNon "  Inclure dans le CSV (sans audit distant) ?") { $srv.Skip = "Non" }
        else { $srv.Skip = "Ignorer" }
        $srv.SkipRaison = "Aucun acces (ni WinRM, ni SSH, ni SMB)"
    } else {
        if ($srv.Methode -eq "PsExec") {
            Write-Host "  Pas de WinRM - audit via PsExec (SMB/445, compte Domain Admin, sans GPO)." -ForegroundColor Yellow
        }
        if (-not (Demander_OuiNon "  Auditer ce systeme ?")) {
            $srv.Skip = "Oui"
            Write-Host "  Raison du skip : " -ForegroundColor DarkGray -NoNewline
            $srv.SkipRaison = Read-Host
            if (-not $srv.SkipRaison) { $srv.SkipRaison = "Skippe manuellement" }
        }
    }
}

# ─── AUDIT DISTANT WINDOWS ──────────────────────────────────
function Audit_Windows {
    param([object]$Cible)

    Write-Host ""
    Write-Host "  >> Audit Windows : $($Cible.IP) ($($Cible.Hostname))" -ForegroundColor Cyan

    $trusted = (Get-Item WSMan:\localhost\Client\TrustedHosts -ErrorAction SilentlyContinue).Value
    if ($trusted -ne "*" -and $trusted -notmatch [regex]::Escape($Cible.IP)) {
        $nouveau = if ($trusted) { "$trusted,$($Cible.IP)" } else { $Cible.IP }
        Set-Item WSMan:\localhost\Client\TrustedHosts -Value $nouveau -Force -ErrorAction SilentlyContinue
    }

    $domaineCourant = (Get-CimInstance Win32_ComputerSystem -ErrorAction SilentlyContinue).Domain
    $cibleConnexion = $Cible.IP
    if ($Cible.Hostname -ne $Cible.IP -and $Cible.Hostname -match "\.") { $cibleConnexion = $Cible.Hostname }

    $params = @{}
    $horsDomaineOuIP = ($Cible.Hostname -eq $Cible.IP) -or (-not $domaineCourant) -or
                       ($Cible.Hostname -notmatch [regex]::Escape($domaineCourant))
    if ($horsDomaineOuIP) {
        Write-Host "  Machine hors domaine - credentials requis." -ForegroundColor Yellow
        try { $params["Credential"] = Get-Credential -Message "Credentials pour $($Cible.Hostname) ($($Cible.IP))" }
        catch { Write-Warning "Credentials annules - $($Cible.IP) ignore."; return }
    }

    $session = $null
    try {
        $session = New-PSSession -ComputerName $cibleConnexion @params -ErrorAction Stop

        # Les memes sous-dossiers que main.ps1, NTFS inclus
        $sousDossiers = @("Comptes","AD","HV","VM","NTFS")
        $dossierTemp  = "C:\Windows\Temp\Audit_$runId"
        Invoke-Command -Session $session -ScriptBlock {
            param($dir, $subs)
            New-Item -ItemType Directory -Force -Path $dir | Out-Null
            foreach ($sub in $subs) { New-Item -ItemType Directory -Force -Path (Join-Path $dir $sub) | Out-Null }
        } -ArgumentList $dossierTemp, $sousDossiers

        # Role de la cible (Get-WindowsFeature n'existe que sur Windows Server)
        $infos = Invoke-Command -Session $session -ScriptBlock {
            $os = (Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue).Caption
            $roles = @()
            if (Get-Command Get-WindowsFeature -ErrorAction SilentlyContinue) {
                try { $roles = (Get-WindowsFeature | Where-Object InstallState -eq Installed).Name } catch {}
            }
            [PSCustomObject]@{ OS = $os; Roles = $roles -join "," }
        }
        $estDC     = $infos.Roles -split "," -contains "AD-Domain-Services"
        $estHyperV = $infos.Roles -split "," -contains "Hyper-V"

        # Scripts a NE PAS copier.
        # NTFS et GPO restent : un serveur de fichiers (non-DC) heberge justement les partages,
        # et GPO se skippe proprement seul si le module manque. On exclut ce qui est purement local
        # a l'orchestrateur (00_), interactif cloud (12_ M365) ou dependant d'un role precis.
        $exclure = @("^_", "^00_", "^12_Audit_Comptes_365", "^23_Audit_Linux")   # "^_" : scripts desactives
        # Hors DC : modules ne collectant que des donnees du domaine (evite les doublons par serveur)
        if (-not $estDC)     { $exclure += @("^13_Arborescence", "^14_Audit_PSO", "^15_Audit_Silos", "^30_Audit_Replication", "^33_Audit_Groupes") }
        if (-not $estHyperV) { $exclure += "^20_Audit_Hyperviseurs" }

        $psDir = Join-Path $root "Scripts\PowerShell"
        $scriptsWinRM = Get-ChildItem $psDir -Filter "*.ps1" |
            Where-Object { $nom = $_.Name; -not ($exclure | Where-Object { $nom -match $_ }) } |
            Sort-Object Name

        $role = if ($estDC) { "DC/AD" } elseif ($estHyperV) { "Hyper-V" } else { "Membre/Standalone" }
        Write-Host "  Role : $role | Scripts : $($scriptsWinRM.Count)" -ForegroundColor DarkGray

        foreach ($s in $scriptsWinRM) {
            Copy-Item -Path $s.FullName -Destination $dossierTemp -ToSession $session -Force
            Write-Host "    - $($s.Name)" -ForegroundColor DarkCyan
            Invoke-Command -Session $session -ScriptBlock {
                param($script, $csvDir)
                $env:AUDIT_TEMP_CSV     = $csvDir
                $env:AUDIT_TEMP_COMPTES = Join-Path $csvDir "Comptes"
                $env:AUDIT_TEMP_AD      = Join-Path $csvDir "AD"
                $env:AUDIT_TEMP_HV      = Join-Path $csvDir "HV"
                $env:AUDIT_TEMP_VM      = Join-Path $csvDir "VM"
                $env:AUDIT_TEMP_NTFS    = Join-Path $csvDir "NTFS"
                $env:AUDIT_NONINTERACTIVE = "1"   # pas de Read-Host a distance
                try { & $script } catch { Write-Warning "Erreur $_" }
            } -ArgumentList (Join-Path $dossierTemp $s.Name), $dossierTemp -ErrorAction SilentlyContinue
        }

        # Rapatriement : tous les fichiers produits (csv ET txt/html NTFS), en conservant
        # le sous-dossier d'origine pour que Process_excels retrouve chaque module.
        $destLocal = Join-Path $tempCsv $Cible.Hostname
        New-Item -ItemType Directory -Force -Path $destLocal | Out-Null
        foreach ($sub in $sousDossiers) {
            New-Item -ItemType Directory -Force -Path (Join-Path $destLocal $sub) | Out-Null
        }

        $fichiersDistants = Invoke-Command -Session $session -ScriptBlock {
            param($dir)
            Get-ChildItem $dir -File -Recurse -Include *.csv,*.txt,*.html -ErrorAction SilentlyContinue |
                ForEach-Object { [PSCustomObject]@{ Full = $_.FullName; Rel = $_.FullName.Substring($dir.Length).TrimStart('\') } }
        } -ArgumentList $dossierTemp

        $nbCopies = 0
        foreach ($f in $fichiersDistants) {
            $destination = Join-Path $destLocal $f.Rel
            New-Item -ItemType Directory -Force -Path (Split-Path $destination) | Out-Null
            Copy-Item -Path $f.Full -Destination $destination -FromSession $session -Force
            Write-Host "    <- $($f.Rel)" -ForegroundColor Green
            $nbCopies++
        }
        Write-Host "  $nbCopies fichier(s) rapatrie(s) dans $destLocal" -ForegroundColor Green

        Invoke-Command -Session $session -ScriptBlock {
            param($dir) Remove-Item $dir -Recurse -Force -ErrorAction SilentlyContinue
        } -ArgumentList $dossierTemp

        Write-Host "  << $($Cible.IP) termine." -ForegroundColor Green
    } catch {
        Write-Warning "Connexion WinRM echouee sur $($Cible.IP) : $_"
    } finally {
        if ($session) { Remove-PSSession $session -ErrorAction SilentlyContinue }
    }
}

# ─── AUDIT DISTANT LINUX ────────────────────────────────────
function Audit_Linux {
    param([object]$Cible)

    Write-Host ""
    Write-Host "  >> Audit Linux : $($Cible.IP) ($($Cible.Hostname))" -ForegroundColor Green

    $sshExe = Trouver_SSH
    if (-not $sshExe) { Write-Warning "SSH non disponible - $($Cible.IP) ignore."; return }

    Write-Host "  Utilisateur SSH pour $($Cible.IP) : " -ForegroundColor Yellow -NoNewline
    $sshUser = Read-Host
    Write-Host "  Mot de passe : " -ForegroundColor Yellow -NoNewline
    $sshPassSecure = Read-Host -AsSecureString
    $sshPass = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto(
        [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($sshPassSecure))

    $cmdH = "echo '=HOSTNAME=' && hostname"
    $cmdO = "echo '=OS=' && cat /etc/os-release 2>/dev/null | grep PRETTY_NAME | cut -d= -f2"
    $cmdI = "echo '=INTERFACES=' && ip addr show 2>/dev/null | grep -E 'inet |^[0-9]+:' || ifconfig 2>/dev/null"
    $cmdU = 'echo "=USERS=" && getent passwd | awk -F: ' + "'" + '$3>=1000 && $7!~/nologin|false|sync/{print $1","$3","$6}' + "'"
    $cmdS = 'echo "=SERVICES=" && systemctl list-units --type=service --state=running --no-pager --no-legend 2>/dev/null | awk ' + "'" + '{print $1}' + "'" + ' | head -30'
    $scriptSSH = "$cmdH && $cmdO && $cmdI && $cmdU && $cmdS"

    $sortie = $null
    try {
        if ($sshExe -match "plink") {
            $sortie = & $sshExe -ssh -l $sshUser -pw $sshPass -batch -o "StrictHostKeyChecking=no" $Cible.IP $scriptSSH 2>&1
        } else {
            $env:SSH_ASKPASS = ""
            $sortie = & $sshExe -o "StrictHostKeyChecking=no" -o "ConnectTimeout=10" "${sshUser}@$($Cible.IP)" $scriptSSH 2>&1
        }
    } catch {
        Write-Warning "Connexion SSH echouee sur $($Cible.IP) : $_"
        return
    }

    $hostname = ""; $os = ""; $section = ""
    $interfaces = [System.Collections.Generic.List[string]]::new()
    $utilisateurs = [System.Collections.Generic.List[string]]::new()
    $services = [System.Collections.Generic.List[string]]::new()

    foreach ($ligne in $sortie) {
        switch -Regex ($ligne) {
            "^=HOSTNAME="   { $section = "hostname"; continue }
            "^=OS="         { $section = "os"; continue }
            "^=INTERFACES=" { $section = "interfaces"; continue }
            "^=USERS="      { $section = "users"; continue }
            "^=SERVICES="   { $section = "services"; continue }
            default {
                if ([string]::IsNullOrWhiteSpace($ligne)) { continue }
                switch ($section) {
                    "hostname"   { $hostname = $ligne.Trim() }
                    "os"         { $os       = $ligne.Trim() }
                    "interfaces" { $interfaces.Add($ligne.Trim()) }
                    "users"      { $utilisateurs.Add($ligne.Trim()) }
                    "services"   { $services.Add($ligne.Trim()) }
                }
            }
        }
    }

    $destLocal = Join-Path $tempCsv $Cible.Hostname
    New-Item -ItemType Directory -Force -Path $destLocal | Out-Null
    $exportFile = Join-Path $destLocal "$($Cible.Hostname)_Audit_Linux.csv"

    [PSCustomObject]@{
        Hostname     = if ($hostname) { $hostname } else { $Cible.Hostname }
        IP           = $Cible.IP
        OS           = $os
        Interfaces   = $interfaces -join " | "
        Utilisateurs = $utilisateurs -join " | "
        Services     = $services -join " | "
    } | Export-Csv -Path $exportFile -NoTypeInformation -Encoding UTF8

    Write-Host "  << $($Cible.IP) termine - CSV : $(Split-Path $exportFile -Leaf)" -ForegroundColor Green
}

# ─── PSEXEC (acquis par init.ps1 ; ici on le localise seulement) ─
function Trouver_PsExec {
    $candidats = @(
        (Join-Path $root "Tools\PsExec64.exe"),
        (Join-Path $root "Tools\PsExec.exe"),
        (Join-Path $root "Tools\PsTools\PsExec64.exe"),
        (Join-Path $root "Tools\PsTools\PsExec.exe")
    ) | Where-Object { Test-Path $_ } | Select-Object -First 1

    if (-not $candidats) {
        $candidats = Get-Command PsExec64.exe, PsExec.exe -ErrorAction SilentlyContinue |
                     Select-Object -First 1 -ExpandProperty Source
    }
    if ($candidats) { Write-Host "  PsExec : $candidats" -ForegroundColor Green; return $candidats }

    Write-Warning "PsExec introuvable - relancer init.ps1 ou placer PsExec64.exe dans Tools\"
    return $null
}

# Audit distant SANS WinRM : copie des scripts via C$ (SMB/445), execution par PsExec (SYSTEM),
# rapatriement par sous-dossier (Comptes/AD/HV/VM/NTFS) comme la voie WinRM.
# Scripts executes (seulement) : comptes, comptes T0, et VM (serveur) ou Workstation (poste).
function Audit_Windows_PsExec {
    param([object]$Cible)

    Write-Host ""
    Write-Host "  >> Audit Windows (PsExec/SMB) : $($Cible.IP) ($($Cible.Hostname))" -ForegroundColor Cyan

    $psexec = Trouver_PsExec
    if (-not $psexec) { Write-Warning "PsExec indisponible - $($Cible.IP) ignore."; return }

    # Compte administrateur du DOMAINE (format DOMAINE\compte). 445 etant deja ouvert,
    # aucune GPO n'est requise : les partages admin C$/ADMIN$ sont accessibles au Domain Admin.
    Write-Host "  Compte administrateur du domaine requis (format DOMAINE\compte) :" -ForegroundColor Yellow
    try { $cred = Get-Credential -Message "Administrateur du domaine pour $($Cible.IP)" }
    catch { Write-Warning "Credentials annules - $($Cible.IP) ignore."; return }
    $credUser = $cred.UserName
    $credPass = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto(
                    [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($cred.Password))

    # Serveur vs poste : DomainRole via DCOM (135) si possible, sinon chaine OS Nmap.
    # 0,1 = poste ; 2,3 = serveur membre/standalone ; 4,5 = controleur de domaine.
    $estServeur = $false
    if ($Cible.Ports -contains 135) {
        try {
            $cimTmp = New-CimSession -ComputerName $Cible.IP -Credential $cred `
                      -SessionOption (New-CimSessionOption -Protocol Dcom) -ErrorAction Stop
            $dr = (Get-CimInstance -CimSession $cimTmp -ClassName Win32_ComputerSystem -ErrorAction SilentlyContinue).DomainRole
            Remove-CimSession $cimTmp
            if ($null -ne $dr) { $estServeur = ([int]$dr -ge 2) }
        } catch {}
    }
    if (-not $estServeur -and $Cible.OS -match "Server") { $estServeur = $true }

    $scriptsVoulus = @("11_Audit_comptes.ps1")
    if ($estServeur) {
        $scriptsVoulus += @("10_Audit_comptes_T0.ps1", "21_Audit_VMs.ps1")
    } else {
        $scriptsVoulus += "22_Audit_Workstation.ps1"
    }

    $psDir = Join-Path $root "Scripts\PowerShell"
    $scriptsDispo = Get-ChildItem $psDir -Filter "*.ps1" -ErrorAction SilentlyContinue |
                    Where-Object { $_.Name -in $scriptsVoulus } | Sort-Object Name
    if (-not $scriptsDispo) {
        Write-Warning "  Aucun des scripts attendus trouve dans $psDir"
        return
    }
    Write-Host "  Role : $(if ($estServeur){'Serveur/DC'}else{'Poste'}) | Scripts : $($scriptsDispo.Count)" -ForegroundColor DarkGray

    # Acces au partage admin C$ (SMB/445)
    $nomDrive = "PSAUD_$($Cible.IP -replace '\.','_')"
    try {
        New-PSDrive -Name $nomDrive -PSProvider FileSystem -Root "\\$($Cible.IP)\C$" -Credential $cred -ErrorAction Stop | Out-Null
    } catch {
        Write-Warning "Acces \\$($Cible.IP)\C$ echoue (SMB/445) : $_"
        return
    }

    $sousDossiers = @("Comptes","AD","HV","VM","NTFS")
    $dossierCible = "C:\Windows\Temp\Audit_$runId"                   # vu depuis la cible
    $dossierUNC   = "${nomDrive}:\Windows\Temp\Audit_$runId"         # vu depuis nous
    foreach ($sub in @("") + $sousDossiers) {
        New-Item -ItemType Directory -Force -Path (Join-Path $dossierUNC $sub) | Out-Null
    }

    # Wrapper : memes variables d'env que la voie WinRM + mode non interactif
    $ntfsLine = if ($env:AUDIT_NTFS_PATHS) { "`$env:AUDIT_NTFS_PATHS = '$($env:AUDIT_NTFS_PATHS)'" } else { "" }
    $wrapper = @"
`$ErrorActionPreference = 'Continue'
`$dir = `$PSScriptRoot
`$env:AUDIT_TEMP_CSV       = `$dir
`$env:AUDIT_TEMP_COMPTES   = Join-Path `$dir 'Comptes'
`$env:AUDIT_TEMP_AD        = Join-Path `$dir 'AD'
`$env:AUDIT_TEMP_HV        = Join-Path `$dir 'HV'
`$env:AUDIT_TEMP_VM        = Join-Path `$dir 'VM'
`$env:AUDIT_TEMP_NTFS      = Join-Path `$dir 'NTFS'
`$env:AUDIT_NONINTERACTIVE = '1'
$ntfsLine
Get-ChildItem `$dir -Filter '*.ps1' | Where-Object { `$_.Name -ne '_run_audit.ps1' } | Sort-Object Name | ForEach-Object {
    try { & `$_.FullName } catch { Write-Warning "Erreur `$(`$_.Name) : `$_" }
}
"@
    Set-Content -Path (Join-Path $dossierUNC "_run_audit.ps1") -Value $wrapper -Encoding UTF8

    foreach ($sfile in $scriptsDispo) {
        Copy-Item -Path $sfile.FullName -Destination $dossierUNC -Force
        Write-Host "    - $($sfile.Name)" -ForegroundColor DarkCyan
    }

    # Execution : PsExec synchrone, en SYSTEM, token eleve
    Write-Host "  PsExec : execution en cours sur la cible (SYSTEM)..." -ForegroundColor DarkGray
    $psArgs = @(
        "\\$($Cible.IP)", "-accepteula", "-nobanner", "-s", "-h",
        "-u", $credUser, "-p", $credPass, "-w", $dossierCible,
        "powershell.exe", "-ExecutionPolicy", "Bypass", "-NonInteractive",
        "-WindowStyle", "Hidden", "-File", "$dossierCible\_run_audit.ps1"
    )
    $errLog = Join-Path $recoDir "psexec_$($Cible.IP).log"
    $proc = Start-Process -FilePath $psexec -ArgumentList $psArgs -NoNewWindow -Wait -PassThru -RedirectStandardError $errLog
    if ($proc.ExitCode -notin @(0,1)) {
        Write-Warning "  PsExec code $($proc.ExitCode) sur $($Cible.IP) - voir $errLog"
    }

    # Rapatriement par sous-dossier (conserve Comptes/AD/HV/VM/NTFS)
    $destLocal = Join-Path $tempCsv $Cible.Hostname
    New-Item -ItemType Directory -Force -Path $destLocal | Out-Null
    foreach ($sub in $sousDossiers) { New-Item -ItemType Directory -Force -Path (Join-Path $destLocal $sub) | Out-Null }

    $fichiers = Get-ChildItem $dossierUNC -File -Recurse -Include *.csv,*.txt,*.html -ErrorAction SilentlyContinue
    $nb = 0
    foreach ($f in $fichiers) {
        $rel = $f.FullName.Substring(((Resolve-Path $dossierUNC).Path).Length).TrimStart('\')
        $destination = Join-Path $destLocal $rel
        New-Item -ItemType Directory -Force -Path (Split-Path $destination) | Out-Null
        Copy-Item -Path $f.FullName -Destination $destination -Force
        Write-Host "    <- $rel" -ForegroundColor Green
        $nb++
    }
    if ($nb -eq 0) { Write-Warning "  Aucun fichier genere (droits insuffisants ou scripts sans resultat)." }
    else { Write-Host "  $nb fichier(s) rapatrie(s) dans $destLocal" -ForegroundColor Green }

    # Nettoyage
    Remove-Item $dossierUNC -Recurse -Force -ErrorAction SilentlyContinue
    Remove-PSDrive $nomDrive -Force -ErrorAction SilentlyContinue
    Write-Host "  << $($Cible.IP) termine." -ForegroundColor Green
}

# ─── ETAPE 4 : EXPORT CSV + AUDIT DISTANT ───────────────────
Write-Host ""
Write-Host "------------------------------------------------------------" -ForegroundColor Cyan
Write-Host "  ETAPE 4 : Export CSV et audit des cibles" -ForegroundColor Cyan
Write-Host "------------------------------------------------------------" -ForegroundColor Cyan

$serveurs | Where-Object { $_.Skip -ne "Ignorer" } |
    Select-Object Hostname, IP, OS, PrecisionOS, Type,
                  @{N="Ports";E={ $_.Ports -join " " }}, WinRM, SSH, SMB, Methode, Skip, SkipRaison |
    Export-Csv -Path $csvResultat -NoTypeInformation -Encoding UTF8
Write-Host "  CSV reconnaissance : $csvResultat" -ForegroundColor Green

$ipsLocales = @(
    [System.Net.Dns]::GetHostAddresses([System.Net.Dns]::GetHostName()) |
    Where-Object { $_.AddressFamily -eq "InterNetwork" } | ForEach-Object { $_.ToString() }
)

$cibles = $serveurs | Where-Object { $_.Skip -eq "Non" -and $_.IP -notin $ipsLocales -and $_.Methode }

Write-Host "  Cibles qualifiees pour audit : $(@($cibles).Count)" -ForegroundColor DarkGray
if (-not $cibles -or @($cibles).Count -eq 0) {
    Write-Host "  Aucune cible a auditer." -ForegroundColor Yellow
} else {
    foreach ($cible in $cibles) {
        switch ($cible.Methode) {
            "WinRM"  { Audit_Windows        -Cible $cible }
            "SSH"    { Audit_Linux          -Cible $cible }
            "PsExec" { Audit_Windows_PsExec -Cible $cible }
        }
    }
}

if ($script:NmapInstallePourReparation) { Desinstaller_Nmap }

Write-Host ""
Write-Host "------------------------------------------------------------" -ForegroundColor Magenta
Write-Host "  RECONNAISSANCE TERMINEE" -ForegroundColor Magenta
Write-Host "  Logs : $recoDir" -ForegroundColor DarkGray
Write-Host "  CSV  : $csvResultat" -ForegroundColor DarkGray
Write-Host "------------------------------------------------------------" -ForegroundColor Magenta

if ($transcriptActif) { try { Stop-Transcript | Out-Null } catch {} }