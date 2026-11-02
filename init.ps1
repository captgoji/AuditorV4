# init.ps1
# Version      : 5.0
# Derniere modif : Suppression de Python / openpyxl / generation des templates (servent uniquement a
#                  Process_excels.py, qui genere lui-meme les templates manquants). Ajout de la
#                  verification / installation des outils RSAT necessaires aux scripts selectionnes
#                  (serveur membre ou poste).
# Role         : Prerequis : RSAT (AD, GPMC, DFS), Microsoft.Graph (si 12_), Npcap et PsExec (si 00_)
# Usage        : Lance automatiquement par main.ps1 via AUDIT_SELECTED_SCRIPTS.
#                Aucun prerequis n'est bloquant : un composant manquant est signale et les scripts
#                concernes s'ignorent proprement. Code de sortie toujours 0.
# ============================================================

$root     = $PSScriptRoot
$logsDir  = Join-Path $root "Logs"
$logFile  = Join-Path $logsDir "Init_$((Get-Date -Format 'yyyyMMdd_HHmmss')).log"

New-Item -ItemType Directory -Force -Path $logsDir | Out-Null
Start-Transcript -Path $logFile -Append -Force

Write-Host "Init demarre - $(Get-Date -Format 'HH:mm:ss')" -ForegroundColor Cyan

# Scripts selectionnes par main.ps1 (pour ne verifier / installer que ce qui est utile)
$scriptsSelectionnes = if ($env:AUDIT_SELECTED_SCRIPTS) {
    $env:AUDIT_SELECTED_SCRIPTS -split ","
} else {
    @()
}
$nonInteractif = $env:AUDIT_NONINTERACTIVE -eq "1"

function Script_Selectionne {
    param([string[]]$Patterns)
    if ($scriptsSelectionnes.Count -eq 0) { return $true }
    foreach ($p in $Patterns) {
        if (@($scriptsSelectionnes | Where-Object { $_ -like $p }).Count -gt 0) { return $true }
    }
    return $false
}

function Demander_OuiNon([string]$Question) {
    if ($nonInteractif) { return $false }
    do { $r = (Read-Host "$Question [O/N]").Trim().ToUpper() } while ($r -notin @("O", "N"))
    return $r -eq "O"
}

$bilan = [System.Collections.Generic.List[object]]::new()
function Ajouter_Bilan([string]$Composant, [string]$Statut, [string]$Detail = "") {
    $bilan.Add([PSCustomObject]@{ Composant = $Composant; Statut = $Statut; Detail = $Detail })
}

# ─── RSAT ───────────────────────────────────────────────────
# Sur un DC, tout est deja present. Sur un serveur membre ou un poste, les modules AD, GPMC et DFS
# ne sont pas installes par defaut : sans eux, les scripts AD s'ignorent ou basculent en audit local.
#   Serveur : Install-WindowsFeature (fonctionnalites RSAT)
#   Poste   : Add-WindowsCapability (Features on Demand : Internet ou WSUS configure pour les FoD)
$composantsRsat = @(
    [PSCustomObject]@{
        Nom      = "Module ActiveDirectory"
        Scripts  = @("10_*", "11_*", "13_*", "14_*", "15_*", "32_*", "33_*")
        Present  = { [bool](Get-Module -ListAvailable -Name ActiveDirectory) }
        Feature  = "RSAT-AD-PowerShell"
        Capacite = "Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0"
    },
    [PSCustomObject]@{
        Nom      = "repadmin (outils AD DS)"
        Scripts  = @("21_*", "30_*")
        Present  = { [bool](Get-Command repadmin.exe -ErrorAction SilentlyContinue) }
        Feature  = "RSAT-ADDS-Tools"
        Capacite = "Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0"
    },
    [PSCustomObject]@{
        Nom      = "Module GroupPolicy (GPMC)"
        Scripts  = @("32_*", "33_*")
        Present  = { [bool](Get-Module -ListAvailable -Name GroupPolicy) }
        Feature  = "GPMC"
        Capacite = "Rsat.GroupPolicy.Management.Tools~~~~0.0.1.0"
    },
    [PSCustomObject]@{
        Nom      = "Module DFSN (espaces de noms DFS)"
        Scripts  = @("31_*")
        Present  = { [bool](Get-Module -ListAvailable -Name DFSN) }
        Feature  = "RSAT-DFS-Mgmt-Con"
        Capacite = "Rsat.FileServices.Tools~~~~0.0.1.0"
    }
)

Write-Host ""
Write-Host "Verification des outils RSAT..." -ForegroundColor Cyan

$cs = Get-CimInstance Win32_ComputerSystem
$os = Get-CimInstance Win32_OperatingSystem
$estServeur = $os.ProductType -ne 1          # 1 = poste, 2 = DC, 3 = serveur membre
$estDC      = $cs.DomainRole -ge 4

$utiles = @($composantsRsat | Where-Object { Script_Selectionne $_.Scripts })

if (-not $cs.PartOfDomain) {
    Write-Host "  Machine hors domaine - RSAT ignores (les scripts AD basculent en audit local)." -ForegroundColor DarkGray
    Ajouter_Bilan "RSAT" "Ignore" "Machine hors domaine"
} elseif ($utiles.Count -eq 0) {
    Write-Host "  Aucun script selectionne ne necessite les RSAT." -ForegroundColor DarkGray
} else {
    $manquants = @()
    foreach ($c in $utiles) {
        if (& $c.Present) {
            Write-Host "  [OK]      $($c.Nom)" -ForegroundColor Green
            Ajouter_Bilan $c.Nom "OK"
        } else {
            Write-Host "  [ABSENT]  $($c.Nom)  (scripts : $($c.Scripts -join ', '))" -ForegroundColor Yellow
            $manquants += $c
        }
    }

    if ($manquants.Count -gt 0) {
        if ($estDC) {
            # Ne devrait pas arriver : on n'installe rien sur un DC, on signale seulement
            Write-Warning "  Composants absents sur un controleur de domaine - verifier l'installation du role AD DS."
            foreach ($c in $manquants) { Ajouter_Bilan $c.Nom "ABSENT" "DC : verifier le role AD DS" }
        } else {
            Write-Host ""
            Write-Host "  L'installation ajoute des outils d'administration a cette machine" -ForegroundColor Yellow
            Write-Host "  ($(if ($estServeur) {'fonctionnalites Windows Server'} else {'Features on Demand, Internet ou WSUS requis'}))." -ForegroundColor Yellow
            if (Demander_OuiNon "  Installer les composants RSAT manquants ?") {
                # Plusieurs composants peuvent partager la meme fonctionnalite : installation unique
                $dejaFait = @{}
                foreach ($c in $manquants) {
                    $cible = if ($estServeur) { $c.Feature } else { $c.Capacite }
                    if (-not $dejaFait.ContainsKey($cible)) {
                        Write-Host "  Installation : $cible ..." -ForegroundColor Yellow
                        try {
                            if ($estServeur) {
                                $r = Install-WindowsFeature -Name $cible -ErrorAction Stop
                                $dejaFait[$cible] = [bool]$r.Success
                                if ($r.RestartNeeded -eq 'Yes') { Write-Warning "  Redemarrage requis pour $cible" }
                            } else {
                                Add-WindowsCapability -Online -Name $cible -ErrorAction Stop | Out-Null
                                $dejaFait[$cible] = $true
                            }
                        } catch {
                            $dejaFait[$cible] = $false
                            Write-Warning "  Echec $cible : $($_.Exception.Message)"
                            if (-not $estServeur) {
                                Write-Warning "  Poste sans Internet ou WSUS bloquant les FoD : installer les RSAT depuis l'ISO 'Features on Demand'."
                            }
                        }
                    }
                    # Re-verification reelle apres installation
                    if (& $c.Present) {
                        Write-Host "  [OK]      $($c.Nom)" -ForegroundColor Green
                        Ajouter_Bilan $c.Nom "Installe"
                    } else {
                        Ajouter_Bilan $c.Nom "ABSENT" "Installation echouee - scripts $($c.Scripts -join ', ') limites"
                    }
                }
            } else {
                Write-Host "  Installation refusee - les scripts concernes seront ignores ou limites." -ForegroundColor DarkGray
                foreach ($c in $manquants) { Ajouter_Bilan $c.Nom "ABSENT" "Installation refusee" }
            }
        }
    }
}

# ─── MICROSOFT GRAPH (seulement si 12_Audit_Comptes_365 est selectionne) ───
$script365 = Join-Path $root "Scripts\PowerShell\12_Audit_Comptes_365.ps1"
Write-Host ""
if ((Test-Path $script365) -and (Script_Selectionne "12_*")) {
    Write-Host "Verification Microsoft.Graph..." -ForegroundColor Cyan
    $mgModule = Get-Module -ListAvailable -Name Microsoft.Graph -ErrorAction SilentlyContinue
    if (-not $mgModule) {
        Write-Host "  Microsoft.Graph absent - installation..." -ForegroundColor Yellow
        try {
            Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force -Scope AllUsers -ErrorAction SilentlyContinue | Out-Null
            Set-PSRepository -Name PSGallery -InstallationPolicy Trusted -ErrorAction SilentlyContinue
            Install-Module Microsoft.Graph -Scope AllUsers -Force -AllowClobber -ErrorAction Stop
            Write-Host "  Microsoft.Graph installe." -ForegroundColor Green
            Ajouter_Bilan "Microsoft.Graph" "Installe"
        } catch {
            Write-Warning "  Microsoft.Graph echoue : $_"
            Write-Warning "  12_Audit_Comptes_365 sera ignore."
            Ajouter_Bilan "Microsoft.Graph" "ABSENT" "12_Audit_Comptes_365 ignore"
        }
    } else {
        $ver = ($mgModule | Sort-Object Version -Descending | Select-Object -First 1).Version
        Write-Host "  Microsoft.Graph v$ver" -ForegroundColor Green
        Ajouter_Bilan "Microsoft.Graph" "OK" "v$ver"
    }
} else {
    Write-Host "12_Audit_Comptes_365 non selectionne - Microsoft.Graph ignore." -ForegroundColor DarkGray
}

# ─── NPCAP (seulement si 00_Reconnaissance est selectionne) ─
if (Script_Selectionne "00_*") {
    $npcapInstaller = Join-Path $root "Tools\Nmap\npcap-installer.exe"
    $service = Get-Service -Name npcap -ErrorAction SilentlyContinue
    Write-Host "Verification Npcap..." -ForegroundColor Cyan
    if ($service) {
        Write-Host "  Npcap : $($service.Status)" -ForegroundColor Green
        Ajouter_Bilan "Npcap" "OK" "$($service.Status)"
    } elseif (Test-Path $npcapInstaller) {
        Write-Host ""
        Write-Host "  *** ACTION REQUISE ***" -ForegroundColor Yellow
        Write-Host "  Npcap va s ouvrir - cocher 'WinPcap API-compatible mode'" -ForegroundColor Yellow
        Write-Host ""
        Start-Process $npcapInstaller -Wait
        Start-Sleep -Seconds 3
        Start-Service -Name npcap -ErrorAction SilentlyContinue
        if (Get-Service -Name npcap -ErrorAction SilentlyContinue) {
            Write-Host "  Npcap installe." -ForegroundColor Green
            Ajouter_Bilan "Npcap" "Installe"
        } else {
            Ajouter_Bilan "Npcap" "ABSENT" "Installation non terminee - detection d'OS Nmap limitee"
        }
    } else {
        Write-Host "  npcap-installer.exe absent de Tools\Nmap\ - Npcap ignore." -ForegroundColor DarkGray
        Ajouter_Bilan "Npcap" "ABSENT" "npcap-installer.exe absent de Tools\Nmap\"
    }
} else {
    Write-Host "00_Reconnaissance non selectionne - Npcap ignore." -ForegroundColor DarkGray
}

# ─── PSEXEC (seulement si 00_Reconnaissance est selectionne) ─
# Audit distant des machines sans WinRM. Hors ligne prioritaire : Tools\PsExec*.exe ou
# Tools\PSTools.zip ; sinon telechargement depuis Sysinternals.
if (Script_Selectionne "00_*") {
    Write-Host "Verification PsExec..." -ForegroundColor Cyan
    $toolsDir = Join-Path $root "Tools"

    $psexec = @(
        (Join-Path $toolsDir "PsExec64.exe"),
        (Join-Path $toolsDir "PsExec.exe"),
        (Join-Path $toolsDir "PSTools\PsExec64.exe"),
        (Join-Path $toolsDir "PSTools\PsExec.exe")
    ) | Where-Object { Test-Path $_ } | Select-Object -First 1

    if (-not $psexec) {
        $psexec = Get-Command PsExec64.exe, PsExec.exe -ErrorAction SilentlyContinue |
                  Select-Object -First 1 -ExpandProperty Source
    }

    $destDir = Join-Path $toolsDir "PSTools"

    # Archive hors ligne deposee manuellement dans Tools\
    if (-not $psexec) {
        $zipLocal = Join-Path $toolsDir "PSTools.zip"
        if (Test-Path $zipLocal) {
            Write-Host "  Archive locale PSTools.zip detectee - extraction..." -ForegroundColor Yellow
            try {
                Expand-Archive -Path $zipLocal -DestinationPath $destDir -Force
                $psexec = @((Join-Path $destDir "PsExec64.exe"), (Join-Path $destDir "PsExec.exe")) |
                          Where-Object { Test-Path $_ } | Select-Object -First 1
            } catch { Write-Warning "  Extraction PSTools.zip echouee : $_" }
        }
    }

    # Telechargement en dernier recours
    if (-not $psexec) {
        Write-Host "  PsExec absent - telechargement depuis Sysinternals..." -ForegroundColor Yellow
        New-Item -ItemType Directory -Force -Path $destDir | Out-Null
        $zip = Join-Path $toolsDir "PSTools.zip"
        $url = "https://download.sysinternals.com/files/PsTools.zip"
        try {
            [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
            $ProgressPreference = 'SilentlyContinue'
            Invoke-WebRequest -Uri $url -OutFile $zip -UseBasicParsing -ErrorAction Stop
            Expand-Archive -Path $zip -DestinationPath $destDir -Force
            Remove-Item $zip -Force -ErrorAction SilentlyContinue
            $psexec = @((Join-Path $destDir "PsExec64.exe"), (Join-Path $destDir "PsExec.exe")) |
                      Where-Object { Test-Path $_ } | Select-Object -First 1
        } catch {
            Write-Warning "  Telechargement PsExec echoue : $_"
            Write-Warning "  Audit distant sans WinRM indisponible. Deposez PSTools.zip (ou PsExec64.exe) dans $toolsDir"
        }
    }

    if ($psexec) {
        # Pre-accepter l'EULA (cle registre) pour eviter tout prompt a distance
        Start-Process $psexec -ArgumentList "-accepteula","-nobanner" -NoNewWindow -Wait -ErrorAction SilentlyContinue
        Write-Host "  PsExec : $psexec" -ForegroundColor Green
        Ajouter_Bilan "PsExec" "OK" $psexec
    } else {
        Ajouter_Bilan "PsExec" "ABSENT" "Audit distant sans WinRM indisponible"
    }
} else {
    Write-Host "00_Reconnaissance non selectionne - PsExec ignore." -ForegroundColor DarkGray
}

# ─── BILAN ──────────────────────────────────────────────────
Write-Host ""
Write-Host "=== PREREQUIS ===" -ForegroundColor Cyan
if ($bilan.Count -eq 0) {
    Write-Host "  Aucun prerequis necessaire pour les scripts selectionnes." -ForegroundColor DarkGray
} else {
    foreach ($b in $bilan) {
        $couleur = switch ($b.Statut) { "ABSENT" { "Yellow" } "Ignore" { "DarkGray" } default { "Green" } }
        $ligne = "  {0,-36} {1,-9} {2}" -f $b.Composant, $b.Statut, $b.Detail
        Write-Host $ligne -ForegroundColor $couleur
    }
}
Write-Host ""
Write-Host "Rappel : Python + openpyxl ne sont necessaires que pour Process_excels.py (mise en forme Excel)." -ForegroundColor DarkGray

Stop-Transcript
exit 0