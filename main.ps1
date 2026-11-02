# main.ps1
# Version      : 4.1
# Derniere modif : Modules 14_PSO, 15_Silos, 33_Groupes (descriptions + bundles), init.ps1 non bloquant
#                  (Python retire, RSAT ajoutes), scripts prefixes par "_" (desactives) toujours
#                  ignores, y compris par le bundle "Tous", rappel Process_excels en fin d'execution,
#                  sous-dossier Temp_CSV\AD (GPO, PSO, Silos, Groupes, Replication)
# Role         : Orchestrateur principal - cartographie SI
# Usage        : .\main.ps1 [-Include <pattern>] [-Exclude <pattern>] [-SkipInit] [-DryRun] [-StopOnErr]
# ============================================================

param(
    [string[]] $Include   = @(),
    [string[]] $Exclude   = @("main.ps1"),
    [switch]   $DryRun,
    [switch]   $StopOnErr,
    [switch]   $SkipInit
)

# Apres une relance via -File, "10_*,20_*" arrive en une seule chaine : on la redecoupe
$Include = @($Include | ForEach-Object { $_ -split ',' } | ForEach-Object { $_.Trim() } | Where-Object { $_ })
$Exclude = @($Exclude | ForEach-Object { $_ -split ',' } | ForEach-Object { $_.Trim() } | Where-Object { $_ })

# ─── AUTO-ELEVATION (relance en admin si necessaire) ────────
# La lecture de certains attributs AD (userAccountControl, etc.) exige des droits eleves.
# Si le script n'est pas lance en administrateur, on le relance automatiquement via UAC.
$estAdmin = ([Security.Principal.WindowsPrincipal] `
    [Security.Principal.WindowsIdentity]::GetCurrent()
).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $estAdmin) {
    Write-Host "Elevation des privileges requise - relance en administrateur..." -ForegroundColor Yellow

    # Reconstruire les arguments passes au script pour les transmettre a la relance
    $argsRelance = @("-NoProfile", "-ExecutionPolicy", "Bypass", "-File", "`"$PSCommandPath`"")
    if ($Include)   { $argsRelance += "-Include";   $argsRelance += ($Include -join ",") }
    if ($Exclude)   { $argsRelance += "-Exclude";   $argsRelance += ($Exclude -join ",") }
    if ($DryRun)    { $argsRelance += "-DryRun" }
    if ($StopOnErr) { $argsRelance += "-StopOnErr" }
    if ($SkipInit)  { $argsRelance += "-SkipInit" }

    try {
        Start-Process -FilePath "powershell.exe" -ArgumentList $argsRelance -Verb RunAs
    } catch {
        Write-Warning "Elevation refusee ou impossible. Relancez PowerShell en tant qu'administrateur."
    }
    exit
}

# ─── CHEMINS ────────────────────────────────────────────────
$root      = $PSScriptRoot
$psDir     = Join-Path $root "Scripts\PowerShell"
$tempCsv   = Join-Path $root "Temp_CSV"
$logs      = Join-Path $root "Logs"
$initScript= Join-Path $root "init.ps1"
$runId     = Get-Date -Format "yyyyMMdd_HHmmss"
$logFile   = Join-Path $logs "Audit_$runId.log"

New-Item -ItemType Directory -Force -Path $logs    | Out-Null
New-Item -ItemType Directory -Force -Path $tempCsv | Out-Null
foreach ($sub in @("Comptes","AD","HV","VM","NTFS")) {
    New-Item -ItemType Directory -Force -Path (Join-Path $tempCsv $sub) | Out-Null
}

$env:AUDIT_TEMP_CSV     = $tempCsv
$env:AUDIT_TEMP_COMPTES = Join-Path $tempCsv "Comptes"
$env:AUDIT_TEMP_AD      = Join-Path $tempCsv "AD"
$env:AUDIT_TEMP_HV      = Join-Path $tempCsv "HV"
$env:AUDIT_TEMP_VM      = Join-Path $tempCsv "VM"
$env:AUDIT_TEMP_NTFS    = Join-Path $tempCsv "NTFS"
$env:AUDIT_RUN_ID       = $runId

Start-Transcript -Path $logFile -Append -Force

Write-Host ""
Write-Host "============================================" -ForegroundColor Cyan
Write-Host "  NewAuditroV3 - Cartographie SI"           -ForegroundColor Cyan
Write-Host "  $env:COMPUTERNAME | $(Get-Date -Format 'dd/MM/yyyy HH:mm')" -ForegroundColor Cyan
Write-Host "============================================" -ForegroundColor Cyan
Write-Host ""

# ─── MENU DE SELECTION ──────────────────────────────────────
# Affiche le menu uniquement si -Include n'est pas fourni en parametre

$bundles = [ordered]@{
    "1" = [PSCustomObject]@{
        Nom     = "Tous les scripts"
        Include = @("*.ps1")
    }
    "2" = [PSCustomObject]@{
        Nom     = "Bundle Comptes  : T0 + AD + M365 + PSO + Silos"
        Include = @("10_*","11_*","12_*","14_*","15_*")
    }
    "3" = [PSCustomObject]@{
        Nom     = "Bundle SI       : OUs + VMs + Replication + Hyperviseurs"
        Include = @("13_*","20_*","21_*","30_*")
    }
    "4" = [PSCustomObject]@{
        Nom     = "Bundle AD       : Comptes + OUs + PSO + Silos + NTFS + GPO + Groupes"
        Include = @("10_*","11_*","13_*","14_*","15_*","31_*","32_*","33_*")
    }
    "5" = [PSCustomObject]@{
        Nom     = "Reconnaissance  : scan reseau uniquement"
        Include = @("00_*")
    }
    "6" = [PSCustomObject]@{
        Nom     = "Selection manuelle"
        Include = @()
    }
}

if ($Include.Count -eq 0 -and $Exclude.Count -le 1) {  # 1 = valeur par defaut "main.ps1"
    Write-Host "Que voulez-vous auditer ?" -ForegroundColor Yellow
    Write-Host ""
    foreach ($key in $bundles.Keys) {
        Write-Host "  [$key] $($bundles[$key].Nom)" -ForegroundColor White
    }
    Write-Host ""
    Write-Host "Votre choix : " -ForegroundColor Yellow -NoNewline
    $choix = Read-Host

    if ($bundles.Contains($choix)) {
        if ($choix -eq "6") {
            Write-Host ""
            Write-Host "Scripts disponibles :" -ForegroundColor Cyan
            Get-ChildItem -Path $psDir -Filter "*.ps1" |
                Where-Object { $_.Name -notlike "_*" } |
                Sort-Object Name |
                ForEach-Object { Write-Host "  $($_.BaseName)" -ForegroundColor White }
            Write-Host ""
            Write-Host "Numeros a lancer (ex: 10,31,33) : " -ForegroundColor Yellow -NoNewline
            $selection = Read-Host
            $Include = @(($selection -split ",") | ForEach-Object { $_.Trim() } | Where-Object { $_ } |
                         ForEach-Object { "$($_)_*" })
        } else {
            $Include = $bundles[$choix].Include
        }
        Write-Host ""
        Write-Host "Selection : $($bundles[$choix].Nom)" -ForegroundColor Green
        Write-Host ""
    } else {
        Write-Host "Choix invalide - tous les scripts seront lances." -ForegroundColor Yellow
        $Include = @("*.ps1")
    }
}

# ─── COLLECTE DES SCRIPTS ───────────────────────────────────
function Get-ScriptsToRun {
    param([string]$Folder, [string[]]$Include, [string[]]$Exclude)

    if (-not (Test-Path $Folder)) {
        Write-Warning "Dossier introuvable : $Folder"
        return @()
    }

    # Un script prefixe par "_" est desactive : jamais lance, quel que soit le motif (meme "*.ps1")
    $tous = Get-ChildItem -Path $Folder -Filter "*.ps1" -File | Where-Object { $_.Name -notlike "_*" }

    # Filtrer les inclusions
    $selectionnes = @()
    foreach ($pattern in $Include) {
        $selectionnes += $tous | Where-Object { $_.Name -like $pattern }
    }

    # Filtrer les exclusions
    foreach ($pattern in $Exclude) {
        $selectionnes = $selectionnes | Where-Object { $_.Name -notlike $pattern }
    }

    # Enlever les doublons et trier par numero
    $selectionnes = $selectionnes | Sort-Object Name -Unique

    # Ignorer les scripts desactives (commentaire AUDIT: disabled)
    $selectionnes = $selectionnes | Where-Object {
        $contenu = Get-Content $_.FullName -TotalCount 15 -ErrorAction SilentlyContinue
        -not ($contenu -match '#\s*AUDIT:\s*disabled')
    }

    return $selectionnes | Sort-Object {
        if ($_.Name -match '^(\d+)') { [int]$Matches[1] } else { 999 }
    }
}

$scripts = Get-ScriptsToRun -Folder $psDir -Include $Include -Exclude $Exclude

if ($scripts.Count -eq 0) {
    Write-Warning "Aucun script trouve avec les criteres selectionnes."
    Stop-Transcript
    exit 0
}

# ─── INIT (prerequis) ───────────────────────────────────────
if ($SkipInit) {
    Write-Host "init.ps1 ignore (-SkipInit)." -ForegroundColor DarkGray
} else {
    if (-not (Test-Path $initScript)) {
        Write-Error "init.ps1 introuvable dans $root"
        Stop-Transcript
        exit 1
    }
    # Dire a init.ps1 quels scripts vont tourner (pour n installer que ce qui est utile)
    $env:AUDIT_SELECTED_SCRIPTS = ($scripts | ForEach-Object { $_.BaseName }) -join ","

    Write-Host "Verification des prerequis (init.ps1)..." -ForegroundColor Cyan
    $proc = Start-Process powershell.exe `
        -ArgumentList @("-NoProfile","-ExecutionPolicy","Bypass","-File",$initScript) `
        -Wait -PassThru -NoNewWindow

    # init.ps1 n'est plus bloquant (bilan affiche par init) : un code non nul = plantage inattendu
    if ($proc.ExitCode -ne 0) {
        Write-Warning "init.ps1 s'est termine avec le code $($proc.ExitCode) - voir Logs\Init_*.log. L'audit continue."
    } else {
        Write-Host "Prerequis verifies." -ForegroundColor Green
    }
    Write-Host ""
}

# ─── NTFS ───────────────────────────────────────────────────
# Plus de question ici : 31_Audit_NTFS.ps1 gere seul la selection des partages, les chemins
# supplementaires et la profondeur. AUDIT_NTFS_PATHS / AUDIT_NTFS_DEPTH restent utilisables.

# ─── VALIDATION UTILISATEUR ─────────────────────────────────
$descriptions = @{
    "00_Reconnaissance"      = "Scan reseau, detection OS, audit Windows (WinRM ou PsExec) et Linux (SSH)"
    "10_Audit_comptes_T0"    = "Comptes privilegies Tier 0 (adminCount=1) ou comptes locaux"
    "11_Audit_comptes"       = "Tous les comptes AD ou locaux"
    "12_Audit_Comptes_365"   = "Comptes Microsoft 365 via Graph API"
    "13_Arborescence_OU"     = "Arborescence des OUs Active Directory"
    "14_Audit_PSO"           = "Strategies de mot de passe affinees (PSO) + politique effective par compte"
    "15_Audit_Silos"         = "Silos et strategies d'authentification, comptes T0 hors silo"
    "21_Audit_VMs"           = "Inventaire VM : OS, IP, roles, FSMO, hyperviseur, WinRM"
    "22_Audit_Workstation"   = "Inventaire poste Windows (meme schema que l audit VM)"
    "30_Audit_Replication"   = "Etat replication AD (necessite 21_Audit_VMs)"
    "20_Audit_Hyperviseurs"  = "Inventaire hyperviseur Hyper-V"
    "31_Audit_NTFS"          = "Partages SMB/DFS : droits NTFS + partage, profondeur interactive, schema arborescence"
    "32_Audit_GPO"           = "Inventaire GPO : createur, OUs liees, statut"
    "33_Audit_Groupes"       = "Groupes AD : membres effectifs, imbrication, T0, references NTFS/GPO"
    "23_Audit_Linux"         = "Audit SSH Linux : OS, utilisateurs, services, interfaces"
}

Write-Host ""
Write-Host "Scripts qui vont etre lances :" -ForegroundColor Cyan
Write-Host ""
$largeur = ($scripts | ForEach-Object { $_.BaseName.Length } | Measure-Object -Maximum).Maximum
foreach ($s in $scripts) {
    $desc = $descriptions[$s.BaseName]
    if (-not $desc) { $desc = "Script personnalise" }
    $espace = " " * ($largeur - $s.BaseName.Length + 2)
    Write-Host "  + $($s.BaseName)$espace" -NoNewline -ForegroundColor White
    Write-Host $desc -ForegroundColor DarkGray
}
Write-Host ""
Write-Host "Lancer ces $($scripts.Count) script(s) ? [O/N] : " -ForegroundColor Yellow -NoNewline
$confirm = Read-Host
if ($confirm -notmatch "^[OoYy]") {
    Write-Host "Audit annule." -ForegroundColor DarkGray
    Stop-Transcript
    exit 0
}
Write-Host ""

# ─── EXECUTION DES SCRIPTS ──────────────────────────────────
function Run_Script {
    param([string]$ScriptPath, [switch]$DryRun, [switch]$StopOnErr)

    $nom    = [System.IO.Path]::GetFileNameWithoutExtension($ScriptPath)
    $logDst = Join-Path $logs "${nom}_${runId}.log"
    $debut  = Get-Date

    # NB : ne pas nommer cette variable $resultat -> collision possible avec les variables des scripts
    $runRes = [PSCustomObject]@{
        Script   = $nom
        Statut   = "EN_COURS"
        Code     = $null
        Debut    = $debut
        Fin      = $null
        Log      = $logDst
    }

    if ($DryRun) {
        Write-Host "  [DRY-RUN] $nom" -ForegroundColor Yellow
        $runRes.Statut = "DRY-RUN"
        $runRes.Fin    = Get-Date
        return $runRes
    }

    Write-Host ">> $nom" -ForegroundColor Cyan

    # Scripts interactifs (Read-Host) : processus PowerShell dedie qui partage la console.
    # Avant : dot-source -> un 'exit' dans le script tuait main.ps1 (pas de resume, scripts suivants
    # non lances) et ses variables ecrasaient celles de Run_Script.
    $estInteractif = $nom -match "^_?00_|^31_"

    if ($estInteractif) {
        Write-Host "   [Mode interactif]" -ForegroundColor DarkYellow
        $env:AUDIT_SCRIPT_LOG = $logDst     # le script demarre son propre transcript
        try {
            $p = Start-Process -FilePath "powershell.exe" `
                -ArgumentList @("-NoProfile","-ExecutionPolicy","Bypass","-File","`"$ScriptPath`"") `
                -NoNewWindow -Wait -PassThru
            $runRes.Code   = $p.ExitCode
            $runRes.Statut = if ($p.ExitCode -eq 0) { "OK" } else { "ERREUR" }
        } catch {
            $runRes.Code   = 1
            $runRes.Statut = "ERREUR"
            Write-Warning "Erreur dans $nom : $_"
        } finally {
            Remove-Item Env:\AUDIT_SCRIPT_LOG -ErrorAction SilentlyContinue
        }
        if (-not (Test-Path $logDst)) { "[Pas de transcript produit par $nom]" | Out-File $logDst -Encoding UTF8 }
        if ($runRes.Code -ne 0) {
            Write-Warning "$nom termine avec code $($runRes.Code) - voir : $logDst"
            if ($StopOnErr) { throw "Arret sur erreur demande (-StopOnErr)" }
        } else {
            Write-Host "   OK - log : $logDst" -ForegroundColor Green
        }
    } else {
        # Scripts non-interactifs : processus separe avec capture de sortie
        $psi = New-Object System.Diagnostics.ProcessStartInfo
        $psi.FileName               = "powershell.exe"
        $psi.Arguments              = "-NoProfile -ExecutionPolicy Bypass -File `"$ScriptPath`""
        $psi.RedirectStandardOutput = $true
        $psi.RedirectStandardError  = $true
        $psi.UseShellExecute        = $false

        $p = [System.Diagnostics.Process]::Start($psi)
        # stderr lu en asynchrone : evite l'interblocage si le tampon stderr se remplit
        $taskErr = $p.StandardError.ReadToEndAsync()
        $stdout  = $p.StandardOutput.ReadToEnd()
        $p.WaitForExit()
        $stderr  = $taskErr.Result

        $stdout | Out-File $logDst -Encoding UTF8
        if ($stderr) { "`n--- ERREURS ---`n$stderr" | Out-File $logDst -Append -Encoding UTF8 }

        $runRes.Code = $p.ExitCode
        $runRes.Statut = if ($p.ExitCode -eq 0) { "OK" } else { "ERREUR" }

        if ($p.ExitCode -ne 0) {
            Write-Warning "$nom termine avec code $($p.ExitCode) - voir : $logDst"
            if ($StopOnErr) { throw "Arret sur erreur demande (-StopOnErr)" }
        } else {
            Write-Host "   OK - log : $logDst" -ForegroundColor Green
        }
    }

    $runRes.Fin = Get-Date
    return $runRes
}

$resultats = @()
foreach ($s in $scripts) {
    try {
        $resultats += Run_Script -ScriptPath $s.FullName -DryRun:$DryRun -StopOnErr:$StopOnErr
    } catch {
        Write-Warning "Arret demande suite a une erreur."
        break
    }
}

# ─── RESUME ─────────────────────────────────────────────────
Write-Host ""
Write-Host "============================================" -ForegroundColor Cyan
Write-Host "  RESUME" -ForegroundColor Cyan
Write-Host "============================================" -ForegroundColor Cyan
$resultats | Select-Object Script, Statut, Code, Debut, Fin | Format-Table -AutoSize

$ok      = ($resultats | Where-Object Statut -eq "OK").Count
$erreurs = ($resultats | Where-Object Statut -in @("ERREUR","EXCEPTION")).Count
$couleur = if ($erreurs -gt 0) { "Red" } else { "Green" }
Write-Host "OK : $ok  |  Erreurs : $erreurs" -ForegroundColor $couleur
Write-Host "CSV dans : $tempCsv" -ForegroundColor Yellow
Write-Host "Excel   : python Process_excels.py --force   (Python + openpyxl, sur cette machine ou une autre)" -ForegroundColor DarkGray
Write-Host ""

Stop-Transcript