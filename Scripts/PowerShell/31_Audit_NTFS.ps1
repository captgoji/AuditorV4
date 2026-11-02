# 50_Audit_NTFS.ps1
# Version      : 3.1 (V4)
# Derniere modif : Resolution des liens DFS (suivis vers leur cible reelle), exclusion d'office de
#                  SYSVOL / NETLOGON (par nom de partage ET par chemin), distinction DFS-link /
#                  jonction locale / autre lien, profondeur DFS demandee au lancement, colonne
#                  Categorie dans le journal (Information vs Erreur).
# Role         : Decouvre les partages, demande lesquels auditer et jusqu'a quelle profondeur,
#                exporte les ACL NTFS de chaque dossier/sous-dossier et genere un schema de l'arborescence.
#                Lance depuis un DC, il peut auditer les partages DFS sans jamais toucher SYSVOL/NETLOGON.
# Usage        : Lance via main.ps1 (processus console dedie) ou directement.
#                Variables d'environnement optionnelles (utiles en non-interactif / WinRM) :
#                  AUDIT_NTFS_PATHS        chemins pre-definis, separes par ';'
#                  AUDIT_NTFS_DEPTH        profondeur par defaut (entier, '*' = illimitee)   [defaut 3]
#                  AUDIT_NTFS_DFS_DEPTH    profondeur sur les cibles DFS distantes (entier, '*')  [defaut = AUDIT_NTFS_DEPTH]
#                  AUDIT_NTFS_EXCLURE      noms de partages a exclure en plus de SYSVOL/NETLOGON, separes par ';'
#                  AUDIT_NTFS_MAX_DOSSIERS garde-fou : nb max de dossiers par racine          [defaut 50000]
#                  AUDIT_NONINTERACTIVE    '1' = aucune question, tous les partages SMB audites
# Sorties (Temp_CSV\NTFS\) :
#   <HOST>_Audit_NTFS.csv                 une ligne par ACE et par dossier (colonnes TailleOctets/Taille incluses)
#   <HOST>_Audit_NTFS_Partages.csv        droits de partage SMB (Get-SmbShareAccess)
#   <HOST>_Audit_NTFS_Erreurs.csv         dossiers inaccessibles / ignores
#   <HOST>_Audit_NTFS_Arborescence.txt    schema texte (ASCII) avec droits explicites
#   <HOST>_Audit_NTFS_Arborescence.html   schema interactif (depliage par niveau, recherche, detail des ACE)
# ============================================================

$ErrorActionPreference = "Continue"

# ─── TRANSCRIPT PROPRE (main.ps1 fournit AUDIT_SCRIPT_LOG) ──
$transcriptActif = $false
if ($env:AUDIT_SCRIPT_LOG) {
    try { Start-Transcript -Path $env:AUDIT_SCRIPT_LOG -Append -Force | Out-Null; $transcriptActif = $true } catch {}
}

# ─── CONTEXTE ───────────────────────────────────────────────
$tempCsv = if ($env:AUDIT_TEMP_CSV) { $env:AUDIT_TEMP_CSV } else {
    Join-Path (Split-Path (Split-Path $PSScriptRoot -Parent) -Parent) "Temp_CSV"
}
$ntfsDir    = if ($env:AUDIT_TEMP_NTFS) { $env:AUDIT_TEMP_NTFS } else { Join-Path $tempCsv "NTFS" }
$CompSys    = Get-CimInstance Win32_ComputerSystem -ErrorAction SilentlyContinue
$IsDomain   = if ($CompSys) { [bool]$CompSys.PartOfDomain } else { $false }
$DomainName = if ($CompSys) { $CompSys.Domain } else { "WORKGROUP" }
$Serveur    = "$env:COMPUTERNAME.$DomainName"
$prefixe    = Join-Path $ntfsDir $Serveur

$FichierCsv      = "${prefixe}_Audit_NTFS.csv"
$FichierPartages = "${prefixe}_Audit_NTFS_Partages.csv"
$FichierErreurs  = "${prefixe}_Audit_NTFS_Erreurs.csv"
$FichierTxt      = "${prefixe}_Audit_NTFS_Arborescence.txt"
$FichierHtml     = "${prefixe}_Audit_NTFS_Arborescence.html"

$profDefaut = 3
if ($env:AUDIT_NTFS_DEPTH) {
    if ($env:AUDIT_NTFS_DEPTH -eq '*') { $profDefaut = -1 }
    elseif ($env:AUDIT_NTFS_DEPTH -match '^\d+$') { $profDefaut = [int]$env:AUDIT_NTFS_DEPTH }
}
$maxDossiers = 50000
if ($env:AUDIT_NTFS_MAX_DOSSIERS -match '^\d+$') { $maxDossiers = [int]$env:AUDIT_NTFS_MAX_DOSSIERS }

# Profondeur du detail de taille disque (Go). Au-dela, le poids est cumule dans le niveau plafond.
# Le comptage de dossiers, lui, reste complet (tous niveaux). Defaut : 5.
$profTaille = 5
if ($env:AUDIT_NTFS_SIZE_DEPTH -match '^\d+$') { $profTaille = [int]$env:AUDIT_NTFS_SIZE_DEPTH }

# Partages exclus d'office (jamais audites), compares sur le nom SMB en insensible a la casse.
# SYSVOL / NETLOGON : repliques FRS/DFSR, sans interet pour un audit de droits et truffes de jonctions.
$exclusionsPartages = @('SYSVOL','NETLOGON')
if ($env:AUDIT_NTFS_EXCLURE) {
    $exclusionsPartages += ($env:AUDIT_NTFS_EXCLURE -split ';' | ForEach-Object { $_.Trim() } | Where-Object { $_ })
}
$exclusionsPartages = $exclusionsPartages | Sort-Object -Unique

# Segments de chemin a ne jamais parcourir, meme atteints via une jonction
# (SYSVOL est expose par plusieurs chemins sur un DC). Construit a partir de $exclusionsPartages
# pour qu'un nom ajoute via AUDIT_NTFS_EXCLURE soit aussi bloque en tant que sous-dossier.
$regexCheminsExclus = ($exclusionsPartages | ForEach-Object { [regex]::Escape($_) }) -join '|'

function Chemin-EstExclu {
    param([string]$Chemin)
    if (-not $regexCheminsExclus) { return $false }
    # match sur un segment entier, quel que soit le separateur ( \ sous Windows )
    return [bool]($Chemin -match "[\\/]($regexCheminsExclus)([\\/]|`$)")
}

# Mode interactif : console reelle, entree non redirigee, pas de forcage
$modeInteractif = [Environment]::UserInteractive -and ($env:AUDIT_NONINTERACTIVE -ne '1')
try { if ([Console]::IsInputRedirected) { $modeInteractif = $false } } catch {}

# ─── REFERENTIELS SID ───────────────────────────────────────
# Comparaison par SID => independant de la langue de l'OS (Everyone / Tout le monde...)
$sidsLarges = @{
    'S-1-1-0'      = 'Tout le monde'
    'S-1-5-7'      = 'Anonyme'
    'S-1-5-11'     = 'Utilisateurs authentifies'
    'S-1-5-32-545' = 'Utilisateurs (BUILTIN)'
    'S-1-5-32-546' = 'Invites (BUILTIN)'
}
$regexSidsLargesDomaine = '-(513|514)$'          # Utilisateurs du domaine / Invites du domaine
$sidsAdminAttendus = @('S-1-5-18','S-1-5-32-544','S-1-3-0','S-1-5-32-549','S-1-5-32-551')
$regexSidsAdminDomaine = '-(512|519)$'           # Admins du domaine / Admins de l'entreprise

$script:cacheSid = @{}
function Resoudre-Sid {
    param([string]$Sid)
    if ($script:cacheSid.ContainsKey($Sid)) { return $script:cacheSid[$Sid] }
    $nom = $null
    try {
        $nom = ([System.Security.Principal.SecurityIdentifier]$Sid).Translate([System.Security.Principal.NTAccount]).Value
    } catch {}
    $script:cacheSid[$Sid] = $nom
    return $nom
}

# ─── TRADUCTION DES DROITS ──────────────────────────────────
function Convertir-Droits {
    param($Rights)
    # Valeur 32 bits non signee (les droits generiques utilisent le bit de poids fort)
    $v = ([int64]([int]$Rights)) -band 4294967295
    $generiques = @()
    if ($v -band 0x10000000) { return "Controle total" }
    if ($v -band 2147483648) { $generiques += "Lecture" }
    if ($v -band 0x40000000) { $generiques += "Ecriture" }
    if ($v -band 0x20000000) { $generiques += "Execution" }
    if ($generiques.Count -gt 0) { return ($generiques -join "/") + " (generique)" }

    $v = $v -bor 0x100000   # Synchronize, souvent absent des ACE heritees de vieux serveurs
    $FullControl    = 2032127
    $Modify         = 1245631
    $ReadAndExecute = 1179817
    $Read           = 1179785
    $Write          = 1048854

    if (($v -band $FullControl)    -eq $FullControl)    { return "Controle total" }
    if (($v -band $Modify)         -eq $Modify)         { return "Modification" }
    $lit   = (($v -band $Read) -eq $Read)
    $exec  = (($v -band $ReadAndExecute) -eq $ReadAndExecute)
    $ecrit = (($v -band $Write) -eq $Write)
    if ($exec -and $ecrit) { return "Lecture et execution + Ecriture" }
    if ($lit  -and $ecrit) { return "Lecture + Ecriture" }
    if ($exec)             { return "Lecture et execution" }
    if ($lit)              { return "Lecture" }
    if ($ecrit)            { return "Ecriture" }
    if (($v -band 0x21) -eq 0x21) { return "Parcours / Liste" }
    return "Speciales"
}

function Droits-PermettentEcriture {
    param($Rights)
    $v = ([int64]([int]$Rights)) -band 4294967295
    # GENERIC_ALL | GENERIC_WRITE | WriteData | AppendData | Delete | DeleteSubdirs | WriteDAC | WriteOwner
    return [bool]($v -band (0x10000000 -bor 0x40000000 -bor 0x2 -bor 0x4 -bor 0x10000 -bor 0x40 -bor 0x40000 -bor 0x80000))
}

function Convertir-Portee {
    param($Inheritance, $Propagation)
    $ci = [bool]($Inheritance -band [System.Security.AccessControl.InheritanceFlags]::ContainerInherit)
    $oi = [bool]($Inheritance -band [System.Security.AccessControl.InheritanceFlags]::ObjectInherit)
    $io = [bool]($Propagation -band [System.Security.AccessControl.PropagationFlags]::InheritOnly)
    $np = [bool]($Propagation -band [System.Security.AccessControl.PropagationFlags]::NoPropagateInherit)

    $txt = if     (-not $ci -and -not $oi) { "Ce dossier seulement" }
           elseif ($ci -and $oi -and -not $io) { "Ce dossier, sous-dossiers et fichiers" }
           elseif ($ci -and -not $oi -and -not $io) { "Ce dossier et sous-dossiers" }
           elseif (-not $ci -and $oi -and -not $io) { "Ce dossier et fichiers" }
           elseif ($ci -and $oi -and $io) { "Sous-dossiers et fichiers seulement" }
           elseif ($ci -and $io) { "Sous-dossiers seulement" }
           else { "Fichiers seulement" }
    if ($np) { $txt += " (1 niveau)" }
    return $txt
}

# ─── CHEMINS LONGS (> 260 car. en PowerShell 5.1) ──────────
function Chemin-Api {
    param([string]$Chemin)
    if ($Chemin.Length -lt 240 -or $Chemin.StartsWith('\\?\')) { return $Chemin }
    if ($Chemin.StartsWith('\\')) { return '\\?\UNC\' + $Chemin.Substring(2) }
    return '\\?\' + $Chemin
}
function Chemin-Affichage {
    param([string]$Chemin)
    if ($Chemin.StartsWith('\\?\UNC\')) { return '\\' + $Chemin.Substring(8) }
    if ($Chemin.StartsWith('\\?\'))     { return $Chemin.Substring(4) }
    return $Chemin
}

# ─── CLASSIFICATION DES POINTS D'ANALYSE (reparse points) ───
# Trois cas a distinguer :
#   - DFS link    : le dossier redirige vers un serveur cible -> IL FAUT le suivre (les ACL sont au bout)
#   - SYSVOL/etc. : exclu par nom -> ne jamais suivre
#   - Jonction/symlink local : ne pas suivre (boucles, doublons)
# Tag de reparse DFS = 0x8000000A (IO_REPARSE_TAG_DFS). On le lit via fsutil, fiable sur tout Windows.
$script:cacheReparse = @{}
function Get-TypeReparse {
    param([string]$Chemin)
    if ($script:cacheReparse.ContainsKey($Chemin)) { return $script:cacheReparse[$Chemin] }
    $type = "Jonction"
    try {
        $sortie = & fsutil reparsepoint query "$Chemin" 2>$null
        if ($LASTEXITCODE -eq 0 -and $sortie) {
            $ligneTag = ($sortie | Select-String -Pattern 'Reparse Tag Value|Valeur de la balise' | Select-Object -First 1)
            if ($ligneTag -match '0x([0-9a-fA-F]+)') {
                $tag = [Convert]::ToInt64($Matches[1],16)
                # 0x8000000A = DFS, 0x80000012 = DFSR ; les deux pointent vers une cible a auditer
                if ($tag -eq 0x8000000A -or $tag -eq 0x80000012) { $type = "DFS" }
            }
        }
    } catch {}
    $script:cacheReparse[$Chemin] = $type
    return $type
}

# ─── DECOUVERTE DES PARTAGES ────────────────────────────────
function Decouvrir-Partages {
    $partages = [System.Collections.Generic.List[object]]::new()

    try {
        $partagesSMB = @(Get-SmbShare -ErrorAction Stop |
            Where-Object { $_.Name -notmatch '^(ADMIN\$|[A-Z]\$|IPC\$|print\$)$' -and $_.Path })
        $nbExclus = 0
        foreach ($p in $partagesSMB) {
            if ($exclusionsPartages -contains $p.Name) {
                $nbExclus++
                Ajouter-Erreur -Dossier $p.Path -Operation "Partage exclu" -Message "Partage '$($p.Name)' exclu d'office (AUDIT_NTFS_EXCLURE / SYSVOL / NETLOGON)" -Categorie "Information"
                continue
            }
            $partages.Add([PSCustomObject]@{ Nom = $p.Name; Chemin = $p.Path; Type = "SMB" })
        }
        $suffixe = if ($nbExclus -gt 0) { " ($nbExclus exclu(s) : $($exclusionsPartages -join ', '))" } else { "" }
        Write-Host "  Partages SMB locaux : $(($partagesSMB.Count) - $nbExclus)$suffixe" -ForegroundColor Green
    } catch {
        Write-Warning "  Impossible de lister les partages SMB : $_"
    }

    if ($IsDomain) {
        try {
            Import-Module DFSN -ErrorAction Stop
            $dfsRoots = @(Get-DfsnRoot -Domain $DomainName -ErrorAction Stop)
            foreach ($dfs in $dfsRoots) {
                $partages.Add([PSCustomObject]@{ Nom = $dfs.Path; Chemin = $dfs.Path; Type = "DFS" })
            }
            Write-Host "  Namespaces DFS : $($dfsRoots.Count)" -ForegroundColor Green
        } catch {
            Write-Host "  DFS : module DFSN non disponible ou aucun namespace" -ForegroundColor DarkGray
        }
    }

    try {
        # NB : en session elevee (UAC), les lecteurs mappes de l'utilisateur standard ne sont pas visibles
        $lecteurs = @(Get-PSDrive -PSProvider FileSystem -ErrorAction Stop |
            Where-Object { $_.DisplayRoot -and $_.DisplayRoot -match '^\\\\' })
        foreach ($l in $lecteurs) {
            $partages.Add([PSCustomObject]@{ Nom = "$($l.Name): $($l.DisplayRoot)"; Chemin = $l.DisplayRoot; Type = "Lecteur-Reseau" })
        }
        Write-Host "  Lecteurs reseau mappes : $($lecteurs.Count)" -ForegroundColor Green
    } catch {
        Write-Warning "  Impossible de lister les lecteurs mappes : $_"
    }

    return ,$partages
}

# ─── SELECTION DES RACINES ──────────────────────────────────
function Ajouter-Racine {
    param($Liste, [string]$Nom, [string]$Chemin, [string]$Type)
    $Chemin = $Chemin.Trim().TrimEnd('\')
    if ($Chemin -match '^[A-Za-z]:$') { $Chemin += '\' }
    if (-not $Chemin) { return }
    if ($Liste | Where-Object { $_.Chemin -ieq $Chemin }) { return }
    if (Chemin-EstExclu $Chemin) {
        Write-Warning "  Chemin exclu d'office (SYSVOL / NETLOGON / AUDIT_NTFS_EXCLURE) : $Chemin"
        return
    }
    if (-not (Test-Path -LiteralPath $Chemin -ErrorAction SilentlyContinue)) {
        Write-Warning "  Chemin inaccessible : $Chemin"
        return
    }
    $Liste.Add([PSCustomObject]@{ Nom = $Nom; Chemin = $Chemin; Type = $Type; Profondeur = $profDefaut })
}

function Choisir-Racines {
    param($PartagesDisponibles)
    $racines = [System.Collections.Generic.List[object]]::new()

    if ($env:AUDIT_NTFS_PATHS) {
        foreach ($c in ($env:AUDIT_NTFS_PATHS -split ';' | Where-Object { $_.Trim() })) {
            Ajouter-Racine -Liste $racines -Nom (Split-Path $c.Trim() -Leaf) -Chemin $c -Type "Manuel"
        }
        Write-Host "  Chemins pre-definis (AUDIT_NTFS_PATHS) : $($racines.Count)" -ForegroundColor DarkGray
    }

    if (-not $modeInteractif) {
        if ($racines.Count -eq 0) {
            foreach ($p in ($PartagesDisponibles | Where-Object Type -eq 'SMB')) {
                Ajouter-Racine -Liste $racines -Nom $p.Nom -Chemin $p.Chemin -Type $p.Type
            }
        }
        return ,$racines
    }

    if ($PartagesDisponibles.Count -gt 0) {
        Write-Host ""
        Write-Host "  Partages detectes :" -ForegroundColor Cyan
        for ($i = 0; $i -lt $PartagesDisponibles.Count; $i++) {
            $p = $PartagesDisponibles[$i]
            Write-Host ("  [{0,2}] [{1}] {2} -> {3}" -f ($i + 1), $p.Type, $p.Nom, $p.Chemin) -ForegroundColor White
        }
        Write-Host "  [ T] Tous"  -ForegroundColor White
        Write-Host "  [ N] Aucun" -ForegroundColor White
        Write-Host ""
        Write-Host "  Partages a auditer (ex: 1,3,5 - T - N) : " -ForegroundColor Yellow -NoNewline
        $saisie = (Read-Host).Trim()

        if ($saisie -match '^[Tt]$') {
            foreach ($p in $PartagesDisponibles) { Ajouter-Racine -Liste $racines -Nom $p.Nom -Chemin $p.Chemin -Type $p.Type }
        } elseif ($saisie -notmatch '^[Nn]?$') {
            foreach ($num in ($saisie -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ -match '^\d+$' })) {
                $idx = [int]$num - 1
                if ($idx -ge 0 -and $idx -lt $PartagesDisponibles.Count) {
                    $p = $PartagesDisponibles[$idx]
                    Ajouter-Racine -Liste $racines -Nom $p.Nom -Chemin $p.Chemin -Type $p.Type
                }
            }
        }
    }

    Write-Host ""
    Write-Host "  Chemins supplementaires (separateur ';', vide pour ignorer) : " -ForegroundColor Yellow -NoNewline
    $extras = Read-Host
    if ($extras) {
        foreach ($c in ($extras -split ';' | Where-Object { $_.Trim() })) {
            Ajouter-Racine -Liste $racines -Nom (Split-Path $c.Trim() -Leaf) -Chemin $c -Type "Manuel"
        }
    }
    return ,$racines
}

# ─── PROFONDEUR INTERACTIVE ─────────────────────────────────
function Texte-Profondeur { param([int]$P) if ($P -lt 0) { "illimitee" } else { "$P" } }

# Compte les dossiers par niveau (sans lire les ACL) pour aider a choisir la profondeur
function Afficher-Volumetrie {
    param($Racines, [int]$NiveauMax = 6, [int]$Plafond = 20000)
    foreach ($r in $Racines) {
        Write-Host "    $($r.Chemin)" -ForegroundColor Cyan
        $niveau = @($r.Chemin); $total = 0
        for ($n = 1; $n -le $NiveauMax -and $niveau.Count -gt 0; $n++) {
            $suivant = [System.Collections.Generic.List[string]]::new()
            foreach ($d in $niveau) {
                try {
                    foreach ($s in [System.IO.Directory]::GetDirectories((Chemin-Api $d))) {
                        try { if ([System.IO.File]::GetAttributes($s) -band [System.IO.FileAttributes]::ReparsePoint) { continue } } catch {}
                        $suivant.Add((Chemin-Affichage $s))
                    }
                } catch {}
                if ($suivant.Count + $total -gt $Plafond) { break }
            }
            $total += $suivant.Count
            Write-Host ("      niveau {0} : {1,7} dossier(s)   (cumul {2})" -f $n, $suivant.Count, $total) -ForegroundColor White
            if ($total -gt $Plafond) { Write-Host "      ... plafond d'apercu atteint ($Plafond)" -ForegroundColor DarkGray; break }
            $niveau = $suivant
        }
    }
}

function Lire-Profondeur {
    param([int]$Defaut, [string]$Libelle, $RacinesApercu)
    while ($true) {
        Write-Host "  $Libelle (0 = racine seule, * = illimitee, ? = apercu volumetrie) [Entree = $(Texte-Profondeur $Defaut)] : " -ForegroundColor Yellow -NoNewline
        $s = (Read-Host).Trim()
        if (-not $s)          { return $Defaut }
        if ($s -eq '*')       { return -1 }
        if ($s -match '^\d+$') { return [int]$s }
        if ($s -eq '?')       { Afficher-Volumetrie -Racines $RacinesApercu; continue }
        Write-Warning "  Valeur invalide."
    }
}

function Choisir-Profondeurs {
    param($Racines)
    if (-not $modeInteractif) { return }
    Write-Host ""
    Write-Host "=== PROFONDEUR D'EXPLORATION ===" -ForegroundColor Cyan
    $global = Lire-Profondeur -Defaut $profDefaut -Libelle "Profondeur par defaut" -RacinesApercu $Racines
    foreach ($r in $Racines) { $r.Profondeur = $global }

    if ($Racines.Count -gt 1) {
        Write-Host "  Personnaliser la profondeur par racine ? [O/N] : " -ForegroundColor Yellow -NoNewline
        if ((Read-Host) -match '^[OoYy]') {
            foreach ($r in $Racines) {
                $r.Profondeur = Lire-Profondeur -Defaut $global -Libelle "  $($r.Chemin)" -RacinesApercu @($r)
            }
        }
    }
}

# ─── EXPLORATION + LECTURE DES ACL ──────────────────────────
$script:idNoeud   = 0
$script:noeuds    = [System.Collections.Generic.List[object]]::new()
$script:lignesCsv = [System.Collections.Generic.List[object]]::new()
$script:erreurs   = [System.Collections.Generic.List[object]]::new()
$script:ciblesDfsVisitees = [System.Collections.Generic.HashSet[string]]::new()
$script:mesures   = @{}   # chemin racine -> resultat de Mesurer-Racine

function Ajouter-Erreur {
    param([string]$Dossier, [string]$Operation, [string]$Message, [string]$Categorie = "Erreur")
    # Categorie : "Erreur" (echec reel : ACL illisible, acces refuse, garde-fou)
    #             "Information" (skip volontaire : jonction, partage/chemin exclu, profondeur atteinte)
    $script:erreurs.Add([PSCustomObject][ordered]@{
        Serveur = $Serveur; Categorie = $Categorie; Dossier = $Dossier; Operation = $Operation; Message = $Message
    })
}

function Lire-AclDossier {
    param([string]$Chemin)
    $acl = Get-Acl -LiteralPath (Chemin-Api $Chemin) -ErrorAction Stop
    $regles = $acl.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier])
    $proprietaire = $null
    try {
        $sidProp = $acl.GetOwner([System.Security.Principal.SecurityIdentifier])
        if ($sidProp) { $proprietaire = Resoudre-Sid $sidProp.Value; if (-not $proprietaire) { $proprietaire = $sidProp.Value } }
    } catch {}
    [PSCustomObject]@{
        Regles       = $regles
        Proteges     = $acl.AreAccessRulesProtected
        Proprietaire = $proprietaire
    }
}

function Auditer-Racine {
    param($Racine)

    $profMax  = [int]$Racine.Profondeur
    $nbVisite = 0
    $file     = [System.Collections.Generic.Queue[object]]::new()
    $file.Enqueue([PSCustomObject]@{ Chemin = $Racine.Chemin; Profondeur = 0; Parent = -1 })

    while ($file.Count -gt 0) {
        $item = $file.Dequeue()
        $nbVisite++
        if ($nbVisite % 50 -eq 0) {
            Write-Progress -Activity "Audit NTFS : $($Racine.Chemin)" -Status "$nbVisite dossier(s) - $($item.Chemin)"
        }

        $script:idNoeud++
        $id = $script:idNoeud
        $relatif = $item.Chemin.Substring([Math]::Min($Racine.Chemin.TrimEnd('\').Length, $item.Chemin.Length)).TrimStart('\')
        $nom = if ($item.Profondeur -eq 0) { $Racine.Chemin } else { Split-Path $item.Chemin -Leaf }

        $noeud = [PSCustomObject]@{
            Id = $id; Parent = $item.Parent; Nom = $nom; Chemin = $item.Chemin; Profondeur = $item.Profondeur
            Racine = $Racine; HeritageCoupe = $false; Proprietaire = ""; Erreur = ""
            NonExplore = $false; Aces = [System.Collections.Generic.List[object]]::new(); Partage = $null
        }

        # Taille du dossier (empreinte recursive), issue du balayage de mesure.
        # Disponible jusqu'au niveau $profTaille ; vide au-dela (non mesure a ce niveau de detail).
        $tailleOctets = ""
        $tailleLisible = ""
        $mesR = $script:mesures[$Racine.Chemin]
        if ($mesR -and $mesR.TailleParChemin.ContainsKey($item.Chemin)) {
            $tailleOctets  = [long]$mesR.TailleParChemin[$item.Chemin]
            $tailleLisible = Format-Taille $tailleOctets
        }

        # 1. ACL du dossier
        try {
            $info = Lire-AclDossier -Chemin $item.Chemin
            $noeud.HeritageCoupe = [bool]$info.Proteges
            $noeud.Proprietaire  = [string]$info.Proprietaire

            foreach ($r in $info.Regles) {
                $sid       = $r.IdentityReference.Value
                $identite  = Resoudre-Sid $sid
                $orphelin  = -not $identite
                if ($orphelin) { $identite = $sid }
                $refus     = ($r.AccessControlType -eq [System.Security.AccessControl.AccessControlType]::Deny)
                $droits    = Convertir-Droits $r.FileSystemRights
                $ecriture  = Droits-PermettentEcriture $r.FileSystemRights

                $alertes = @()
                if ($refus)    { $alertes += "ACE de refus" }
                if ($orphelin) { $alertes += "SID orphelin" }
                if (($sidsLarges.ContainsKey($sid) -or $sid -match $regexSidsLargesDomaine) -and $ecriture -and -not $refus) {
                    $alertes += "Groupe large avec droits d'ecriture"
                }
                if (-not $r.IsInherited -and -not $refus -and $droits -eq "Controle total" -and
                    $sidsAdminAttendus -notcontains $sid -and $sid -notmatch $regexSidsAdminDomaine) {
                    $alertes += "Controle total explicite"
                }
                $alerte = $alertes -join " | "

                $noeud.Aces.Add([PSCustomObject]@{
                    Identite = $identite; Refus = $refus; Droits = $droits; Herite = [bool]$r.IsInherited
                    Portee = (Convertir-Portee $r.InheritanceFlags $r.PropagationFlags); Alerte = $alerte
                })

                $script:lignesCsv.Add([PSCustomObject][ordered]@{
                    Serveur           = $Serveur
                    Partage           = $Racine.Nom
                    TypePartage       = $Racine.Type
                    Racine            = $Racine.Chemin
                    Dossier           = $item.Chemin
                    CheminRelatif     = $relatif
                    Profondeur        = $item.Profondeur
                    TailleOctets      = $tailleOctets
                    Taille            = $tailleLisible
                    HeritageDesactive = if ($noeud.HeritageCoupe) { "Oui" } else { "Non" }
                    Proprietaire      = $noeud.Proprietaire
                    Identite          = $identite
                    SID               = $sid
                    TypeAcces         = if ($refus) { "Refuser" } else { "Autoriser" }
                    Droits            = $droits
                    DroitsBruts       = [string]$r.FileSystemRights
                    Herite            = if ($r.IsInherited) { "Oui" } else { "Non" }
                    AppliqueA         = Convertir-Portee $r.InheritanceFlags $r.PropagationFlags
                    Alerte            = $alerte
                })
            }
        } catch {
            $msg = $_.Exception.Message
            $noeud.Erreur = $msg
            Ajouter-Erreur -Dossier $item.Chemin -Operation "Lecture ACL" -Message $msg
            $script:lignesCsv.Add([PSCustomObject][ordered]@{
                Serveur = $Serveur; Partage = $Racine.Nom; TypePartage = $Racine.Type; Racine = $Racine.Chemin
                Dossier = $item.Chemin; CheminRelatif = $relatif; Profondeur = $item.Profondeur
                TailleOctets = $tailleOctets; Taille = $tailleLisible
                HeritageDesactive = ""; Proprietaire = ""; Identite = ""; SID = ""; TypeAcces = ""
                Droits = ""; DroitsBruts = ""; Herite = ""; AppliqueA = ""; Alerte = "ACL illisible : $msg"
            })
        }
        $script:noeuds.Add($noeud)

        # 2. Sous-dossiers
        $limiteAtteinte = ($profMax -ge 0 -and $item.Profondeur -ge $profMax)
        try {
            if ($limiteAtteinte) {
                # On signale seulement s'il existe des sous-dossiers non explores
                $enum = [System.IO.Directory]::EnumerateDirectories((Chemin-Api $item.Chemin)).GetEnumerator()
                $noeud.NonExplore = $enum.MoveNext()
                continue
            }
            $enfants = [System.IO.Directory]::GetDirectories((Chemin-Api $item.Chemin)) | Sort-Object
        } catch {
            Ajouter-Erreur -Dossier $item.Chemin -Operation "Liste sous-dossiers" -Message $_.Exception.Message
            continue
        }

        foreach ($e in $enfants) {
            $cheminEnfant = Chemin-Affichage $e

            # Chemin exclu par nom (SYSVOL, NETLOGON, AUDIT_NTFS_EXCLURE) : jamais parcouru,
            # meme atteint via une jonction ou un lien DFS.
            if (Chemin-EstExclu $cheminEnfant) {
                Ajouter-Erreur -Dossier $cheminEnfant -Operation "Chemin exclu" -Message "Exclu d'office (SYSVOL / NETLOGON / AUDIT_NTFS_EXCLURE)" -Categorie "Information"
                continue
            }

            # Points d'analyse : distinguer un lien DFS (a suivre) d'une jonction locale (a ignorer).
            try {
                $attr = [System.IO.File]::GetAttributes($e)
                if ($attr -band [System.IO.FileAttributes]::ReparsePoint) {
                    $typeReparse = Get-TypeReparse $cheminEnfant
                    if ($typeReparse -eq "DFS") {
                        # Lien DFS : la cible reelle (autre serveur) est resolue en suivant le chemin.
                        # Protection anti-boucle : on ne suit un lien que si sa cible resolue n'a pas
                        # deja ete visitee dans cette racine.
                        $cible = $null
                        try { $cible = (Get-Item -LiteralPath $cheminEnfant -Force -ErrorAction Stop).Target } catch {}
                        if (-not $cible) { $cible = $cheminEnfant }
                        $cle = ($cible -join ';').ToLowerInvariant().TrimEnd('\')
                        if ($script:ciblesDfsVisitees.Contains($cle)) {
                            Ajouter-Erreur -Dossier $cheminEnfant -Operation "Lien DFS" -Message "Cible deja auditee ($cible) - evite la boucle" -Categorie "Information"
                            continue
                        }
                        $null = $script:ciblesDfsVisitees.Add($cle)
                        Ajouter-Erreur -Dossier $cheminEnfant -Operation "Lien DFS suivi" -Message "Redirige vers $cible" -Categorie "Information"
                        # On continue : le dossier est mis en file normalement ci-dessous et sera parcouru.
                    } else {
                        Ajouter-Erreur -Dossier $cheminEnfant -Operation "Jonction / lien" -Message "Point d'analyse local non parcouru (evite les boucles et doublons)" -Categorie "Information"
                        continue
                    }
                }
            } catch {}

            if (($nbVisite + $file.Count) -ge $maxDossiers) {
                Ajouter-Erreur -Dossier $item.Chemin -Operation "Garde-fou" -Message "Limite de $maxDossiers dossiers atteinte - exploration arretee" -Categorie "Information"
                Write-Warning "  Limite de $maxDossiers dossiers atteinte sur $($Racine.Chemin) (AUDIT_NTFS_MAX_DOSSIERS)"
                $file.Clear()
                break
            }
            $file.Enqueue([PSCustomObject]@{ Chemin = $cheminEnfant; Profondeur = $item.Profondeur + 1; Parent = $id })
        }
    }
    Write-Progress -Activity "Audit NTFS : $($Racine.Chemin)" -Completed
    return $nbVisite
}

# ─── DROITS DE PARTAGE SMB ──────────────────────────────────
function Auditer-DroitsPartage {
    param($Racines)
    $lignes = [System.Collections.Generic.List[object]]::new()
    foreach ($r in ($Racines | Where-Object Type -eq 'SMB')) {
        try {
            $acces = @(Get-SmbShareAccess -Name $r.Nom -ErrorAction Stop)
            $resume = [System.Collections.Generic.List[object]]::new()
            foreach ($a in $acces) {
                $alerte = ""
                if ($a.AccountName -match '^(Everyone|Tout le monde)$' -and "$($a.AccessRight)" -match 'Full|Change' -and "$($a.AccessControlType)" -eq 'Allow') {
                    $alerte = "Tout le monde en $($a.AccessRight) sur le partage"
                }
                $lignes.Add([PSCustomObject][ordered]@{
                    Serveur = $Serveur; Partage = $r.Nom; CheminLocal = $r.Chemin; Identite = $a.AccountName
                    TypeAcces = if ("$($a.AccessControlType)" -eq 'Deny') { "Refuser" } else { "Autoriser" }
                    DroitsPartage = "$($a.AccessRight)"; Alerte = $alerte
                })
                $resume.Add([PSCustomObject]@{ Identite = $a.AccountName; Type = "$($a.AccessControlType)"; Droit = "$($a.AccessRight)" })
            }
            $r | Add-Member -NotePropertyName DroitsPartage -NotePropertyValue $resume -Force
        } catch {
            Ajouter-Erreur -Dossier $r.Chemin -Operation "Droits de partage" -Message $_.Exception.Message
        }
    }
    return ,$lignes
}

# ─── SCHEMA TEXTE ───────────────────────────────────────────
# ─── TAILLE DISQUE : formatage lisible ──────────────────────
function Format-Taille {
    param([long]$Octets)
    if ($Octets -ge 1099511627776) { return ("{0:N2} To" -f ($Octets / 1099511627776)) }
    if ($Octets -ge 1073741824)    { return ("{0:N2} Go" -f ($Octets / 1073741824)) }
    if ($Octets -ge 1048576)       { return ("{0:N0} Mo" -f ($Octets / 1048576)) }
    if ($Octets -gt 0)             { return "<1 Mo" }
    return "0"
}

# ─── BALAYAGE COMPLET D'UNE RACINE (sans ACL) ───────────────
# Un seul parcours, en lecture seule, sans plafond (le comptage de dossiers n'est
# qu'une enumeration). Retourne :
#   DossiersParNiveau : int[] - nb de dossiers EXISTANTS par niveau (complet, tous niveaux)
#   OctetsParNiveau   : long[] - poids des fichiers par niveau (index 0..profTaille ; le dernier
#                       cumule le niveau profTaille et tout ce qui est en dessous)
#   TailleParChemin   : hashtable chemin -> taille recursive (octets), pour les dossiers
#                       jusqu'au niveau profTaille (= empreinte disque du dossier et de tout son contenu)
#   NiveauMax, TailleTotale
function Mesurer-Racine {
    param([string]$Chemin, [int]$ProfTaille)

    $dossiersParNiveau = [System.Collections.Generic.List[int]]::new()
    $octetsParNiveau   = [System.Collections.Generic.List[long]]::new()
    for ($i = 0; $i -le $ProfTaille; $i++) { $octetsParNiveau.Add([long]0) }
    $tailleParChemin = @{}
    $visite          = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $niveauMax = 0
    $total     = [long]0

    # Pile DFS. Chaque entree porte sa chaine d'ancetres (chemins) de niveau <= ProfTaille, a crediter.
    $pile = [System.Collections.Generic.Stack[object]]::new()
    $pile.Push([PSCustomObject]@{ Chemin = $Chemin; Niveau = 0; Ancetres = @() })

    while ($pile.Count -gt 0) {
        $cur = $pile.Pop()
        $cle = $cur.Chemin.TrimEnd('\').ToLowerInvariant()
        if (-not $visite.Add($cle)) { continue }   # anti-boucle (jonctions / DFS circulaires)

        # Comptage du dossier dans son niveau
        while ($dossiersParNiveau.Count -le $cur.Niveau) { $dossiersParNiveau.Add(0) }
        $dossiersParNiveau[$cur.Niveau]++
        if ($cur.Niveau -gt $niveauMax) { $niveauMax = $cur.Niveau }

        # Ancetres a crediter pour la taille recursive (ce dossier inclus s'il est <= ProfTaille)
        $aCrediter = @($cur.Ancetres)
        if ($cur.Niveau -le $ProfTaille) {
            if (-not $tailleParChemin.ContainsKey($cur.Chemin)) { $tailleParChemin[$cur.Chemin] = [long]0 }
            $aCrediter += $cur.Chemin
        }

        # Poids des fichiers directement dans ce dossier
        $octetsDirects = [long]0
        try {
            $di = [System.IO.DirectoryInfo]::new((Chemin-Api $cur.Chemin))
            foreach ($f in $di.EnumerateFiles()) { $octetsDirects += [long]$f.Length }
        } catch {}

        if ($octetsDirects -gt 0) {
            $total += $octetsDirects
            $idx = [Math]::Min($cur.Niveau, $ProfTaille)
            $octetsParNiveau[$idx] += $octetsDirects
            foreach ($a in $aCrediter) { $tailleParChemin[$a] += $octetsDirects }
        }

        # Sous-dossiers
        $chaineEnfant = @($cur.Ancetres)
        if ($cur.Niveau -lt $ProfTaille) { $chaineEnfant += $cur.Chemin }  # on ne credite que <= ProfTaille
        try {
            $di = [System.IO.DirectoryInfo]::new((Chemin-Api $cur.Chemin))
            foreach ($sd in $di.EnumerateDirectories()) {
                $cheminEnfant = Chemin-Affichage $sd.FullName
                if (Chemin-EstExclu $cheminEnfant) { continue }
                if ($sd.Attributes -band [System.IO.FileAttributes]::ReparsePoint) {
                    # Jonction locale : on ne suit pas (boucles/doublons). DFS : on suit (donnees reelles).
                    if ((Get-TypeReparse $cheminEnfant) -ne "DFS") { continue }
                }
                $pile.Push([PSCustomObject]@{ Chemin = $cheminEnfant; Niveau = $cur.Niveau + 1; Ancetres = $chaineEnfant })
            }
        } catch {}
    }

    return [PSCustomObject]@{
        DossiersParNiveau = $dossiersParNiveau.ToArray()
        OctetsParNiveau   = $octetsParNiveau.ToArray()
        TailleParChemin   = $tailleParChemin
        NiveauMax         = $niveauMax
        TailleTotale      = $total
        ProfTaille        = $ProfTaille
    }
}

# ─── VOLUMETRIE (niveaux et dossiers par niveau, sur l'audit reel) ──
# Retourne une table ordonnee : niveau -> nb de dossiers. Niveau 0 = la racine elle-meme,
# niveau 1 = ses sous-dossiers directs, etc. (coherent avec l'apercu "?").
function Calculer-Volumetrie {
    param($Noeuds)
    # Comptage par niveau dans un tableau indexe par la profondeur (evite les pieges
    # d'indexation entiere sur une hashtable ordonnee).
    $max = 0
    foreach ($n in $Noeuds) { $p = [int]$n.Profondeur; if ($p -gt $max) { $max = $p } }
    $compte = New-Object 'int[]' ($max + 1)
    foreach ($n in $Noeuds) { $compte[[int]$n.Profondeur]++ }
    return [PSCustomObject]@{
        ParNiveau = $compte          # index 0 = racine, 1 = niveau 1, ...
        NiveauMax = $max             # profondeur max atteinte (nb de niveaux de sous-dossiers)
        Total     = @($Noeuds).Count
    }
}

function Generer-ArborescenceTxt {
    param($Racines, [string]$Fichier)

    $enfants = @{}
    foreach ($n in $script:noeuds) {
        if (-not $enfants.ContainsKey($n.Parent)) { $enfants[$n.Parent] = [System.Collections.Generic.List[object]]::new() }
        $enfants[$n.Parent].Add($n)
    }
    $lignes = [System.Collections.Generic.List[string]]::new()

    # Taille lisible d'un noeud (depuis le balayage de mesure), ou "" si non mesuree
    function Taille-Noeud {
        param($N)
        $mes = $script:mesures[$N.Racine.Chemin]
        if ($mes -and $mes.TailleParChemin.ContainsKey($N.Chemin)) {
            return Format-Taille ([long]$mes.TailleParChemin[$N.Chemin])
        }
        return ""
    }

    function Resume-Noeud {
        param($N)
        $tags = @()
        $tl = Taille-Noeud $N
        if ($tl -and $tl -ne "0")                      { $tags += "[$tl]" }
        if ($N.HeritageCoupe)                          { $tags += "[HERITAGE COUPE]" }
        if ($N.Aces | Where-Object Refus)              { $tags += "[REFUS]" }
        $nbAl = @($N.Aces | Where-Object { $_.Alerte }).Count
        if ($nbAl -gt 0)                               { $tags += "[!$nbAl]" }
        if ($N.Erreur)                                 { $tags += "[ACL ILLISIBLE]" }
        if ($N.NonExplore)                             { $tags += "[+ non explore]" }
        $expl = @($N.Aces | Where-Object { -not $_.Herite } | ForEach-Object {
            $t = if ($_.Refus) { "REFUS " } else { "" }
            "$($_.Identite) ($t$($_.Droits))"
        })
        $txt = ($tags -join " ")
        if ($expl.Count -gt 0) { $txt += "  => " + ($expl -join " ; ") }
        return $txt.Trim()
    }

    function Ecrire-Noeud {
        param($N, [string]$Prefixe, [bool]$Dernier)
        $connecteur = if ($Dernier) { "+-- " } else { "|-- " }
        $suite      = if ($Dernier) { "    " } else { "|   " }
        $resume     = Resume-Noeud $N
        $lignes.Add("$Prefixe$connecteur$($N.Nom)" + $(if ($resume) { "  $resume" } else { "" }))
        if ($enfants.ContainsKey($N.Id)) {
            $liste = $enfants[$N.Id]
            for ($i = 0; $i -lt $liste.Count; $i++) {
                Ecrire-Noeud -N $liste[$i] -Prefixe ($Prefixe + $suite) -Dernier ($i -eq $liste.Count - 1)
            }
        }
    }

    $lignes.Add("Arborescence des partages - $Serveur - $(Get-Date -Format 'dd/MM/yyyy HH:mm')")
    $lignes.Add("Legende : [HERITAGE COUPE] heritage desactive | [REFUS] ACE Deny | [!n] n alerte(s) | [+ non explore] sous-dossiers au-dela de la profondeur")
    $lignes.Add("          => droits EXPLICITES uniquement (les droits herites sont dans le CSV)")
    $lignes.Add("")

    $numRacine = 0
    foreach ($racineNoeud in ($enfants[-1] | Where-Object { $_ })) {
        $r = $racineNoeud.Racine
        $numRacine++
        $lignes.Add("")
        $lignes.Add("#" * 100)
        $lignes.Add("##  PARTAGE $numRacine : $($r.Nom) [$($r.Type)]")
        $lignes.Add("##  $($r.Chemin)")
        $lignes.Add("##  Profondeur demandee : $(Texte-Profondeur $r.Profondeur)")
        $lignes.Add("#" * 100)

        # Dossiers audites (perimetre reel) de cette racine
        $noeudsRacine = @($script:noeuds | Where-Object { $_.Racine -eq $r })
        $vol = Calculer-Volumetrie -Noeuds $noeudsRacine
        $mes = $script:mesures[$r.Chemin]
        $nbExist = if ($mes) { ($mes.DossiersParNiveau | Measure-Object -Sum).Sum } else { "?" }
        $nivExist = if ($mes) { $mes.NiveauMax } else { "?" }

        $lignes.Add("  Dossiers : $($vol.Total) audite(s) / $nbExist existant(s)   |   Profondeur : $($vol.NiveauMax) audite / $nivExist existant   |   Taille disque : $(if ($mes) { Format-Taille $mes.TailleTotale } else { '?' })")
        $lignes.Add("  Repartition par niveau (existants / audites / taille jusqu'au niveau $profTaille) :")
        $nivMaxAff = if ($mes) { $mes.NiveauMax } else { $vol.ParNiveau.Count - 1 }
        for ($k = 0; $k -le $nivMaxAff; $k++) {
            $libelle  = if ($k -eq 0) { "racine" } else { "niveau $k" }
            $existant = if ($mes -and $k -lt $mes.DossiersParNiveau.Count) { $mes.DossiersParNiveau[$k] } else { 0 }
            $audite   = if ($k -lt $vol.ParNiveau.Count) { $vol.ParNiveau[$k] } else { 0 }
            # Taille : detail jusqu'a profTaille ; le dernier index cumule "niveau profTaille et +"
            $txtTaille = ""
            if ($mes) {
                if ($k -lt $profTaille) { $txtTaille = Format-Taille $mes.OctetsParNiveau[$k] }
                elseif ($k -eq $profTaille) {
                    $txtTaille = Format-Taille $mes.OctetsParNiveau[$profTaille]
                    if ($mes.NiveauMax -gt $profTaille) { $libelle = "niveau $k+" }
                } else { $txtTaille = "(inclus dans niveau $profTaille+)" }
            }
            $lignes.Add(("    {0,-11} : {1,7} existant(s) / {2,7} audite(s)   {3}" -f $libelle, $existant, $audite, $txtTaille))
        }

        if ($r.PSObject.Properties['DroitsPartage'] -and $r.DroitsPartage) {
            $lignes.Add("  Droits de partage : " + (($r.DroitsPartage | ForEach-Object { "$($_.Identite) ($($_.Type) $($_.Droit))" }) -join " ; "))
        }
        $lignes.Add("  Proprietaire : $($racineNoeud.Proprietaire)")
        $lignes.Add("  ACL racine :")
        foreach ($a in $racineNoeud.Aces) {
            $t = if ($a.Refus) { "REFUS    " } else { "Autoriser" }
            $h = if ($a.Herite) { "herite " } else { "explicite" }
            $lignes.Add(("    {0}  {1,-40} {2,-30} {3}  {4}" -f $t, $a.Identite, $a.Droits, $h, $a.Portee) + $(if ($a.Alerte) { "  !! $($a.Alerte)" } else { "" }))
        }
        $lignes.Add("")
        $lignes.Add("  --- Arborescence (taille entre crochets) ".PadRight(100, '-'))
        $lignes.Add($racineNoeud.Nom + $(if (($rs = Resume-Noeud $racineNoeud)) { "  $rs" } else { "" }))
        if ($enfants.ContainsKey($racineNoeud.Id)) {
            $liste = $enfants[$racineNoeud.Id]
            for ($i = 0; $i -lt $liste.Count; $i++) {
                Ecrire-Noeud -N $liste[$i] -Prefixe "" -Dernier ($i -eq $liste.Count - 1)
            }
        }
        $lignes.Add("")
        $lignes.Add(("~" * 100))
        $lignes.Add("")
    }

    # ─── Recap global (toutes racines confondues) ───
    $volGlobal = Calculer-Volumetrie -Noeuds $script:noeuds
    # Agregation des mesures completes de toutes les racines
    $gExist = [System.Collections.Generic.List[long]]::new()
    $gOctets = [System.Collections.Generic.List[long]]::new()
    for ($i = 0; $i -le $profTaille; $i++) { $gOctets.Add([long]0) }
    $gTotalOctets = [long]0; $gNivMax = 0
    foreach ($r in $Racines) {
        $mes = $script:mesures[$r.Chemin]; if (-not $mes) { continue }
        for ($k = 0; $k -lt $mes.DossiersParNiveau.Count; $k++) {
            while ($gExist.Count -le $k) { $gExist.Add([long]0) }
            $gExist[$k] += $mes.DossiersParNiveau[$k]
        }
        for ($k = 0; $k -le $profTaille; $k++) { $gOctets[$k] += $mes.OctetsParNiveau[$k] }
        $gTotalOctets += $mes.TailleTotale
        if ($mes.NiveauMax -gt $gNivMax) { $gNivMax = $mes.NiveauMax }
    }
    $gTotalExist = ($gExist | Measure-Object -Sum).Sum

    $lignes.Add("=" * 100)
    $lignes.Add("RECAPITULATIF GLOBAL")
    $lignes.Add("  Racines auditees            : $(@($Racines).Count)")
    $lignes.Add("  Dossiers audites / existants : $($volGlobal.Total) / $gTotalExist")
    $lignes.Add("  Profondeur max (audit/reel) : $($volGlobal.NiveauMax) / $gNivMax niveau(x)")
    $lignes.Add("  Taille disque totale        : $(Format-Taille $gTotalOctets)")
    $lignes.Add("  Repartition par niveau (existants / audites / taille jusqu'au niveau $profTaille) :")
    for ($k = 0; $k -le $gNivMax; $k++) {
        $libelle  = if ($k -eq 0) { "racines" } else { "niveau $k" }
        $existant = if ($k -lt $gExist.Count) { $gExist[$k] } else { 0 }
        $audite   = if ($k -lt $volGlobal.ParNiveau.Count) { $volGlobal.ParNiveau[$k] } else { 0 }
        $txtTaille = ""
        if ($k -lt $profTaille) { $txtTaille = Format-Taille $gOctets[$k] }
        elseif ($k -eq $profTaille) {
            $txtTaille = Format-Taille $gOctets[$profTaille]
            if ($gNivMax -gt $profTaille) { $libelle = "niveau $k+" }
        } else { $txtTaille = "(inclus dans niveau $profTaille+)" }
        $lignes.Add(("    {0,-11} : {1,7} existant(s) / {2,7} audite(s)   {3}" -f $libelle, $existant, $audite, $txtTaille))
    }
    $lignes.Add("=" * 100)

    $lignes | Out-File -FilePath $Fichier -Encoding UTF8
}

# ─── SCHEMA HTML INTERACTIF ─────────────────────────────────
function Json-Chaine {
    param([string]$S)
    if ($null -eq $S) { return '""' }
    # Remplacements vectorises (un switch caractere par caractere est trop lent en PS 5.1)
    $t = $S.Replace('\', '\\').Replace('"', '\"')
    $t = [regex]::Replace($t, '[\x00-\x1f<>&\u2028\u2029]', { param($m) '\u{0:x4}' -f [int][char]$m.Value })
    return '"' + $t + '"'
}

function Generer-ArborescenceHtml {
    param($Racines, [string]$Fichier)

    # Serialisation JSON manuelle (ConvertTo-Json est tres lent en PS 5.1 sur de gros volumes)
    $sb = [System.Text.StringBuilder]::new()
    [void]$sb.Append('{"s":' + (Json-Chaine $Serveur) + ',"t":' + (Json-Chaine (Get-Date -Format 'dd/MM/yyyy HH:mm')))
    [void]$sb.Append(',"sd":' + $profTaille + ',"n":[')
    $premier = $true
    foreach ($n in $script:noeuds) {
        $f = 0
        if ($n.HeritageCoupe) { $f = $f -bor 1 }
        if ($n.Aces | Where-Object Refus) { $f = $f -bor 2 }
        if ($n.Aces | Where-Object { $_.Alerte }) { $f = $f -bor 4 }
        if ($n.Aces | Where-Object { -not $_.Herite }) { $f = $f -bor 8 }
        if ($n.NonExplore) { $f = $f -bor 16 }
        if ($n.Erreur) { $f = $f -bor 32 }

        if (-not $premier) { [void]$sb.Append(',') }
        $premier = $false
        [void]$sb.Append('{"i":' + $n.Id + ',"p":' + $n.Parent + ',"d":' + $n.Profondeur + ',"f":' + $f)
        [void]$sb.Append(',"n":' + (Json-Chaine $n.Nom) + ',"c":' + (Json-Chaine $n.Chemin))
        [void]$sb.Append(',"o":' + (Json-Chaine $n.Proprietaire) + ',"e":' + (Json-Chaine $n.Erreur))

        # Taille recursive du dossier (octets), si mesuree (niveau <= profTaille)
        $mesN = $script:mesures[$n.Racine.Chemin]
        if ($mesN -and $mesN.TailleParChemin.ContainsKey($n.Chemin)) {
            [void]$sb.Append(',"z":' + [long]$mesN.TailleParChemin[$n.Chemin])
        }

        if ($n.Parent -eq -1) {
            $r = $n.Racine
            [void]$sb.Append(',"r":' + (Json-Chaine "$($r.Nom) [$($r.Type)]") + ',"pm":' + (Json-Chaine (Texte-Profondeur $r.Profondeur)))
            # Tableaux complets de la racine : dossiers existants par niveau + octets par niveau + total
            $mes = $script:mesures[$r.Chemin]
            if ($mes) {
                [void]$sb.Append(',"fc":[' + (($mes.DossiersParNiveau | ForEach-Object { [string]$_ }) -join ',') + ']')
                [void]$sb.Append(',"bz":[' + (($mes.OctetsParNiveau | ForEach-Object { [string][long]$_ }) -join ',') + ']')
                [void]$sb.Append(',"tt":' + [long]$mes.TailleTotale)
            }
            [void]$sb.Append(',"sp":[')
            if ($r.PSObject.Properties['DroitsPartage'] -and $r.DroitsPartage) {
                [void]$sb.Append((($r.DroitsPartage | ForEach-Object {
                    '[' + (Json-Chaine $_.Identite) + ',' + (Json-Chaine $_.Type) + ',' + (Json-Chaine $_.Droit) + ']'
                }) -join ','))
            }
            [void]$sb.Append(']')
        }
        [void]$sb.Append(',"a":[')
        [void]$sb.Append((($n.Aces | ForEach-Object {
            '[' + (Json-Chaine $_.Identite) + ',' + $(if ($_.Refus) { '1' } else { '0' }) + ',' + (Json-Chaine $_.Droits) + ',' +
            $(if ($_.Herite) { '1' } else { '0' }) + ',' + (Json-Chaine $_.Portee) + ',' + (Json-Chaine $_.Alerte) + ']'
        }) -join ','))
        [void]$sb.Append(']}')
    }
    [void]$sb.Append(']}')

    $html = $script:modeleHtml.Replace('/*__DATA__*/null', $sb.ToString())
    [System.IO.File]::WriteAllText($Fichier, $html, [System.Text.UTF8Encoding]::new($false))
}

# Modele HTML autonome (aucune ressource externe : utilisable hors ligne chez le client)
$script:modeleHtml = @'
<!DOCTYPE html>
<html lang="fr"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Arborescence NTFS</title>
<style>
:root{--bg:#f6f7f9;--pan:#fff;--tx:#1d2330;--mu:#6b7385;--bd:#dde1e8;--sel:#e3ecff;--hov:#f0f3f8;
--h:#b86e00;--hb:#fff2dc;--r:#c62828;--rb:#fde7e7;--a:#d84315;--ab:#ffece3;--e:#1565c0;--eb:#e4efff;--g:#6b7385;--gb:#eef0f4}
@media (prefers-color-scheme:dark){:root{--bg:#14171d;--pan:#1c2028;--tx:#e6e9ef;--mu:#9aa3b5;--bd:#2d333f;--sel:#26334d;--hov:#232833;
--h:#ffb74d;--hb:#3a2e1a;--r:#ef9a9a;--rb:#3d2020;--a:#ffab91;--ab:#3d261d;--e:#90caf9;--eb:#1d2c40;--g:#9aa3b5;--gb:#272c36}}
*{box-sizing:border-box}html,body{height:100%;margin:0}
body{font:14px/1.45 "Segoe UI",system-ui,sans-serif;background:var(--bg);color:var(--tx);display:flex;flex-direction:column}
header{padding:12px 18px;border-bottom:1px solid var(--bd);background:var(--pan)}
header h1{font-size:17px;margin:0 0 2px}header .m{color:var(--mu);font-size:12.5px}
.bar{display:flex;flex-wrap:wrap;gap:14px;align-items:center;padding:10px 18px;border-bottom:1px solid var(--bd);background:var(--pan)}
.bar label{display:flex;align-items:center;gap:6px;color:var(--mu);font-size:13px}
.bar input[type=search]{padding:6px 9px;border:1px solid var(--bd);border-radius:6px;min-width:240px;background:var(--bg);color:var(--tx)}
.bar input[type=range]{width:150px}.bar b{color:var(--tx);min-width:52px;display:inline-block}
.bar button{padding:5px 10px;border:1px solid var(--bd);border-radius:6px;background:var(--bg);color:var(--tx);cursor:pointer}
main{flex:1;display:flex;min-height:0}
#tree{flex:1 1 45%;overflow:auto;padding:10px 6px 30px;background:var(--pan);border-right:1px solid var(--bd)}
#det{flex:1 1 55%;overflow:auto;padding:16px 20px}
ul{list-style:none;margin:0;padding-left:18px}#tree>ul{padding-left:4px}
.row{display:flex;align-items:center;gap:6px;padding:2px 6px;border-radius:5px;cursor:pointer;white-space:nowrap}
.row:hover{background:var(--hov)}.row.sel{background:var(--sel)}
.tg{width:16px;text-align:center;color:var(--mu);flex:none;font-size:11px}
.nm{overflow:hidden;text-overflow:ellipsis}.root>.row .nm{font-weight:600}
.bd{font-size:11px;padding:0 6px;border-radius:9px;line-height:17px;flex:none}
.bH{color:var(--h);background:var(--hb)}.bR{color:var(--r);background:var(--rb)}.bA{color:var(--a);background:var(--ab)}
.bE{color:var(--e);background:var(--eb)}.bG{color:var(--g);background:var(--gb)}
mark{background:#ffe066;color:#000;border-radius:2px}
#det h2{font-size:16px;margin:0 0 4px;word-break:break-all}.kv{color:var(--mu);font-size:13px;margin:2px 0}
.tw{overflow-x:auto;margin-top:12px}table{border-collapse:collapse;width:100%;min-width:560px;font-size:13px}
th,td{text-align:left;padding:5px 8px;border-bottom:1px solid var(--bd);vertical-align:top}
th{color:var(--mu);font-weight:600;position:sticky;top:0;background:var(--bg)}
tr.inh td{color:var(--mu)}tr.deny td:first-child{border-left:3px solid var(--r)}tr.alr td:last-child{color:var(--a);font-weight:600}
.leg{display:flex;flex-wrap:wrap;gap:8px;font-size:12px;color:var(--mu);margin-left:auto}
.empty{color:var(--mu);margin-top:40px;text-align:center}
.stat h2{font-size:16px;margin:0 0 10px}.stat h3{font-size:14px;margin:18px 0 4px}
.stat .big{display:flex;gap:22px;flex-wrap:wrap;margin:6px 0 4px}
.stat .big div{background:var(--hov);border:1px solid var(--bd);border-radius:8px;padding:8px 14px;min-width:90px}
.stat .big .v{font-size:22px;font-weight:600}.stat .big .l{font-size:12px;color:var(--mu)}
.stat .lvl,.stat .lvlhdr{display:grid;grid-template-columns:84px 1fr 110px 92px;gap:8px;align-items:center;margin:3px 0;font-size:13px}
.stat .lvlhdr{color:var(--mu);font-size:11px;margin-top:8px;border-bottom:1px solid var(--bd);padding-bottom:3px}
.stat .lvl .lab{color:var(--mu)}.stat .lvl .barbg{background:var(--hov);border-radius:4px;height:14px;overflow:hidden}
.stat .lvl .bar{background:var(--e);height:100%}
.stat .lvl .n{text-align:right;font-variant-numeric:tabular-nums}
.stat .tz{text-align:right;font-variant-numeric:tabular-nums;color:var(--mu)}
.bZ{color:var(--g);background:var(--gb)}
@media (max-width:820px){main{flex-direction:column}#tree{border-right:0;border-bottom:1px solid var(--bd);max-height:55vh}}
</style></head><body>
<header><h1>Arborescence des partages &amp; droits NTFS</h1><div class="m" id="meta"></div></header>
<div class="bar">
 <input type="search" id="q" placeholder="Rechercher un dossier ou un compte&hellip;">
 <label>D&eacute;plier jusqu'au niveau <input type="range" id="lv" min="0" max="1" value="1"><b id="lvv"></b></label>
 <label><input type="checkbox" id="fx"> Dossiers avec droits explicites / alertes seulement</label>
 <label><input type="checkbox" id="fi"> Masquer les ACE h&eacute;rit&eacute;es</label>
 <button id="stats" title="Volum&eacute;trie par niveau">&#128202; Statistiques</button>
 <div class="leg"><span class="bd bE">E n</span>explicites <span class="bd bH">H</span>h&eacute;ritage coup&eacute;
 <span class="bd bR">R</span>refus <span class="bd bA">! n</span>alertes <span class="bd bG">+</span>non explor&eacute;</div>
</div>
<main><div id="tree"></div><div id="det"><p class="empty">S&eacute;lectionnez un dossier pour afficher ses droits.</p></div></main>
<script>
const D=/*__DATA__*/null;
const byId=new Map(),kids=new Map();let maxD=0;
D.n.forEach(n=>{byId.set(n.i,n);if(!kids.has(n.p))kids.set(n.p,[]);kids.get(n.p).push(n);if(n.d>maxD)maxD=n.d;n.sf=n.f;});
for(let k=D.n.length-1;k>=0;k--){const n=D.n[k];n.df=n.df||0;if(n.p>=0){const P=byId.get(n.p);if(P){P.sf|=n.sf;P.df=(P.df||0)|n.sf;}}}
const $=id=>document.getElementById(id);
const esc=s=>String(s==null?'':s).replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));
const SD=D.sd;
function fsize(o){if(o==null)return'';if(o>=1099511627776)return(o/1099511627776).toFixed(2)+' To';
 if(o>=1073741824)return(o/1073741824).toFixed(2)+' Go';if(o>=1048576)return Math.round(o/1048576)+' Mo';
 if(o>0)return'<1 Mo';return'0';}
$('meta').textContent=D.s+' \u2014 g\u00e9n\u00e9r\u00e9 le '+D.t+' \u2014 '+D.n.length+' dossier(s)';
const lv=$('lv');lv.max=Math.max(1,maxD);lv.value=Math.min(1,maxD);
const open=new Set();let sel=null,visible=null,query='';
function hl(t){if(!query)return esc(t);const i=t.toLowerCase().indexOf(query);if(i<0)return esc(t);
 return esc(t.slice(0,i))+'<mark>'+esc(t.slice(i,i+query.length))+'</mark>'+esc(t.slice(i+query.length));}
function computeVisible(){
 const fx=$('fx').checked;query=$('q').value.trim().toLowerCase();
 if(!fx&&!query){visible=null;return;}
 visible=new Set();
 D.n.forEach(n=>{let ok=true;
  if(fx&&!(n.f&(1|2|4|8|32)))ok=false;
  if(ok&&query){ok=n.n.toLowerCase().includes(query)||n.c.toLowerCase().includes(query)||n.a.some(a=>a[0].toLowerCase().includes(query));}
  if(ok){let x=n;while(x&&!visible.has(x.i)){visible.add(x.i);if(x!==n)open.add(x.i);x=byId.get(x.p);}}});
}
function badges(n){let b='';const ne=n.a.filter(a=>!a[3]).length,na=n.a.filter(a=>a[5]).length;
 if(ne)b+='<span class="bd bE" title="ACE explicites">E '+ne+'</span>';
 if(n.f&1)b+='<span class="bd bH" title="H\u00e9ritage d\u00e9sactiv\u00e9">H</span>';
 if(n.f&2)b+='<span class="bd bR" title="ACE de refus">R</span>';
 if(na)b+='<span class="bd bA" title="Alertes">! '+na+'</span>';
 if(n.f&32)b+='<span class="bd bR" title="ACL illisible">ACL ?</span>';
 if(n.f&16)b+='<span class="bd bG" title="Sous-dossiers au-del\u00e0 de la profondeur audit\u00e9e">+</span>';
 if((n.df&(2|4))&&!open.has(n.i))b+='<span class="bd bA" title="Refus ou alerte dans un sous-dossier">\u2193!</span>';
 if(n.z)b+='<span class="bd bZ" title="Taille du dossier (contenu inclus)">'+fsize(n.z)+'</span>';
 return b;}
function renderNode(n){
 const ch=(kids.get(n.i)||[]).filter(c=>!visible||visible.has(c.i));
 const li=document.createElement('li');if(n.p<0)li.className='root';
 const isOpen=open.has(n.i)&&ch.length>0;
 const row=document.createElement('div');row.className='row'+(sel===n.i?' sel':'');
 row.innerHTML='<span class="tg">'+(ch.length?(isOpen?'\u25be':'\u25b8'):'')+'</span><span class="nm">'+hl(n.p<0?(n.r+'  '+n.n):n.n)+'</span>'+badges(n);
 row.onclick=e=>{if(e.target.classList.contains('tg')&&ch.length){open.has(n.i)?open.delete(n.i):open.add(n.i);render();return;}
  sel=n.i;if(ch.length&&!open.has(n.i))open.add(n.i);render();detail(n);};
 li.appendChild(row);
 if(isOpen){const ul=document.createElement('ul');ch.forEach(c=>ul.appendChild(renderNode(c)));li.appendChild(ul);}
 return li;}
function render(){const t=$('tree'),y=t.scrollTop;t.innerHTML='';const ul=document.createElement('ul');
 const roots=(kids.get(-1)||[]).filter(r=>!visible||visible.has(r.i));
 if(!roots.length){t.innerHTML='<p class="empty">Aucun dossier ne correspond.</p>';return;}
 roots.forEach(r=>ul.appendChild(renderNode(r)));t.appendChild(ul);t.scrollTop=y;}
function detail(n){const hide=$('fi').checked;let h='<h2>'+esc(n.c)+'</h2>';
 if(n.p<0)h+='<div class="kv">Partage : '+esc(n.r)+' \u2014 profondeur audit\u00e9e : '+esc(n.pm)+'</div>';
 h+='<div class="kv">Niveau '+n.d+' \u2014 propri\u00e9taire : '+esc(n.o||'?')+'</div>';
 if(n.z!=null)h+='<div class="kv">Taille du dossier (contenu inclus) : <b>'+fsize(n.z)+'</b></div>';
 else if(n.d>SD)h+='<div class="kv">Taille non d\u00e9taill\u00e9e au-del\u00e0 du niveau '+SD+'</div>';
 h+='<div class="kv">H\u00e9ritage : '+(n.f&1?'<b style="color:var(--h)">d\u00e9sactiv\u00e9</b>':'actif')+'</div>';
 if(n.e)h+='<div class="kv" style="color:var(--r)">ACL illisible : '+esc(n.e)+'</div>';
 if(n.f&16)h+='<div class="kv">Contient des sous-dossiers non explor\u00e9s (limite de profondeur).</div>';
 if(n.sp&&n.sp.length){h+='<div class="tw"><table><tr><th>Droits de partage SMB</th><th>Type</th><th>Droit</th></tr>'+
  n.sp.map(s=>'<tr><td>'+esc(s[0])+'</td><td>'+esc(s[1])+'</td><td>'+esc(s[2])+'</td></tr>').join('')+'</table></div>';}
 const aces=n.a.filter(a=>!(hide&&a[3]));
 h+='<div class="tw"><table><tr><th>Compte / groupe</th><th>Type</th><th>Droits</th><th>Origine</th><th>S\u2019applique \u00e0</th><th>Alerte</th></tr>';
 h+=aces.length?aces.map(a=>'<tr class="'+(a[3]?'inh ':'')+(a[1]?'deny ':'')+(a[5]?'alr':'')+'"><td>'+hl(a[0])+'</td><td>'+(a[1]?'Refuser':'Autoriser')+
  '</td><td>'+esc(a[2])+'</td><td>'+(a[3]?'H\u00e9rit\u00e9e':'<b>Explicite</b>')+'</td><td>'+esc(a[4])+'</td><td>'+esc(a[5])+'</td></tr>').join('')
  :'<tr><td colspan="6" style="color:var(--mu)">Aucune ACE \u00e0 afficher.</td></tr>';
 $('det').innerHTML=h+'</table></div>';}
function setLevel(v){$('lvv').textContent=v+' / '+maxD;open.clear();D.n.forEach(n=>{if(n.d<v)open.add(n.i);});}
// Racine (ancetre p<0) de chaque noeud, mise en cache
function rootOf(n){let x=n;while(x&&x.p>=0)x=byId.get(x.p);return x;}
// auditByLevel : nb de dossiers audites par niveau, pour un ensemble de noeuds
function auditByLevel(nodes){const a=[];nodes.forEach(n=>{a[n.d]=(a[n.d]||0)+1;});for(let i=0;i<a.length;i++)if(a[i]==null)a[i]=0;return a;}
// Un bloc = un en-tete + chiffres cles + tableau par niveau (existants / audites / taille)
function volBlock(label,audit,exist,bytes,totBytes){
 const nivMax=Math.max(audit.length-1,exist?exist.length-1:0);
 const totAudit=audit.reduce((s,x)=>s+(x||0),0);
 const totExist=exist?exist.reduce((s,x)=>s+(x||0),0):null;
 let h='';
 if(label!==null)h+='<h3>'+esc(label)+'</h3>';
 h+='<div class="big">';
 h+='<div><div class="v">'+(totExist!=null?totExist:totAudit)+'</div><div class="l">dossiers'+(totExist!=null?' existants':'')+'</div></div>';
 if(totExist!=null)h+='<div><div class="v">'+totAudit+'</div><div class="l">audit\u00e9s</div></div>';
 h+='<div><div class="v">'+nivMax+'</div><div class="l">niveau'+(nivMax>1?'x':'')+'</div></div>';
 if(totBytes!=null)h+='<div><div class="v">'+fsize(totBytes)+'</div><div class="l">taille disque</div></div>';
 h+='</div>';
 // peak pour l'echelle des barres (sur existants si dispo, sinon audites)
 const ref=exist||audit;let peak=0;ref.forEach(x=>{if(x>peak)peak=x;});
 h+='<div class="lvlhdr"><span></span><span>existants / audit\u00e9s</span><span class="tz">taille \u2264 niv.'+SD+'</span></div>';
 for(let k=0;k<=nivMax;k++){
  const ex=exist?(exist[k]||0):null, au=audit[k]||0;
  const lab=k===0?(label===null?'racines':'racine'):'niveau '+k;
  const w=peak?Math.round((ex!=null?ex:au)/peak*100):0;
  let tz='';
  if(bytes){ if(k<SD)tz=fsize(bytes[k]||0); else if(k===SD)tz=fsize(bytes[SD]||0)+(nivMax>SD?' +':''); else tz='\u2193'; }
  h+='<div class="lvl"><span class="lab">'+lab+'</span>'+
     '<span class="barbg"><span class="bar" style="width:'+w+'%"></span></span>'+
     '<span class="n">'+(ex!=null?ex+' / ':'')+au+'</span>'+
     '<span class="tz">'+tz+'</span></div>';
 }
 return h;}
function stats(){
 sel=null;
 const roots=kids.get(-1)||[];
 // Global : agreger les tableaux complets des racines
 let gExist=[],gBytes=[],gTot=0,haveMeta=false;
 roots.forEach(r=>{
  if(r.fc){haveMeta=true;r.fc.forEach((c,k)=>gExist[k]=(gExist[k]||0)+c);
   if(r.bz)r.bz.forEach((b,k)=>gBytes[k]=(gBytes[k]||0)+b);
   if(r.tt!=null)gTot+=r.tt;}
 });
 let h='<div class="stat"><h2>\u{1F4CA} Volum\u00e9trie de l\'audit</h2>';
 h+=volBlock(null,auditByLevel(D.n),haveMeta?gExist:null,haveMeta?gBytes:null,haveMeta?gTot:null);
 h+='<h3 style="margin-top:22px;border-top:1px solid var(--bd);padding-top:12px">Par partage / racine</h3>';
 roots.forEach(r=>{const sub=D.n.filter(n=>rootOf(n)===r);
  h+=volBlock((r.r?r.r+'  ':'')+r.n,auditByLevel(sub),r.fc||null,r.bz||null,r.tt!=null?r.tt:null);});
 $('det').innerHTML=h+'</div>';}
lv.oninput=()=>{setLevel(+lv.value);computeVisible();render();};
$('q').oninput=()=>{computeVisible();render();};
$('fx').onchange=()=>{computeVisible();render();};
$('fi').onchange=()=>{if(sel!=null)detail(byId.get(sel));};
$('stats').onclick=stats;
setLevel(+lv.value);render();
</script></body></html>
'@

# ─── MAIN ────────────────────────────────────────────────────
function Invoke-AuditNTFS {
    Write-Host ""
    Write-Host "=== AUDIT NTFS ===" -ForegroundColor Cyan
    if (-not $modeInteractif) { Write-Host "  Mode non interactif (profondeur : $(Texte-Profondeur $profDefaut))" -ForegroundColor DarkGray }

    Write-Host ""
    Write-Host "Decouverte des partages..." -ForegroundColor Cyan
    $partagesDisponibles = Decouvrir-Partages

    $racines = Choisir-Racines -PartagesDisponibles $partagesDisponibles
    if ($racines.Count -eq 0) {
        Write-Host "Aucun chemin selectionne - audit NTFS ignore." -ForegroundColor Yellow
        return 0
    }

    Choisir-Profondeurs -Racines $racines

    Write-Host ""
    Write-Host "Racines a auditer :" -ForegroundColor Cyan
    foreach ($r in $racines) { Write-Host "  - [$($r.Type)] $($r.Chemin)  (profondeur : $(Texte-Profondeur $r.Profondeur))" -ForegroundColor White }

    $null = New-Item -ItemType Directory -Force -Path $ntfsDir

    $lignesPartage = Auditer-DroitsPartage -Racines $racines

    foreach ($r in $racines) {
        Write-Host ""
        Write-Host "Audit : $($r.Chemin)" -ForegroundColor DarkCyan

        # Balayage complet (dossiers tous niveaux + taille disque jusqu'au niveau $profTaille).
        # Lecture seule, sans plafond : donne la vraie taille du partage independamment de la
        # profondeur d'audit choisie.
        Write-Host "  Mesure de l'arborescence complete (dossiers + taille)..." -ForegroundColor DarkGray
        $script:mesures[$r.Chemin] = Mesurer-Racine -Chemin $r.Chemin -ProfTaille $profTaille
        $m = $script:mesures[$r.Chemin]
        $totDoss = ($m.DossiersParNiveau | Measure-Object -Sum).Sum
        Write-Host "    $totDoss dossier(s) existant(s) sur $($m.NiveauMax) niveau(x) - $(Format-Taille $m.TailleTotale)" -ForegroundColor DarkGray

        $avant = $script:lignesCsv.Count
        $nb = Auditer-Racine -Racine $r
        Write-Host "  $nb dossier(s) audite(s), $($script:lignesCsv.Count - $avant) ACE collectee(s)" -ForegroundColor Green
    }

    # Exports
    $script:lignesCsv | Export-Csv -Path $FichierCsv -NoTypeInformation -Encoding UTF8
    Write-Host ""
    Write-Host "CSV droits NTFS      : $FichierCsv ($($script:lignesCsv.Count) lignes)" -ForegroundColor Green

    if ($lignesPartage.Count -gt 0) {
        $lignesPartage | Export-Csv -Path $FichierPartages -NoTypeInformation -Encoding UTF8
        Write-Host "CSV droits partage   : $FichierPartages" -ForegroundColor Green
    }
    if ($script:erreurs.Count -gt 0) {
        $script:erreurs | Export-Csv -Path $FichierErreurs -NoTypeInformation -Encoding UTF8
        $nbErr  = @($script:erreurs | Where-Object { $_.Categorie -eq "Erreur" }).Count
        $nbInfo = $script:erreurs.Count - $nbErr
        $couleur = if ($nbErr -gt 0) { "Yellow" } else { "DarkGray" }
        Write-Host "Journal erreurs/skip : $FichierErreurs ($nbErr erreur(s), $nbInfo info(s) : jonctions, DFS, exclusions)" -ForegroundColor $couleur
    }

    try {
        Generer-ArborescenceTxt  -Racines $racines -Fichier $FichierTxt
        Write-Host "Schema texte         : $FichierTxt" -ForegroundColor Green
    } catch { Write-Warning "Generation du schema texte echouee : $_" }

    try {
        Generer-ArborescenceHtml -Racines $racines -Fichier $FichierHtml
        Write-Host "Schema interactif    : $FichierHtml" -ForegroundColor Green
    } catch { Write-Warning "Generation du schema HTML echouee : $_" }

    $nbAlertes = @($script:lignesCsv | Where-Object { $_.Alerte }).Count
    if ($nbAlertes -gt 0) { Write-Host "Alertes relevees     : $nbAlertes (colonne Alerte du CSV)" -ForegroundColor Yellow }
    return 0
}

$codeSortie = 1
try {
    $null = Invoke-AuditNTFS
    $codeSortie = 0
} catch {
    Write-Error "Audit NTFS interrompu : $_"
    $codeSortie = 1
} finally {
    if ($transcriptActif) { try { Stop-Transcript | Out-Null } catch {} }
}

# Pas de 'exit' si le script est dot-source (sinon on tuerait l'appelant)
if ($MyInvocation.InvocationName -ne '.') { exit $codeSortie }