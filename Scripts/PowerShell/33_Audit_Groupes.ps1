# 33_Audit_Groupes.ps1
# Version      : 1.2
# Derniere modif : Sortie dans Temp_CSV\AD
# v1.1         : ReferenceNTFS : chemin complet des dossiers ou le groupe a une ACE explicite
#                  (au lieu du seul partage racine, illisible sur les espaces DFS), droits indiques
# Role         : Audit des groupes AD (securite + distribution) : identite, portee, membres effectifs,
#                imbrication (circulaire / vers groupe privilegie), T0, dates, references NTFS et GPO
# Usage        : Lance via main.ps1 ou directement. Necessite RSAT AD (DC ou membre de domaine).
#                Numerote 33_ pour tourner APRES 31_Audit_NTFS (lecture de ses CSV pour le croisement).
#                $env:AUDIT_GROUPES_REPLMETA = "0" desactive la lecture des metadonnees de replication
#                (colonne DerniereModifMembres) sur les tres gros domaines.
# Sortie       : une ligne par membre effectif ; les infos du groupe ne sont remplies que sur la
#                premiere ligne du groupe (lignes suivantes : colonnes Membres/TypeMembre/MembreVia).
# ============================================================
$tempCsv    = $env:AUDIT_TEMP_CSV
if (-not $tempCsv) { $tempCsv = Join-Path $PSScriptRoot "..\..\Temp_CSV" }
$CompSys    = Get-CimInstance Win32_ComputerSystem
$DomainName = $CompSys.Domain
$AdDir      = if ($env:AUDIT_TEMP_AD) { $env:AUDIT_TEMP_AD } else { Join-Path $tempCsv "AD" }
$ExportFile = "$AdDir\$env:COMPUTERNAME.$DomainName" + "_Audit_Groupes.csv"
$NtfsDir    = if ($env:AUDIT_TEMP_NTFS) { $env:AUDIT_TEMP_NTFS } else { Join-Path $tempCsv "NTFS" }

$null = New-Item -ItemType Directory -Force -Path (Split-Path $ExportFile)

if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
    Write-Host "Module ActiveDirectory introuvable - script ignore (necessite RSAT AD)." -ForegroundColor Yellow
    exit 0
}
Import-Module ActiveDirectory -ErrorAction Stop

$Domain    = Get-ADDomain
$DomainSID = $Domain.DomainSID.Value
$DcName    = (Get-ADDomainController -Discover -DomainName $Domain.DNSRoot).HostName | Select-Object -First 1
$LireRepl  = $env:AUDIT_GROUPES_REPLMETA -ne "0"

# ─── FONCTIONS UTILITAIRES ──────────────────────────────────

# Decoupe un DN en RDN en respectant les virgules echappees (CN=Dupont\, Jean,OU=...)
function Get-RdnList([string]$Dn) {
    return [regex]::Split($Dn, '(?<!\\),')
}

# Nom du conteneur direct (OU ou CN) dans lequel se trouve l'objet - pas le chemin complet
function Get-ParentName([string]$Dn) {
    $rdn = Get-RdnList $Dn
    if ($rdn.Count -lt 2) { return "" }
    return (($rdn[1] -replace '^(OU|CN|DC)=', '') -replace '\\,', ',')
}

# Nom lisible a partir d'un DN inconnu (objet hors domaine)
function Get-CnFromDn([string]$Dn) {
    return (((Get-RdnList $Dn)[0] -replace '^(CN|OU)=', '') -replace '\\,', ',')
}

function Get-Rid([string]$Sid) {
    if (-not $Sid) { return -1 }
    return [int](($Sid -split '-')[-1])
}

function Convert-SidToName([string]$Sid) {
    try {
        return ([System.Security.Principal.SecurityIdentifier]$Sid).Translate([System.Security.Principal.NTAccount]).Value
    } catch {
        return "$Sid (SID orphelin)"
    }
}

function OuiNon($b) { if ($b) { "Oui" } else { "Non" } }

# ─── GROUPES PRIVILEGIES (T0) ───────────────────────────────
# Detection par SID => independant de la langue de l'OS (Admins du domaine / Domain Admins...)
#   BUILTIN : 544 Administrateurs, 548 Account Ops, 549 Server Ops, 550 Print Ops, 551 Backup Ops, 552 Replicator
#   Domaine : 512 Domain Admins, 516 Domain Controllers, 517 Cert Publishers, 518 Schema Admins,
#             519 Enterprise Admins, 520 GPO Creator Owners, 521 RODC, 526 Key Admins, 527 Enterprise Key Admins
#   DnsAdmins : RID variable => detection par nom
$RidBuiltinT0 = @(544, 548, 549, 550, 551, 552)
$RidDomaineT0 = @(512, 516, 517, 518, 519, 520, 521, 526, 527)

function Test-Privilegie($Grp) {
    $sid = $Grp.SID
    $rid = Get-Rid $sid
    if ($sid -match '^S-1-5-32-' -and $RidBuiltinT0 -contains $rid) { return $true }
    if ($sid -like "$DomainSID-*" -and $RidDomaineT0 -contains $rid) { return $true }
    if ($Grp.SamAccountName -eq 'DnsAdmins') { return $true }
    return $false
}

# ─── COLLECTE AD ────────────────────────────────────────────
Write-Host "Lecture des groupes AD..."
$Groups = Get-ADGroup -Filter * -Properties SID, mail, GroupCategory, GroupScope, member, adminCount, `
                                            isCriticalSystemObject, whenCreated, whenChanged `
          -ErrorAction Stop | Sort-Object Name

Write-Host "Lecture des objets membres potentiels (comptes, ordinateurs, gMSA, FSP, contacts)..."
$Objets = Get-ADObject -LDAPFilter "(|(objectSid=*)(objectClass=contact))" `
                       -Properties sAMAccountName, objectSid, primaryGroupID, objectClass `
                       -ErrorAction Stop

# Index DN -> objet, et DN -> infos groupe
$ParDn = @{}
foreach ($o in $Objets) { $ParDn[$o.DistinguishedName] = $o }

$GrpParDn  = @{}
$GrpParRid = @{}
foreach ($g in $Groups) {
    $info = [PSCustomObject]@{
        Dn             = $g.DistinguishedName
        Name           = $g.Name
        SamAccountName = $g.SamAccountName
        SID            = $g.SID.Value
        Objet          = $g
    }
    $GrpParDn[$g.DistinguishedName] = $info
    if ($info.SID -like "$DomainSID-*") { $GrpParRid[(Get-Rid $info.SID)] = $info }
}

# Graphe des membres : DN groupe -> liste de DN membres
# + appartenance via le groupe principal (primaryGroupID), absente de l'attribut 'member'
#   (sans ca, "Utilisateurs du domaine" apparaitrait vide)
$Membres = @{}
foreach ($g in $Groups) {
    $Membres[$g.DistinguishedName] = [System.Collections.Generic.List[string]]::new()
    foreach ($m in $g.member) { $Membres[$g.DistinguishedName].Add($m) }
}
$Principal = @{}   # DN membre -> DN groupe principal (pour l'etiquette "Groupe principal")
foreach ($o in $Objets) {
    if ($o.primaryGroupID -and $GrpParRid.ContainsKey([int]$o.primaryGroupID)) {
        $gDn = $GrpParRid[[int]$o.primaryGroupID].Dn
        if (-not $Membres[$gDn].Contains($o.DistinguishedName)) {
            $Membres[$gDn].Add($o.DistinguishedName)
            $Principal["$gDn|$($o.DistinguishedName)"] = $true
        }
    }
}

# Graphe inverse (parents) restreint aux groupes : DN groupe -> groupes qui le contiennent
$Parents = @{}
foreach ($gDn in $Membres.Keys) {
    foreach ($m in $Membres[$gDn]) {
        if ($GrpParDn.ContainsKey($m)) {
            if (-not $Parents.ContainsKey($m)) { $Parents[$m] = [System.Collections.Generic.List[string]]::new() }
            $Parents[$m].Add($gDn)
        }
    }
}

function Get-TypeMembre($Dn) {
    if (-not $ParDn.ContainsKey($Dn)) { return "Hors domaine" }
    switch ($ParDn[$Dn].ObjectClass) {
        "user"                             { "Utilisateur" }
        "inetOrgPerson"                    { "Utilisateur" }
        "computer"                         { "Ordinateur" }
        "msDS-GroupManagedServiceAccount"  { "gMSA" }
        "msDS-ManagedServiceAccount"       { "MSA" }
        "foreignSecurityPrincipal"         { "Externe (FSP)" }
        "contact"                          { "Contact" }
        default                            { $ParDn[$Dn].ObjectClass }
    }
}

function Get-NomMembre($Dn) {
    if (-not $ParDn.ContainsKey($Dn)) { return Get-CnFromDn $Dn }
    $o = $ParDn[$Dn]
    if ($o.ObjectClass -eq "foreignSecurityPrincipal") { return Convert-SidToName $o.Name }
    if ($o.sAMAccountName) { return $o.sAMAccountName }
    return $o.Name
}

# Membres effectifs (recursif, parcours en largeur => chemin le plus court) + detection de cycle
function Get-MembresEffectifs([string]$StartDn) {
    $feuilles = [ordered]@{}           # DN membre -> chemin "via"
    $vus      = @{ $StartDn = $true }
    $file     = [System.Collections.Generic.Queue[object]]::new()
    $file.Enqueue(@($StartDn, @()))    # (DN groupe, chemin de noms depuis le groupe audite)
    $cycle    = $null

    while ($file.Count -gt 0) {
        $courant = $file.Dequeue()
        $gDn = $courant[0]; $chemin = $courant[1]
        foreach ($m in $Membres[$gDn]) {
            if ($GrpParDn.ContainsKey($m)) {
                if ($m -eq $StartDn) {
                    if (-not $cycle) {
                        $noms  = @($GrpParDn[$StartDn].Name) + $chemin + @($GrpParDn[$StartDn].Name)
                        $cycle = $noms -join " > "
                    }
                } elseif (-not $vus.ContainsKey($m)) {
                    $vus[$m] = $true
                    $file.Enqueue(@($m, ($chemin + @($GrpParDn[$m].Name))))
                }
            } elseif (-not $feuilles.Contains($m)) {
                if ($chemin.Count -eq 0) {
                    $via = if ($Principal.ContainsKey("$gDn|$m")) { "Groupe principal" } else { "Direct" }
                } else {
                    $via = "Via " + ($chemin -join " > ")
                }
                $feuilles[$m] = $via
            }
        }
    }
    return [PSCustomObject]@{ Feuilles = $feuilles; Cycle = $cycle }
}

# Chemins d'imbrication vers les groupes privilegies (remontee via les parents)
function Get-CheminsPrivilegies([string]$StartDn) {
    $res  = [System.Collections.Generic.List[string]]::new()
    $vus  = @{ $StartDn = $true }
    $file = [System.Collections.Generic.Queue[object]]::new()
    $file.Enqueue(@($StartDn, @($GrpParDn[$StartDn].Name)))
    while ($file.Count -gt 0) {
        $courant = $file.Dequeue()
        $gDn = $courant[0]; $chemin = $courant[1]
        if (-not $Parents.ContainsKey($gDn)) { continue }
        foreach ($p in $Parents[$gDn]) {
            if ($vus.ContainsKey($p)) { continue }
            $vus[$p] = $true
            $nouveau = $chemin + @($GrpParDn[$p].Name)
            if (Test-Privilegie $GrpParDn[$p]) { $res.Add($nouveau -join " > ") }
            $file.Enqueue(@($p, $nouveau))
        }
    }
    return $res
}

# Date de derniere modification de l'appartenance (metadonnees de replication des valeurs liees 'member')
function Get-DerniereModifMembres([string]$Dn) {
    if (-not $LireRepl) { return "Non collecte" }
    try {
        $meta = Get-ADReplicationAttributeMetadata -Object $Dn -Server $DcName -Properties member `
                                                   -ShowAllLinkedValues -ErrorAction Stop
        $dates = foreach ($m in $meta) {
            if ($m.AttributeName -ne 'member') { continue }
            foreach ($d in @($m.LastOriginatingChangeTime, $m.LastOriginatingDeleteTime)) {
                if ($d -and $d.Year -gt 1601) { $d }
            }
        }
        if ($dates) { return ($dates | Sort-Object -Descending | Select-Object -First 1) }
        return ""
    } catch {
        return "Erreur lecture"
    }
}

# ─── REFERENCES NTFS (CSV produits par 31_Audit_NTFS) ───────
# NB : les SID BUILTIN (S-1-5-32-*) designent les groupes LOCAUX du serveur de fichiers,
#      pas le groupe du domaine => exclus du croisement (idem pour les GPO).
#      Seules les ACE EXPLICITES (Herite = Non) sont retenues : c'est la que le groupe a ete
#      positionne ; les ACE heritees se repetent sur chaque sous-dossier et noieraient l'information.
$RefNtfs     = @{}   # cle (SID ou nom en minuscules) -> HashSet "chemin [droits]"
$NtfsAudite  = $false
$MaxRefNtfs  = 50    # au-dela, la cellule est tronquee (limite Excel : 32 767 caracteres)

# Chemin lisible d'une ligne du CSV NTFS
#   DFS / lecteur reseau / chemin UNC : le dossier tel quel (\\domaine\DFS\Compta\RH)
#   Partage SMB local                 : \\Serveur\Partage\CheminRelatif (au lieu de D:\Partages\...)
#   Autre chemin local                : Serveur : D:\...
function Get-CheminNtfs($L) {
    if ($L.Dossier -like '\\*') { return $L.Dossier.TrimEnd('\') }
    if ($L.TypePartage -eq 'SMB' -and $L.Partage) {
        $c = "\\$($L.Serveur)\$($L.Partage)"
        if ($L.CheminRelatif) { $c += "\$($L.CheminRelatif)" }
        return $c
    }
    if ($L.Dossier) { return "$($L.Serveur) : $($L.Dossier)" }
    return "\\$($L.Serveur)\$($L.Partage)"
}

$csvNtfs = @(Get-ChildItem -Path $NtfsDir -Filter "*_Audit_NTFS*.csv" -File -ErrorAction SilentlyContinue |
             Where-Object { $_.Name -match '_Audit_NTFS(_Partages)?\.csv$' })
if ($csvNtfs.Count -gt 0) {
    $NtfsAudite = $true
    foreach ($f in $csvNtfs) {
        $estPartages = $f.Name -match '_Partages\.csv$'
        foreach ($l in (Import-Csv -Path $f.FullName -Encoding UTF8)) {
            if (-not $l.Identite) { continue }
            if ($estPartages) {
                # Droits de partage SMB
                $cible = "\\$($l.Serveur)\$($l.Partage) [partage : $($l.DroitsPartage)]"
            } else {
                if ($l.Herite -ne 'Non') { continue }
                $droits = if ($l.TypeAcces -eq 'Refuser') { "Refus $($l.Droits)" } else { $l.Droits }
                $cible  = "$(Get-CheminNtfs $l) [$droits]"
            }
            $cles = @()
            if ($l.PSObject.Properties['SID'] -and $l.SID) { $cles += $l.SID }
            $cles += (($l.Identite -split '\\')[-1]).ToLower()
            foreach ($c in $cles) {
                if (-not $RefNtfs.ContainsKey($c)) { $RefNtfs[$c] = [System.Collections.Generic.HashSet[string]]::new() }
                [void]$RefNtfs[$c].Add($cible)
            }
        }
    }
    Write-Host "Croisement NTFS : $($csvNtfs.Count) CSV lus."
} else {
    Write-Host "Aucun CSV NTFS trouve dans $NtfsDir - colonne ReferenceNTFS = 'Non audite'." -ForegroundColor Yellow
}

# ─── REFERENCES GPO ─────────────────────────────────────────
# Sources : filtrage de securite / delegation (Get-GPPermission), groupes restreints et droits
#           utilisateur (GptTmpl.inf), preferences de groupes locaux (Groups.xml)
$RefGpo     = @{}    # SID -> HashSet "NomGPO (type)"
$GpoAudite  = $false
function Add-RefGpo([string]$Sid, [string]$Libelle) {
    if (-not $Sid -or $Sid -match '^S-1-5-32-') { return }
    if (-not $RefGpo.ContainsKey($Sid)) { $RefGpo[$Sid] = [System.Collections.Generic.HashSet[string]]::new() }
    [void]$RefGpo[$Sid].Add($Libelle)
}

# Index nom -> SID pour les entrees GptTmpl.inf non resolues en SID (ecrites par nom)
$SidParNom = @{}
foreach ($g in $GrpParDn.Values) { $SidParNom[$g.SamAccountName.ToLower()] = $g.SID }

if (Get-Module -ListAvailable -Name GroupPolicy) {
    Import-Module GroupPolicy -ErrorAction SilentlyContinue
    $GpoAudite = $true
    $dns  = $Domain.DNSRoot
    $gpos = Get-GPO -All -Domain $dns -ErrorAction SilentlyContinue
    Write-Host "Croisement GPO : $(@($gpos).Count) GPO a analyser..."

    foreach ($gpo in $gpos) {
        $nom = $gpo.DisplayName

        # 1) Filtrage de securite et delegation (on ignore la delegation par defaut DA / EA)
        try {
            foreach ($p in (Get-GPPermission -Guid $gpo.Id -All -DomainName $dns -ErrorAction Stop)) {
                $sid = $p.Trustee.Sid.Value
                if ($p.Permission -eq 'GpoApply') {
                    Add-RefGpo $sid "$nom (Filtrage)"
                } elseif ($p.Permission -in @('GpoEdit', 'GpoEditDeleteModifySecurity', 'GpoCustom')) {
                    if ($sid -notin @("$DomainSID-512", "$DomainSID-519")) { Add-RefGpo $sid "$nom (Delegation)" }
                }
            }
        } catch {}

        $base = "\\$dns\SYSVOL\$dns\Policies\{$($gpo.Id)}"

        # 2) GptTmpl.inf : [Group Membership] et [Privilege Rights]
        $inf = Join-Path $base "Machine\Microsoft\Windows NT\SecEdit\GptTmpl.inf"
        if (Test-Path $inf) {
            $section = ""
            foreach ($ligne in (Get-Content -Path $inf -ErrorAction SilentlyContinue)) {
                if ($ligne -match '^\s*\[(.+)\]\s*$') { $section = $Matches[1]; continue }
                $libelle = switch ($section) {
                    'Group Membership' { "Groupes restreints" }
                    'Privilege Rights' { "Droits utilisateur" }
                    default            { $null }
                }
                if (-not $libelle) { continue }
                foreach ($m in [regex]::Matches($ligne, 'S-1-[0-9-]+')) { Add-RefGpo $m.Value "$nom ($libelle)" }
                # Entrees ecrites par nom (sans *SID)
                $valeurs = ($ligne -split '=', 2)[-1] -split ','
                foreach ($v in $valeurs) {
                    $n = (($v.Trim() -split '\\')[-1]).ToLower()
                    if ($n -and -not $n.StartsWith('*') -and $SidParNom.ContainsKey($n)) {
                        Add-RefGpo $SidParNom[$n] "$nom ($libelle)"
                    }
                }
            }
        }

        # 3) Preferences : groupes locaux (Groups.xml cote ordinateur et utilisateur)
        foreach ($cote in @("Machine", "User")) {
            $xml = Join-Path $base "$cote\Preferences\Groups\Groups.xml"
            if (Test-Path $xml) {
                $contenu = Get-Content -Path $xml -Raw -ErrorAction SilentlyContinue
                foreach ($m in [regex]::Matches($contenu, '(?i)sid="(S-1-[0-9-]+)"')) {
                    Add-RefGpo $m.Groups[1].Value "$nom (Preferences groupes)"
                }
            }
        }
    }
} else {
    Write-Host "Module GroupPolicy introuvable - colonne ReferenceGPO = 'Non audite'." -ForegroundColor Yellow
}

# ─── CONSTRUCTION DES LIGNES ────────────────────────────────
$Results = [System.Collections.Generic.List[object]]::new()
$i = 0
foreach ($g in $Groups) {
    $i++
    if ($i % 100 -eq 0) { Write-Host "  $i / $($Groups.Count) groupes traites..." }

    try {
        $dn   = $g.DistinguishedName
        $sid  = $g.SID.Value
        $info = $GrpParDn[$dn]

        $effectifs = Get-MembresEffectifs $dn
        $chemins   = Get-CheminsPrivilegies $dn

        $estBuiltin = ($sid -match '^S-1-5-32-') -or ((Get-Rid $sid) -lt 1000) -or [bool]$g.isCriticalSystemObject

        $memberOf = @()
        if ($Parents.ContainsKey($dn)) { $memberOf = $Parents[$dn] | ForEach-Object { $GrpParDn[$_].Name } | Sort-Object }

        # References NTFS / GPO
        if ($sid -match '^S-1-5-32-') {
            $refN = "N/A (groupe BUILTIN local)"
            $refG = "N/A (groupe BUILTIN local)"
        } else {
            if ($NtfsAudite) {
                $cibles = [System.Collections.Generic.HashSet[string]]::new()
                foreach ($c in @($sid, $g.SamAccountName.ToLower(), $g.Name.ToLower())) {
                    if ($RefNtfs.ContainsKey($c)) { $cibles.UnionWith($RefNtfs[$c]) }
                }
                if ($cibles.Count -eq 0) {
                    $refN = "Non"
                } else {
                    $liste = @($cibles | Sort-Object)
                    $refN  = ($liste | Select-Object -First $MaxRefNtfs) -join " | "
                    if ($liste.Count -gt $MaxRefNtfs) { $refN += " | ... (+$($liste.Count - $MaxRefNtfs) autres, voir l'audit NTFS)" }
                }
            } else { $refN = "Non audite" }

            if ($GpoAudite) {
                $refG = if ($RefGpo.ContainsKey($sid)) { ($RefGpo[$sid] | Sort-Object) -join " - " } else { "Non" }
            } else { $refG = "Non audite" }
        }

        $categorie = if ($g.GroupCategory -eq 'Security') { "Securite" } else { "Distribution" }
        $portee    = switch ("$($g.GroupScope)") {
            'DomainLocal' { "Domaine local" }
            'Global'      { "Globale" }
            'Universal'   { "Universelle" }
            default       { "$($g.GroupScope)" }
        }

        $ligneGroupe = [ordered]@{
            Groupe                = $g.Name
            SamAccountName        = $g.SamAccountName
            OU                    = Get-ParentName $dn
            SID                   = $sid
            Mail                  = $g.mail
            Categorie             = $categorie
            Portee                = $portee
            Builtin               = OuiNon $estBuiltin
            NbMembresEffectifs    = $effectifs.Feuilles.Count
            Membres               = ""
            TypeMembre            = ""
            MembreVia             = ""
            MemberOf              = ($memberOf -join " - ")
            ImbricationCirculaire = if ($effectifs.Cycle) { "Oui : $($effectifs.Cycle)" } else { "Non" }
            CheminVersPrivilegie  = ($chemins -join " | ")
            PrivilegieT0          = OuiNon (Test-Privilegie $info)
            AdminCount            = OuiNon ($g.adminCount -eq 1)
            DateCreation          = $g.whenCreated
            DateModification      = $g.whenChanged
            DerniereModifMembres  = Get-DerniereModifMembres $dn
            ReferenceNTFS         = $refN
            ReferenceGPO          = $refG
        }

        # Tri des membres : type puis nom
        $listeMembres = foreach ($m in $effectifs.Feuilles.Keys) {
            [PSCustomObject]@{ Nom = Get-NomMembre $m; Type = Get-TypeMembre $m; Via = $effectifs.Feuilles[$m] }
        }
        $listeMembres = @($listeMembres | Sort-Object Type, Nom)

        if ($listeMembres.Count -eq 0) {
            # Groupe vide : une seule ligne
            $Results.Add([PSCustomObject]$ligneGroupe)
            continue
        }

        $premier = $true
        foreach ($m in $listeMembres) {
            if ($premier) {
                $ligne = $ligneGroupe
                $premier = $false
            } else {
                # Lignes suivantes : seules les colonnes membre sont remplies (cf. maquette)
                $ligne = [ordered]@{}
                foreach ($k in $ligneGroupe.Keys) { $ligne[$k] = "" }
            }
            $ligne.Membres    = $m.Nom
            $ligne.TypeMembre = $m.Type
            $ligne.MembreVia  = $m.Via
            $Results.Add([PSCustomObject]$ligne)
        }
    } catch {
        Write-Warning "Impossible de traiter le groupe $($g.Name) : $_"
    }
}

Write-Host "$($Groups.Count) groupe(s) collecte(s), $($Results.Count) ligne(s)"
$Results | Export-Csv -Path $ExportFile -NoTypeInformation -Encoding UTF8
Write-Host "Rapport genere : $ExportFile"