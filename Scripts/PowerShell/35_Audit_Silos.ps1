# 15_Audit_Silos.ps1
# Version      : 1.1
# Derniere modif : Sorties dans Temp_CSV\AD
# Role         : Audit des silos de strategies d'authentification (Authentication Policy Silos)
#                et des strategies d'authentification associees (Kerberos armoring / restriction T0)
# Usage        : Lance via main.ps1 ou directement. Necessite RSAT AD et un niveau fonctionnel
#                de domaine >= 2012 R2 (sinon les silos n'existent pas : rapport avec une ligne d'info).
# Sorties      : <HOST>_Audit_Silos.csv            : une ligne par compte (infos silo sur la 1re ligne)
#                                                    + bloc "(Aucun silo)" : comptes T0 actifs hors silo
#                <HOST>_Audit_Silos_Politiques.csv : une ligne par strategie d'authentification
# Rappel       : un compte n'est reellement dans un silo que s'il est AUTORISE (msDS-AuthNPolicySiloMembers)
#                ET ASSIGNE (msDS-AssignedAuthNPolicySilo). Les deux colonnes sont controlees.
# ============================================================
$tempCsv    = $env:AUDIT_TEMP_CSV
if (-not $tempCsv) { $tempCsv = Join-Path $PSScriptRoot "..\..\Temp_CSV" }
$CompSys    = Get-CimInstance Win32_ComputerSystem
$DomainName = $CompSys.Domain
$AdDir      = if ($env:AUDIT_TEMP_AD) { $env:AUDIT_TEMP_AD } else { Join-Path $tempCsv "AD" }
$ExportSilos = "$AdDir\$env:COMPUTERNAME.$DomainName" + "_Audit_Silos.csv"
$ExportPol   = "$AdDir\$env:COMPUTERNAME.$DomainName" + "_Audit_Silos_Politiques.csv"

# Duree de vie TGT au-dela de laquelle on alerte (Protected Users = 240 min)
$SeuilTgtMin = 240

$null = New-Item -ItemType Directory -Force -Path (Split-Path $ExportSilos)

if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
    Write-Host "Module ActiveDirectory introuvable - script ignore (necessite RSAT AD)." -ForegroundColor Yellow
    exit 0
}
Import-Module ActiveDirectory -ErrorAction Stop

# ─── FONCTIONS UTILITAIRES ──────────────────────────────────
function OuiNon($b) { if ($b) { "Oui" } else { "Non" } }

function Get-CnFromDn([string]$Dn) {
    if (-not $Dn) { return "" }
    return (((([regex]::Split($Dn, '(?<!\\),'))[0]) -replace '^(CN|OU)=', '') -replace '\\,', ',')
}

function Get-ParentName([string]$Dn) {
    $rdn = [regex]::Split($Dn, '(?<!\\),')
    if ($rdn.Count -lt 2) { return "" }
    return (($rdn[1] -replace '^(OU|CN|DC)=', '') -replace '\\,', ',')
}

function Convert-SidToName([string]$Sid) {
    try { return ([System.Security.Principal.SecurityIdentifier]$Sid).Translate([System.Security.Principal.NTAccount]).Value }
    catch { return $Sid }
}

# Condition "AllowedToAuthenticate" (SDDL) -> texte lisible : on garde l'expression conditionnelle
# et on remplace les SID par les noms. Accepte une chaine SDDL ou un descripteur binaire.
function Format-Condition($Valeur) {
    if (-not $Valeur) { return "" }
    $sddl = $Valeur
    if ($Valeur -is [byte[]]) {
        try { $sddl = (New-Object System.Security.AccessControl.RawSecurityDescriptor($Valeur, 0)).GetSddlForm('All') }
        catch { return "(descripteur illisible)" }
    }
    $sddl = "$sddl"
    # Extrait la condition de l'ACE conditionnelle : (XA;OICI;CR;;;WD;(<condition>))
    if ($sddl -match ';WD;\((.+)\)\)\s*$') { $sddl = "(" + $Matches[1] + ")" }
    return [regex]::Replace($sddl, 'SID\((S-1-[0-9-]+)\)', { param($m) "SID(" + (Convert-SidToName $m.Groups[1].Value) + ")" })
}

function Format-Tgt($Minutes) {
    if (-not $Minutes) { return "Defaut (strategie Kerberos)" }   # 0/vide = duree de vie de la strategie Kerberos du domaine
    return "$Minutes min"
}

function Get-TypeCompte($Obj) {
    switch ($Obj.ObjectClass) {
        "user"                            { "Utilisateur" }
        "inetOrgPerson"                   { "Utilisateur" }
        "computer"                        { "Ordinateur" }
        "msDS-GroupManagedServiceAccount" { "gMSA" }
        "msDS-ManagedServiceAccount"      { "MSA" }
        default                           { $Obj.ObjectClass }
    }
}

# Ligne silo vide - garantit le meme schema pour Export-Csv
function New-LigneSilo {
    return [ordered]@{
        Silo = ""; Mode = ""; PolitiqueUtilisateur = ""; PolitiqueOrdinateur = ""; PolitiqueService = ""
        NbComptes = ""; Compte = ""; TypeCompte = ""; OUCompte = ""; Active = ""; T0 = ""
        Autorise = ""; Assigne = ""; Description = ""; DateCreation = ""; DateModification = ""; Alerte = ""
    }
}

# ─── COLLECTE ───────────────────────────────────────────────
$ResSilos = [System.Collections.Generic.List[object]]::new()
$ResPol   = [System.Collections.Generic.List[object]]::new()

$silosDisponibles = $true
try {
    $Silos = @(Get-ADAuthenticationPolicySilo -Filter * `
               -Properties Description, whenCreated, whenChanged, 'msDS-AuthNPolicySiloMembers', 'msDS-AssignedAuthNPolicySiloBL' `
               -ErrorAction Stop | Sort-Object Name)
    $Politiques = @(Get-ADAuthenticationPolicy -Filter * -Properties *, 'msDS-AssignedAuthNPolicyBL' -ErrorAction Stop | Sort-Object Name)
} catch {
    $silosDisponibles = $false
    $Silos = @(); $Politiques = @()
    Write-Host "Silos indisponibles (niveau fonctionnel < 2012 R2 ou cmdlets absentes) : $_" -ForegroundColor Yellow
}
Write-Host "$($Silos.Count) silo(s), $($Politiques.Count) strategie(s) d'authentification."

$PolParDn = @{}
foreach ($p in $Politiques) { $PolParDn[$p.DistinguishedName] = $p }

# Cache des comptes membres (resolution DN -> objet)
$CacheComptes = @{}
function Get-Compte([string]$Dn) {
    if (-not $CacheComptes.ContainsKey($Dn)) {
        try {
            $CacheComptes[$Dn] = Get-ADObject -Identity $Dn -Properties sAMAccountName, userAccountControl, adminCount, `
                                              'msDS-AssignedAuthNPolicySilo' -ErrorAction Stop
        } catch { $CacheComptes[$Dn] = $null }
    }
    return $CacheComptes[$Dn]
}

# ─── SILOS ──────────────────────────────────────────────────
foreach ($s in $Silos) {
    try {
        $autorises = @($s.'msDS-AuthNPolicySiloMembers')
        $assignes  = @($s.'msDS-AssignedAuthNPolicySiloBL')
        $tous      = @(($autorises + $assignes) | Where-Object { $_ } | Sort-Object -Unique)

        $alertesSilo = @()
        if (-not $s.Enforce) { $alertesSilo += "Mode audit (non applique)" }
        if (-not ($s.UserAuthenticationPolicy -or $s.ComputerAuthenticationPolicy -or $s.ServiceAuthenticationPolicy)) {
            $alertesSilo += "Aucune strategie associee"
        }
        if ($tous.Count -eq 0) { $alertesSilo += "Silo vide" }

        $base = New-LigneSilo
        $base.Silo                 = $s.Name
        $base.Mode                 = if ($s.Enforce) { "Applique" } else { "Audit" }
        $base.PolitiqueUtilisateur = Get-CnFromDn "$($s.UserAuthenticationPolicy)"
        $base.PolitiqueOrdinateur  = Get-CnFromDn "$($s.ComputerAuthenticationPolicy)"
        $base.PolitiqueService     = Get-CnFromDn "$($s.ServiceAuthenticationPolicy)"
        $base.NbComptes            = $tous.Count
        $base.Description          = $s.Description
        $base.DateCreation         = $s.whenCreated
        $base.DateModification     = $s.whenChanged

        if ($tous.Count -eq 0) {
            $base.Alerte = $alertesSilo -join " | "
            $ResSilos.Add([PSCustomObject]$base)
            continue
        }

        # Tri : type puis nom
        $lignesMembres = foreach ($dn in $tous) {
            $o = Get-Compte $dn
            [PSCustomObject]@{
                Dn   = $dn
                Obj  = $o
                Nom  = if ($o -and $o.sAMAccountName) { $o.sAMAccountName } else { Get-CnFromDn $dn }
                Type = if ($o) { Get-TypeCompte $o } else { "Introuvable" }
            }
        }

        $premier = $true
        foreach ($m in ($lignesMembres | Sort-Object Type, Nom)) {
            $ligne   = if ($premier) { $base } else { New-LigneSilo }
            $alertes = @()
            if ($premier) { $alertes += $alertesSilo }

            $estAutorise = $autorises -contains $m.Dn
            $estAssigne  = $assignes  -contains $m.Dn
            if ($estAutorise -and -not $estAssigne) { $alertes += "Autorise mais non assigne : hors silo" }
            if ($estAssigne -and -not $estAutorise) { $alertes += "Assigne mais non autorise : authentification refusee" }

            $ligne.Compte     = $m.Nom
            $ligne.TypeCompte = $m.Type
            $ligne.OUCompte   = Get-ParentName $m.Dn
            if ($m.Obj) {
                $uac = [int]$m.Obj.userAccountControl
                $ligne.Active = OuiNon (-not ($uac -band 2))
                $ligne.T0     = OuiNon ($m.Obj.adminCount -eq 1)
            }
            $ligne.Autorise = OuiNon $estAutorise
            $ligne.Assigne  = OuiNon $estAssigne
            $ligne.Alerte   = $alertes -join " | "
            $ResSilos.Add([PSCustomObject]$ligne)
            $premier = $false
        }
    } catch {
        Write-Warning "Impossible de traiter le silo $($s.Name) : $_"
    }
}

if (-not $silosDisponibles) {
    $l = New-LigneSilo
    $l.Silo   = "(Silos indisponibles)"
    $l.Alerte = "Niveau fonctionnel du domaine < 2012 R2 ou cmdlets absentes"
    $ResSilos.Add([PSCustomObject]$l)
} elseif ($Silos.Count -eq 0) {
    $l = New-LigneSilo
    $l.Silo   = "(Aucun silo configure)"
    $l.Alerte = "Aucun silo d'authentification : les comptes T0 ne sont pas restreints"
    $ResSilos.Add([PSCustomObject]$l)
}

# ─── COMPTES T0 ACTIFS HORS SILO ────────────────────────────
# adminCount=1, actif, sans silo assigne (ou assigne a un silo qui ne l'autorise pas)
$Silo_Autorises = @{}
foreach ($s in $Silos) { $Silo_Autorises[$s.DistinguishedName] = @($s.'msDS-AuthNPolicySiloMembers') }

$T0 = @(Get-ADObject -LDAPFilter "(&(adminCount=1)(objectClass=user)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))" `
        -Properties sAMAccountName, 'msDS-AssignedAuthNPolicySilo' -ErrorAction SilentlyContinue |
        Where-Object {
            $siloDn = $_.'msDS-AssignedAuthNPolicySilo'
            -not $siloDn -or -not ($Silo_Autorises.ContainsKey($siloDn) -and $Silo_Autorises[$siloDn] -contains $_.DistinguishedName)
        } | Sort-Object sAMAccountName)

$premier = $true
foreach ($o in $T0) {
    $ligne = New-LigneSilo
    if ($premier) {
        $ligne.Silo      = "(Aucun silo)"
        $ligne.NbComptes = $T0.Count
        $premier = $false
    }
    $ligne.Compte     = $o.sAMAccountName
    $ligne.TypeCompte = Get-TypeCompte $o
    $ligne.OUCompte   = Get-ParentName $o.DistinguishedName
    $ligne.Active     = "Oui"
    $ligne.T0         = "Oui"
    $ligne.Autorise   = "Non"
    $ligne.Assigne    = OuiNon ([bool]$o.'msDS-AssignedAuthNPolicySilo')
    $ligne.Alerte     = "Compte T0 hors silo"
    $ResSilos.Add([PSCustomObject]$ligne)
}

# ─── STRATEGIES D'AUTHENTIFICATION ──────────────────────────
foreach ($p in $Politiques) {
    try {
        $dn = $p.DistinguishedName
        $silosUtilisant = @($Silos | Where-Object {
            "$($_.UserAuthenticationPolicy)" -eq $dn -or "$($_.ComputerAuthenticationPolicy)" -eq $dn -or "$($_.ServiceAuthenticationPolicy)" -eq $dn
        } | ForEach-Object { $_.Name })
        $assignesDirect = @($p.'msDS-AssignedAuthNPolicyBL' | Where-Object { $_ } | ForEach-Object {
            $o = Get-Compte $_
            if ($o -and $o.sAMAccountName) { $o.sAMAccountName } else { Get-CnFromDn $_ }
        } | Sort-Object)

        $condUserFrom = Format-Condition $p.UserAllowedToAuthenticateFrom

        $alertes = @()
        if (-not $p.Enforce) { $alertes += "Mode audit (non applique)" }
        if ($silosUtilisant.Count -eq 0 -and $assignesDirect.Count -eq 0) { $alertes += "Strategie non utilisee" }
        if ($silosUtilisant.Count -gt 0 -and -not $condUserFrom) { $alertes += "Aucune restriction d'origine pour les utilisateurs" }
        if ($p.UserTGTLifetimeMins -gt $SeuilTgtMin) { $alertes += "TGT utilisateur > $SeuilTgtMin min" }

        $ResPol.Add([PSCustomObject][ordered]@{
            Politique                  = $p.Name
            Mode                       = if ($p.Enforce) { "Applique" } else { "Audit" }
            TGTUtilisateur             = Format-Tgt $p.UserTGTLifetimeMins
            UtilisateurDepuis          = $condUserFrom
            UtilisateurVers            = Format-Condition $p.UserAllowedToAuthenticateTo
            TGTOrdinateur              = Format-Tgt $p.ComputerTGTLifetimeMins
            OrdinateurVers             = Format-Condition $p.ComputerAllowedToAuthenticateTo
            TGTService                 = Format-Tgt $p.ServiceTGTLifetimeMins
            ServiceDepuis              = Format-Condition $p.ServiceAllowedToAuthenticateFrom
            ServiceVers                = Format-Condition $p.ServiceAllowedToAuthenticateTo
            SilosUtilisant             = $silosUtilisant -join " - "
            ComptesAssignesDirectement = $assignesDirect -join " - "
            Description                = $p.Description
            DateCreation               = $p.whenCreated
            DateModification           = $p.whenChanged
            Alerte                     = $alertes -join " | "
        })
    } catch {
        Write-Warning "Impossible de traiter la strategie $($p.Name) : $_"
    }
}

Write-Host "$($ResSilos.Count) ligne(s) silos (dont $($T0.Count) compte(s) T0 hors silo), $($ResPol.Count) strategie(s)"
$ResSilos | Export-Csv -Path $ExportSilos -NoTypeInformation -Encoding UTF8
if ($ResPol.Count -gt 0) {
    $ResPol | Export-Csv -Path $ExportPol -NoTypeInformation -Encoding UTF8
    Write-Host "Rapports generes : $ExportSilos"
    Write-Host "                   $ExportPol"
} else {
    Write-Host "Rapport genere : $ExportSilos (aucune strategie d'authentification)"
}