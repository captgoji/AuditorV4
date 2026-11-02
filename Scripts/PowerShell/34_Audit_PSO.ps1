# 14_Audit_PSO.ps1
# Version      : 1.1
# Derniere modif : Sorties dans Temp_CSV\AD
# Role         : Audit des strategies de mot de passe affinees (PSO / Fine-Grained Password Policies)
#                + politique par defaut du domaine, cibles des PSO, politique effective par compte
# Usage        : Lance via main.ps1 ou directement. Necessite RSAT AD (DC ou membre de domaine).
# Sorties      : <HOST>_Audit_PSO.csv         : une ligne par cible de PSO (infos PSO sur la 1re ligne)
#                <HOST>_Audit_PSO_Comptes.csv : une ligne par compte utilisateur avec sa politique effective
# ============================================================
$tempCsv    = $env:AUDIT_TEMP_CSV
if (-not $tempCsv) { $tempCsv = Join-Path $PSScriptRoot "..\..\Temp_CSV" }
$CompSys    = Get-CimInstance Win32_ComputerSystem
$DomainName = $CompSys.Domain
$AdDir      = if ($env:AUDIT_TEMP_AD) { $env:AUDIT_TEMP_AD } else { Join-Path $tempCsv "AD" }
$ExportPso     = "$AdDir\$env:COMPUTERNAME.$DomainName" + "_Audit_PSO.csv"
$ExportComptes = "$AdDir\$env:COMPUTERNAME.$DomainName" + "_Audit_PSO_Comptes.csv"

# Seuils d'alerte (a ajuster selon le referentiel de l'audit)
$SeuilLongueurMin = 12
$SeuilHistorique  = 12

$null = New-Item -ItemType Directory -Force -Path (Split-Path $ExportPso)

if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
    Write-Host "Module ActiveDirectory introuvable - script ignore (necessite RSAT AD)." -ForegroundColor Yellow
    exit 0
}
Import-Module ActiveDirectory -ErrorAction Stop

$NomDefaut = "Politique par defaut du domaine"

# ─── FONCTIONS UTILITAIRES ──────────────────────────────────
function OuiNon($b) { if ($b) { "Oui" } else { "Non" } }

# TimeSpan -> texte lisible ("42 j", "30 min", "1 h 30 min"). $Zero = libelle pour une duree nulle/illimitee
function Format-Duree($Ts, [string]$Zero) {
    if ($null -eq $Ts) { return "" }
    if ($Ts.Ticks -le 0 -or $Ts.TotalDays -gt 36500) { return $Zero }
    $parts = @()
    if ($Ts.Days    -gt 0) { $parts += "$($Ts.Days) j" }
    if ($Ts.Hours   -gt 0) { $parts += "$($Ts.Hours) h" }
    if ($Ts.Minutes -gt 0) { $parts += "$($Ts.Minutes) min" }
    if ($parts.Count -eq 0) { $parts += "$([int]$Ts.TotalSeconds) s" }
    return ($parts -join " ")
}

# Echappement d'une valeur pour un filtre LDAP (RFC 4515)
function ConvertTo-LdapFilterValue([string]$V) {
    return ($V -replace '\\', '\5c' -replace '\*', '\2a' -replace '\(', '\28' -replace '\)', '\29')
}

function Get-ParentName([string]$Dn) {
    $rdn = [regex]::Split($Dn, '(?<!\\),')
    if ($rdn.Count -lt 2) { return "" }
    return (($rdn[1] -replace '^(OU|CN|DC)=', '') -replace '\\,', ',')
}

# Alertes sur les reglages d'une politique (PSO ou politique par defaut)
function Get-AlertesPolitique($P) {
    $a = @()
    if ($P.MinPasswordLength -lt $SeuilLongueurMin) { $a += "Longueur < $SeuilLongueurMin" }
    if (-not $P.ComplexityEnabled)                   { $a += "Complexite desactivee" }
    if ($P.ReversibleEncryptionEnabled)              { $a += "Chiffrement reversible" }
    if ($P.PasswordHistoryCount -lt $SeuilHistorique) { $a += "Historique < $SeuilHistorique" }
    if ($P.LockoutThreshold -eq 0)                   { $a += "Pas de verrouillage" }
    if ($P.MaxPasswordAge -and $P.MaxPasswordAge.Ticks -le 0) { $a += "Pas d'expiration" }
    return $a
}

# Ligne PSO vide (toutes les colonnes) - garantit le meme schema pour Export-Csv
function New-LignePso {
    return [ordered]@{
        PSO = ""; Precedence = ""; LongueurMin = ""; Historique = ""; Complexite = ""
        ChiffrementReversible = ""; AgeMin = ""; AgeMax = ""; SeuilVerrouillage = ""
        DureeVerrouillage = ""; FenetreObservation = ""; NbComptesEffectifs = ""
        Cible = ""; TypeCible = ""; OUCible = ""; NbComptesCible = ""
        Description = ""; DateCreation = ""; DateModification = ""; Alerte = ""
    }
}

function Set-Reglages($Ligne, $P) {
    $Ligne.LongueurMin           = $P.MinPasswordLength
    $Ligne.Historique            = $P.PasswordHistoryCount
    $Ligne.Complexite            = OuiNon $P.ComplexityEnabled
    $Ligne.ChiffrementReversible = OuiNon $P.ReversibleEncryptionEnabled
    $Ligne.AgeMin                = Format-Duree $P.MinPasswordAge "Aucun"
    $Ligne.AgeMax                = Format-Duree $P.MaxPasswordAge "Jamais"
    $Ligne.SeuilVerrouillage     = if ($P.LockoutThreshold -eq 0) { "Aucun" } else { $P.LockoutThreshold }
    $Ligne.DureeVerrouillage     = Format-Duree $P.LockoutDuration "Deverrouillage manuel"
    $Ligne.FenetreObservation    = Format-Duree $P.LockoutObservationWindow ""
}

# ─── COLLECTE ───────────────────────────────────────────────
$Defaut = Get-ADDefaultDomainPasswordPolicy -ErrorAction Stop
$Psos   = @(Get-ADFineGrainedPasswordPolicy -Filter * -Properties Description, whenCreated, whenChanged `
            -ErrorAction SilentlyContinue | Sort-Object Precedence, Name)
Write-Host "$($Psos.Count) PSO trouvee(s)."

# msDS-ResultantPSO : attribut construit par le DC = PSO effective du compte (vide = politique par defaut)
$Users = Get-ADUser -Filter * -Properties 'msDS-ResultantPSO', adminCount, Enabled, DisplayName -ErrorAction Stop
$EffectifsParPso = @{}
foreach ($u in $Users) {
    $cle = if ($u.'msDS-ResultantPSO') { $u.'msDS-ResultantPSO' } else { $NomDefaut }
    if (-not $EffectifsParPso.ContainsKey($cle)) { $EffectifsParPso[$cle] = 0 }
    $EffectifsParPso[$cle]++
}

$PsoParDn = @{}
foreach ($p in $Psos) { $PsoParDn[$p.DistinguishedName] = $p }

# Precedences en doublon : comportement non deterministe (departage par GUID)
$Doublons = @($Psos | Group-Object Precedence | Where-Object Count -gt 1 | ForEach-Object { [int]$_.Name })

$ResPso = [System.Collections.Generic.List[object]]::new()

# Ligne de reference : politique par defaut du domaine
$l = New-LignePso
$l.PSO                = $NomDefaut
$l.Precedence         = "-"
Set-Reglages $l $Defaut
$l.NbComptesEffectifs = [int]$EffectifsParPso[$NomDefaut]
$l.Cible              = "Comptes sans PSO"
$l.TypeCible          = "Domaine"
$l.Alerte             = (Get-AlertesPolitique $Defaut) -join " | "
$ResPso.Add([PSCustomObject]$l)

foreach ($p in $Psos) {
    try {
        $alertesPso = @(Get-AlertesPolitique $p)
        if ($Doublons -contains [int]$p.Precedence) { $alertesPso += "Precedence en doublon" }
        $cibles = @($p.AppliesTo)
        if ($cibles.Count -eq 0) { $alertesPso += "Aucune cible" }

        $base = New-LignePso
        $base.PSO                = $p.Name
        $base.Precedence         = $p.Precedence
        Set-Reglages $base $p
        $base.NbComptesEffectifs = [int]$EffectifsParPso[$p.DistinguishedName]
        $base.Description        = $p.Description
        $base.DateCreation       = $p.whenCreated
        $base.DateModification   = $p.whenChanged

        if ($cibles.Count -eq 0) {
            $base.Alerte = $alertesPso -join " | "
            $ResPso.Add([PSCustomObject]$base)
            continue
        }

        $premier = $true
        foreach ($dn in ($cibles | Sort-Object)) {
            $ligne = if ($premier) { $base } else { New-LignePso }
            $alertesCible = @()
            if ($premier) { $alertesCible += $alertesPso }

            try {
                $obj = Get-ADObject -Identity $dn -Properties sAMAccountName, groupType -ErrorAction Stop
                $ligne.Cible   = if ($obj.sAMAccountName) { $obj.sAMAccountName } else { $obj.Name }
                $ligne.OUCible = Get-ParentName $dn

                if ($obj.ObjectClass -eq 'group') {
                    # groupType : 0x2 = global, 0x4 = domaine local, 0x8 = universel, 0x80000000 = securite
                    $gt      = [int64]$obj.groupType
                    $securite = ($gt -band 0x80000000) -ne 0
                    $portee  = if ($gt -band 0x2) { "globale" } elseif ($gt -band 0x4) { "domaine local" } elseif ($gt -band 0x8) { "universelle" } else { "?" }
                    $ligne.TypeCible = "Groupe $portee" + $(if ($securite) { "" } else { " (distribution)" })
                    # Une PSO ne s'applique qu'aux groupes de securite GLOBAUX
                    if (-not $securite)          { $alertesCible += "Groupe de distribution : PSO ignoree" }
                    elseif ($portee -ne "globale") { $alertesCible += "Groupe non global : PSO ignoree" }

                    # Membres utilisateurs (recursif, hors groupe principal)
                    $n = @(Get-ADUser -LDAPFilter "(memberOf:1.2.840.113556.1.4.1941:=$(ConvertTo-LdapFilterValue $dn))" -ErrorAction SilentlyContinue).Count
                    $ligne.NbComptesCible = $n
                    if ($n -eq 0) { $alertesCible += "Groupe cible sans utilisateur" }
                } elseif ($obj.ObjectClass -in @('user', 'inetOrgPerson')) {
                    $ligne.TypeCible      = "Utilisateur"
                    $ligne.NbComptesCible = 1
                } else {
                    $ligne.TypeCible = $obj.ObjectClass
                    $alertesCible += "Type de cible non supporte : PSO ignoree"
                }
            } catch {
                $ligne.Cible     = (([regex]::Split($dn, '(?<!\\),'))[0] -replace '^CN=', '')
                $ligne.TypeCible = "Introuvable"
                $alertesCible += "Cible introuvable"
            }

            $ligne.Alerte = $alertesCible -join " | "
            $ResPso.Add([PSCustomObject]$ligne)
            $premier = $false
        }
    } catch {
        Write-Warning "Impossible de traiter la PSO $($p.Name) : $_"
    }
}

# ─── POLITIQUE EFFECTIVE PAR COMPTE ─────────────────────────
$ResComptes = [System.Collections.Generic.List[object]]::new()
foreach ($u in ($Users | Sort-Object SamAccountName)) {
    $dnPso = $u.'msDS-ResultantPSO'
    $pol   = if ($dnPso -and $PsoParDn.ContainsKey($dnPso)) { $PsoParDn[$dnPso] } else { $null }
    $estT0 = $u.adminCount -eq 1

    $alertes = @()
    if ($estT0 -and -not $dnPso) { $alertes += "Compte T0 sans PSO" }

    $ResComptes.Add([PSCustomObject][ordered]@{
        Compte             = $u.SamAccountName
        NomAffiche         = $u.DisplayName
        OU                 = Get-ParentName $u.DistinguishedName
        Active             = OuiNon $u.Enabled
        T0                 = OuiNon $estT0
        PolitiqueEffective = if ($pol) { $pol.Name } elseif ($dnPso) { "PSO illisible" } else { $NomDefaut }
        Precedence         = if ($pol) { $pol.Precedence } else { "-" }
        LongueurMin        = if ($pol) { $pol.MinPasswordLength } else { $Defaut.MinPasswordLength }
        Alerte             = $alertes -join " | "
    })
}

Write-Host "$($ResPso.Count) ligne(s) PSO, $($ResComptes.Count) compte(s)"
$ResPso     | Export-Csv -Path $ExportPso     -NoTypeInformation -Encoding UTF8
$ResComptes | Export-Csv -Path $ExportComptes -NoTypeInformation -Encoding UTF8
Write-Host "Rapports generes : $ExportPso"
Write-Host "                   $ExportComptes"