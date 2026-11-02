# 11_Audit_comptes.ps1
# Version      : 2.0
# Derniere modif : Colonne DerniereConnexion (lastLogonTimestamp replique, precision ~14 j ;
#                  LastLogon pour les comptes locaux)
# Role         : Audit tous les comptes AD hors T0, ou comptes locaux sur machine standalone
# Usage        : Lance via main.ps1 ou directement. Necessite RSAT AD sur DC.
# ============================================================
$tempCsv    = $env:AUDIT_TEMP_CSV
$CompSys    = Get-CimInstance Win32_ComputerSystem
$DomainName = $CompSys.Domain
$ExportFile = "$tempCsv\Comptes\$env:COMPUTERNAME.$DomainName" + "_Audit_comptes.csv"
$Results    = @()

$null = New-Item -ItemType Directory -Force -Path (Split-Path $ExportFile)

$IsADDSInstalled = (Get-WindowsFeature -Name AD-Domain-Services).InstallState -eq 'Installed'

if ($IsADDSInstalled) {
    # On demande les proprietes natives calculees par le module AD (Enabled, PasswordNeverExpires...)
    # plutot que de decoder userAccountControl a la main (peu fiable sur -Filter *)
    $Users = Get-ADUser -Filter * `
             -Properties Enabled, userAccountControl, adminCount, Description, `
                         PasswordLastSet, MemberOf, PasswordNeverExpires, `
                         PasswordNotRequired, CannotChangePassword, PasswordExpired, `
                         Created, Modified, LastLogonDate `
             -ErrorAction SilentlyContinue

    # Recuperer services et taches UNE SEULE FOIS (pas dans la boucle - perf)
    $tousServices = Get-CimInstance Win32_Service -ErrorAction SilentlyContinue
    $toutesTaches = Get-ScheduledTask -ErrorAction SilentlyContinue

    foreach ($ADUser in $Users) {
        # Exclure les comptes T0 (adminCount=1) - deja traites par 10_Audit_comptes_T0.ps1
        # adminCount est NULL pour les users normaux - ne pas tester -eq 0 car NULL != 0
        if ($ADUser.adminCount -eq 1) { continue }

        try {
            $GroupsAD = ($ADUser.MemberOf | ForEach-Object {
                ($_ -split ",")[0] -replace "CN=", ""
            }) -join " - "

            # Matching robuste : comparer le nom de compte (apres DOMAINE\) en exact, insensible casse
            $sam = $ADUser.SamAccountName
            $DomServiceList = ($tousServices |
                Where-Object {
                    $_.StartName -and (($_.StartName -split '\\')[-1]) -ieq $sam
                } | ForEach-Object { $_.Name }) -join " - "

            $DomTaskList = ($toutesTaches |
                Where-Object {
                    $_.Principal.UserId -and (($_.Principal.UserId -split '\\')[-1]) -ieq $sam
                } | ForEach-Object { $_.TaskName }) -join " - "

            # Detection Active : .Enabled natif, avec repli sur userAccountControl (bit 2 = ACCOUNTDISABLE)
            $uac = $ADUser.userAccountControl
            if ($null -ne $ADUser.Enabled) {
                $IsEnabled = $ADUser.Enabled
            } else {
                $IsEnabled = -not [bool]($uac -band 2)
            }

            # Reglage du mot de passe : proprietes natives + repli sur les bits userAccountControl
            #   0x10000 = DONT_EXPIRE_PASSWORD | 0x0020 = PASSWD_NOTREQD | 0x0040 = PASSWD_CANT_CHANGE
            $reglagesMdp = @()
            if ($ADUser.PasswordNeverExpires -or ($null -ne $uac -and ($uac -band 0x10000))) { $reglagesMdp += "N'expire jamais" }
            if ($ADUser.PasswordNotRequired  -or ($null -ne $uac -and ($uac -band 0x0020)))  { $reglagesMdp += "Non requis" }
            if ($ADUser.CannotChangePassword -or ($null -ne $uac -and ($uac -band 0x0040)))  { $reglagesMdp += "Ne peut pas changer" }
            if ($ADUser.PasswordExpired) { $reglagesMdp += "Expire" }
            $reglageMdpTexte = if ($reglagesMdp.Count -gt 0) { ($reglagesMdp | Select-Object -Unique) -join " | " } else { "Standard" }

            # Date de desactivation : approximation via Modified (AD ne stocke pas la vraie date)
            $dateDesactivation = if ($IsEnabled -eq $false) { $ADUser.Modified } else { "" }

            # Conversion booleen -> Oui/Non pour l'affichage
            $ActiveTexte = if ($IsEnabled) { "Oui" } else { "Non" }

            $Results += [PSCustomObject]@{
                Ordinateur         = "$env:COMPUTERNAME.$DomainName"
                Name               = $ADUser.SamAccountName
                Type               = "Compte domaine"
                DateCreation       = $ADUser.Created
                Active             = $ActiveTexte
                ReglageMdp         = $reglageMdpTexte
                DateDesactivation  = $dateDesactivation
                Description        = $ADUser.Description
                PasswordLastSet    = $ADUser.PasswordLastSet
                DerniereConnexion  = $ADUser.LastLogonDate
                Groupes            = $GroupsAD
                Services           = $DomServiceList
                ScheduledTask      = $DomTaskList
            }
        } catch {
            Write-Warning "Impossible de traiter le compte $($ADUser.SamAccountName) : $_"
        }
    }
} else {
    $LocalUsers = Get-LocalUser

    foreach ($User in $LocalUsers) {
        $Groups = (Get-LocalGroup | ForEach-Object {
            try {
                if (Get-LocalGroupMember $_.Name -Member $User.Name -ErrorAction SilentlyContinue) {
                    $_.Name
                }
            } catch {}
        }) -join " - "

        $ServiceList = (Get-CimInstance Win32_Service |
            Where-Object { $_.StartName -match $User.Name } |
            ForEach-Object { $_.Name }) -join " - "

        $TaskList = (Get-ScheduledTask |
            Where-Object { $_.Principal.UserId -match $User.Name } |
            ForEach-Object { $_.TaskName }) -join " - "

        # Reglage MDP pour comptes locaux
        $reglagesMdp = @()
        if ($null -eq $User.PasswordExpires -and $User.Enabled) { $reglagesMdp += "N'expire jamais" }
        if ($false -eq $User.UserMayChangePassword)             { $reglagesMdp += "Ne peut pas changer" }
        $reglageMdpTexte = if ($reglagesMdp.Count -gt 0) { $reglagesMdp -join " | " } else { "Standard" }

        $dateDesactivation = if (-not $User.Enabled) { $User.PasswordLastSet } else { "" }
        $ActiveTexte = if ($User.Enabled) { "Oui" } else { "Non" }

        $Results += [PSCustomObject]@{
            Ordinateur         = "$env:COMPUTERNAME.$DomainName"
            Name               = $User.Name
            Type               = "Compte local"
            DateCreation       = ""
            Active             = $ActiveTexte
            ReglageMdp         = $reglageMdpTexte
            DateDesactivation  = $dateDesactivation
            Description        = $User.Description
            PasswordLastSet    = $User.PasswordLastSet
            DerniereConnexion  = $User.LastLogon
            Groupes            = $Groups
            Services           = $ServiceList
            ScheduledTask      = $TaskList
        }
    }
}

Write-Host "$($Results.Count) compte(s) collecte(s)"
$Results | Export-Csv -Path $ExportFile -NoTypeInformation -Encoding UTF8
Write-Host "Rapport genere : $ExportFile"