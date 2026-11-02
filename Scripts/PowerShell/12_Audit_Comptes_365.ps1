# 12_Audit_Comptes_365.ps1
# Version      : 1.2
# Derniere modif : Ajout header standard
# Role         : Audit comptes Microsoft 365 : licences, connexions, MDP via Microsoft Graph API
# Usage        : Lance via main.ps1. Necessite Microsoft.Graph installe et Connect-MgGraph.
# ============================================================
Connect-MgGraph

$thresholdDate = (Get-Date).AddMonths(-6)
$skus = Get-MgSubscribedSku -All
$skuTable = @{}
$servicePlanTable = @{}

foreach ($sku in $skus) {
    $skuId = $sku.SkuId.ToString()
    if (-not $skuTable.ContainsKey($skuId)) {
        $skuTable[$skuId] = $sku.SkuPartNumber
    }

    foreach ($sp in $sku.ServicePlans) {
        $spId = $sp.ServicePlanId.ToString()
        if (-not $servicePlanTable.ContainsKey($spId)) {
            $servicePlanTable[$spId] = [PSCustomObject]@{
                ServicePlanName = $sp.ServicePlanName
                SkuPartNumber   = $sku.SkuPartNumber
            }
        }
    }
}

$users = Get-MgUser -All -Property "id,displayName,givenName,surname,userPrincipalName,createdDateTime,assignedLicenses,assignedPlans,signInActivity,lastPasswordChangeDateTime"

$report = foreach ($u in $users) {
    $licenceNames = @()
    foreach ($lic in $u.AssignedLicenses) {
        $skuId = $lic.SkuId.ToString()
        if ($skuTable.ContainsKey($skuId)) {
            $licenceNames += $skuTable[$skuId]
        } else {
            $licenceNames += $skuId
        }
    }
    $licenceList = ($licenceNames | Sort-Object -Unique) -join ", "

    $enabledPlans = $u.AssignedPlans | Where-Object { $_.CapabilityStatus -eq "Enabled" }

    $apps = foreach ($plan in $enabledPlans) {
        $spId = $plan.ServicePlanId.ToString()
        if ($servicePlanTable.ContainsKey($spId)) {
            $info = $servicePlanTable[$spId]
            "$($info.ServicePlanName) [$($info.SkuPartNumber)]"
        } else {
            $spId
        }
    }
    $appsList = ($apps | Sort-Object -Unique) -join "; "

    $lastPwdChange = if ($u.LastPasswordChangeDateTime) {
        [datetime]$u.LastPasswordChangeDateTime
    } else { $null }

    $pwdOlderThan6M = if ($lastPwdChange) {
        ($lastPwdChange -lt $thresholdDate)
    } else { $null }

    $neverConnected = $false
    $lastSignIn = $null

    if ($u.SignInActivity -and $u.SignInActivity.LastSignInDateTime) {
        $lastSignIn = [datetime]$u.SignInActivity.LastSignInDateTime
    }
    else {
        $neverConnected = $true
    }

    if ($neverConnected -eq $true) {
        $signInOlderThan6M = $true
    }
    else {
        $signInOlderThan6M = ($lastSignIn -lt $thresholdDate)
    }

    [PSCustomObject]@{
        GivenName                = $u.GivenName
        Surname                  = $u.Surname
        UserPrincipalName        = $u.UserPrincipalName
        AccountCreatedDate       = [datetime]$u.CreatedDateTime
        Licences                 = $licenceList
        LastPasswordChangeDate   = $lastPwdChange
        PasswordOlderThan6Months = $pwdOlderThan6M
        LastSignInDate           = $lastSignIn
        NeverConnected           = $neverConnected
        SignInOlderThan6Months   = $signInOlderThan6M
        EnabledAppsFromLicences  = $appsList
    }
}

$tempCsv = $env:AUDIT_TEMP_CSV
$CompSys = Get-CimInstance Win32_ComputerSystem
$DomainName = $CompSys.Domain
$ExportFile = "$tempCsv\Comptes\$env:COMPUTERNAME.$DomainName" + "_Audit_Comptes_365.csv"
$null = New-Item -ItemType Directory -Force -Path (Split-Path $ExportFile)

$report | Export-Csv -Path $ExportFile -NoTypeInformation -Encoding UTF8
Write-Host "Export termine : $ExportFile"