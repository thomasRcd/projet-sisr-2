# ================= VARIABLES =================

$domainDN = "DC=tls,DC=vitabigpharma,DC=local"
$baseOU   = "OU=Collab,$domainDN"
$csvPath  = "C:\ton_chemin\users.csv"
$logFile  = "$env:USERPROFILE\Desktop\log_ad.txt"
$report   = "$env:USERPROFILE\Desktop\report_users.csv"

$DryRun = $false   # TRUE = simulation

# ================= FONCTIONS =================

function Write-MyLog ($msg) {
    $line = "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') : $msg"
    Write-Host $line
    $line | Out-File $logFile -Append -Encoding UTF8
}

# Enlever accents
function Remove-Accents($text) {
    $normalized = $text.Normalize([Text.NormalizationForm]::FormD)
    return ($normalized -replace '\p{Mn}', '')
}

# Générer mot de passe
function New-RandomPassword {
    return [System.Web.Security.Membership]::GeneratePassword(12,2)
}

# Générer samAccountName unique
function Get-UniqueSam($prenom,$nom) {
    $base = (Remove-Accents("$prenom.$nom")).ToLower() -replace " ", ""
    $sam = $base
    $i = 1

    while (Get-ADUser -Filter "SamAccountName -eq '$sam'" -ErrorAction SilentlyContinue) {
        $sam = "$base$i"
        $i++
    }
    return $sam
}

# ================= STRUCTURE OU =================

if (-not (Get-ADOrganizationalUnit -LDAPFilter "(distinguishedName=$baseOU)" -ErrorAction SilentlyContinue)) {
    if (!$DryRun) { New-ADOrganizationalUnit -Name "Collab" -Path $domainDN }
    Write-MyLog "OU Collab créée"
}

foreach ($ou in @("Users","Ordinateurs","Groupes")) {
    $target = "OU=$ou,$baseOU"
    if (-not (Get-ADOrganizationalUnit -LDAPFilter "(distinguishedName=$target)" -ErrorAction SilentlyContinue)) {
        if (!$DryRun) { New-ADOrganizationalUnit -Name $ou -Path $baseOU }
        Write-MyLog "OU $ou créée"
    }
}

# ================= IMPORT CSV =================

$users = Import-Csv $csvPath -Delimiter ","
$reportData = @()

foreach ($u in $users) {

    $sam = Get-UniqueSam $u.Prenom $u.Nom
    $pwdPlain = "VitaBigPharma2026!"
    $pwd = ConvertTo-SecureString $pwdPlain -AsPlainText -Force

    # OU par service
    $serviceOU = "OU=$($u.Service),OU=Users,$baseOU"

    if (-not (Get-ADOrganizationalUnit -LDAPFilter "(ou=$($u.Service))" -SearchBase "OU=Users,$baseOU" -ErrorAction SilentlyContinue)) {
        if (!$DryRun) { New-ADOrganizationalUnit -Name $u.Service -Path "OU=Users,$baseOU" }
        Write-MyLog "OU service créée : $($u.Service)"
    }

    try {
        if (!$DryRun) {
            New-ADUser `
                -Name "$($u.Prenom) $($u.Nom)" `
                -GivenName $u.Prenom `
                -Surname $u.Nom `
                -SamAccountName $sam `
                -UserPrincipalName $u.Email `
                -Path $serviceOU `
                -AccountPassword $pwd `
                -Enabled $true `
                -ChangePasswordAtLogon $true
        }

        Write-MyLog "User créé : $sam"

        # Groupe
        if (-not (Get-ADGroup -Filter "Name -eq '$($u.Groupe)'" -ErrorAction SilentlyContinue)) {
            if (!$DryRun) {
                New-ADGroup -Name $u.Groupe -GroupScope Global -GroupCategory Security -Path "OU=Groupes,$baseOU"
            }
            Write-MyLog "Groupe créé : $($u.Groupe)"
        }

        if (!$DryRun) {
            Add-ADGroupMember -Identity $u.Groupe -Members $sam
        }
        Write-MyLog "$sam ajouté à $($u.Groupe)"

        # Rapport
        $reportData += [PSCustomObject]@{
            Prenom = $u.Prenom
            Nom = $u.Nom
            SamAccountName = $sam
            Email = $u.Email
            Service = $u.Service
            Groupe = $u.Groupe
            Password = $pwdPlain
        }
    }
    catch {
        Write-MyLog "ERREUR $sam : $($_.Exception.Message)"
    }
}

# Export rapport
$reportData | Export-Csv $report -NoTypeInformation -Encoding UTF8
Write-MyLog "Rapport exporté : $report"


