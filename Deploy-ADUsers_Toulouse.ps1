
# =========================
# Déploiement AD - Toulouse
# OU / Groupes / Utilisateurs (métiers) + affectations
# Domaine : tls.vitabigpharma.local
# =========================

Import-Module ActiveDirectory

# ---- Paramètres
$DomainDN = (Get-ADDomain).DistinguishedName
$SiteOUName = "Toulouse"

# OU
$OU_Root      = "OU=$SiteOUName,$DomainDN"
$OU_Users     = "OU=Utilisateurs,$OU_Root"
$OU_Groups    = "OU=Groupes,$OU_Root"

# Groupes métiers (Toulouse = Direction / RH / Finance + ERP Dolibarr)
$BusinessGroups = @(
    "TLS-DIRECTION",
    "TLS-RH",
    "TLS-FINANCE",
    "TLS-DOLIBARR-USERS",
    "TLS-DOLIBARR-ADMINS"
)

# Chemins fichiers
$CsvPath = ".\users_tls.csv"
$LogPath = ".\deploy_log_tls.txt"

# ---- Fonctions
function Ensure-OU {
    param([string]$OuDn, [string]$OuName, [string]$ParentDn)

    if (-not (Get-ADOrganizationalUnit -LDAPFilter "(distinguishedName=$OuDn)" -ErrorAction SilentlyContinue)) {
        New-ADOrganizationalUnit -Name $OuName -Path $ParentDn -ProtectedFromAccidentalDeletion $true
        Add-Content $LogPath "OU créée : $OuDn"
    }
}

function Ensure-Group {
    param([string]$GroupName, [string]$PathDn)

    if (-not (Get-ADGroup -Filter "Name -eq '$GroupName'" -ErrorAction SilentlyContinue)) {
        New-ADGroup -Name $GroupName -GroupScope Global -GroupCategory Security -Path $PathDn
        Add-Content $LogPath "Groupe créé : $GroupName"
    }
}

# ---- Début script
"==== Déploiement Toulouse - $(Get-Date) ====" | Out-File $LogPath

# Vérifie que le CSV existe
if (-not (Test-Path $CsvPath)) {
    Add-Content $LogPath "ERREUR : CSV introuvable ($CsvPath)"
    Write-Host "ERREUR : CSV introuvable ($CsvPath)" -ForegroundColor Red
    exit
}

# 1) Création arborescence OU
Ensure-OU -OuDn $OU_Root   -OuName $SiteOUName    -ParentDn $DomainDN
Ensure-OU -OuDn $OU_Users  -OuName "Utilisateurs" -ParentDn $OU_Root
Ensure-OU -OuDn $OU_Groups -OuName "Groupes"      -ParentDn $OU_Root

# 2) Création des groupes métiers
foreach ($g in $BusinessGroups){ Ensure-Group -GroupName $g -PathDn $OU_Groups }

# 3) Import CSV + création utilisateurs
# CSV attendu : Prenom,Nom,Service,Role,Mail,Password
# Service : Direction | RH | Finance
# Role    : User | DolibarrAdmin (optionnel)
$users = Import-Csv $CsvPath

foreach ($u in $users) {

    $Prenom  = $u.Prenom.Trim()
    $Nom     = $u.Nom.Trim()
    $Service = $u.Service.Trim()
    $Role    = $u.Role.Trim()
    $Mail    = $u.Mail.Trim()
    $Pwd     = $u.Password

    # Login automatique : prenom.nom
    $Login = ($Prenom + "." + $Nom).ToLower()
    $Sam   = $Login

    $DisplayName = "$Prenom $Nom"
    $UPN = "$Login@tls.vitabigpharma.local"

    # Vérifie si existe déjà
    $exists = Get-ADUser -Filter "SamAccountName -eq '$Sam'" -ErrorAction SilentlyContinue
    if ($exists) {
        Add-Content $LogPath "Utilisateur déjà existant : $Sam"
        continue
    }

    try {
        # Création user
        New-ADUser `
            -Name $DisplayName `
            -GivenName $Prenom `
            -Surname $Nom `
            -DisplayName $DisplayName `
            -SamAccountName $Sam `
            -UserPrincipalName $UPN `
            -EmailAddress $Mail `
            -Path $OU_Users `
            -AccountPassword (ConvertTo-SecureString $Pwd -AsPlainText -Force) `
            -Enabled $true `
            -ChangePasswordAtLogon $true

        Add-Content $LogPath "Utilisateur créé : $Sam ($Service / $Role)"

        # Ajout groupe métier (selon Service)
        $ServiceUpper = $Service.ToUpper()
        if ($ServiceUpper -in @("DIRECTION","RH","FINANCE")) {
            $GroupService = "TLS-" + $ServiceUpper
            Add-ADGroupMember -Identity $GroupService -Members $Sam
        }

        # Ajout aux groupes Dolibarr (ERP Toulouse)
        Add-ADGroupMember -Identity "TLS-DOLIBARR-USERS" -Members $Sam

        if ($Role.ToLower() -eq "dolibarradmin") {
            Add-ADGroupMember -Identity "TLS-DOLIBARR-ADMINS" -Members $Sam
        }

    } catch {
        Add-Content $LogPath "ERREUR création $Sam : $($_.Exception.Message)"
    }
}

Add-Content $LogPath "==== Fin - $(Get-Date) ===="
Write-Host "Terminé. Log : $LogPath"
