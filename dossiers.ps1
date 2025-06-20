#Requires -Version 5.1
<#
.SYNOPSIS
    Script d'audit des permissions NTFS avec export HTML interactif - Version optimisée
    
.DESCRIPTION
    Ce script analyse récursivement une arborescence de dossiers pour extraire :
    - Les permissions NTFS (ACL)
    - Les propriétaires
    - Les dates de modification
    - La résolution des SID en noms d'utilisateurs/groupes AD
    
    Version optimisée avec traitement parallèle pour gros volumes
    
.PARAMETER Path
    Chemin racine à analyser (si non spécifié, une fenêtre de sélection s'ouvre)
    
.PARAMETER OutputPath
    Dossier de sortie pour les fichiers générés (par défaut : Desktop\NTFS_Audit_[date])
    
.PARAMETER MaxDepth
    Profondeur maximale de récursion (par défaut : illimité)
    
.PARAMETER IncludeInherited
    Inclure les permissions héritées dans l'analyse
    
.PARAMETER ExcludeFolders
    Liste de dossiers à exclure (supports wildcards)
    
.PARAMETER UseParallel
    Active le traitement parallèle (recommandé pour > 1000 dossiers)
    
.PARAMETER MaxThreads
    Nombre maximum de threads parallèles (par défaut : nombre de CPU)
    
.EXAMPLE
    .\NTFS-Audit.ps1
    # Ouvre une fenêtre pour sélectionner le dossier
    
.EXAMPLE
    .\NTFS-Audit.ps1 -Path "C:\Partages" -MaxDepth 5 -UseParallel
    
.EXAMPLE
    .\NTFS-Audit.ps1 -Path "D:\Data" -ExcludeFolders @("*temp*", "*cache*") -MaxThreads 8
#>

[CmdletBinding()]
param(
    [Parameter(Position = 0)]
    [ValidateScript({
        if ([string]::IsNullOrWhiteSpace($_)) { $true }
        elseif (Test-Path $_ -PathType Container) { $true }
        else { throw "Le chemin '$_' n'existe pas ou n'est pas un dossier" }
    })]
    [string]$Path = "",
    
    [Parameter()]
    [string]$OutputPath = [System.IO.Path]::Combine([Environment]::GetFolderPath("Desktop"), "NTFS_Audit_$(Get-Date -Format 'yyyyMMdd_HHmmss')"),
    
    [Parameter()]
    [int]$MaxDepth = [int]::MaxValue,
    
    [Parameter()]
    [switch]$IncludeInherited,
    
    [Parameter()]
    [string[]]$ExcludeFolders = @(),
    
    [Parameter()]
    [switch]$UseParallel,
    
    [Parameter()]
    [int]$MaxThreads = [Environment]::ProcessorCount
)

# ================================
# FONCTION DE SÉLECTION DE DOSSIER
# ================================

function Select-FolderDialog {
    param(
        [string]$Description = "Sélectionnez le dossier à analyser",
        [string]$RootFolder = [Environment]::GetFolderPath("Desktop")
    )
    
    # Charger Windows Forms
    Add-Type -AssemblyName System.Windows.Forms
    
    # Créer le dialogue
    $folderBrowser = New-Object System.Windows.Forms.FolderBrowserDialog
    $folderBrowser.Description = $Description
    $folderBrowser.ShowNewFolderButton = $false
    $folderBrowser.RootFolder = "MyComputer"
    
    # Si un dossier initial est spécifié
    if (Test-Path $RootFolder) {
        $folderBrowser.SelectedPath = $RootFolder
    }
    
    # Afficher le dialogue
    $result = $folderBrowser.ShowDialog()
    
    if ($result -eq [System.Windows.Forms.DialogResult]::OK) {
        return $folderBrowser.SelectedPath
    } else {
        return $null
    }
}

# ================================
# SÉLECTION DU DOSSIER SI NON SPÉCIFIÉ
# ================================

if ([string]::IsNullOrWhiteSpace($Path)) {
    Write-Host "`n╔══════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "║           SÉLECTION DU DOSSIER À ANALYSER                    ║" -ForegroundColor Cyan
    Write-Host "╚══════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
    
    Write-Host "`nOuverture de la fenêtre de sélection..." -ForegroundColor Yellow
    
    $selectedPath = Select-FolderDialog -Description "Sélectionnez le dossier racine pour l'audit NTFS"
    
    if ([string]::IsNullOrWhiteSpace($selectedPath)) {
        Write-Host "`nAucun dossier sélectionné. Arrêt du script." -ForegroundColor Red
        exit
    }
    
    $Path = $selectedPath
    # Vérifier que l'utilisateur a accès au dossier
    try {
        Get-ChildItem -Path $Path -Force -ErrorAction Stop | Select-Object -First 1 | Out-Null
    } catch {
        Write-Host "`nErreur : Impossible d'accéder au dossier sélectionné." -ForegroundColor Red
        Write-Host "Message : $_" -ForegroundColor Red
        exit
    }
    Write-Host "Dossier sélectionné : $Path" -ForegroundColor Green
}

# ================================
# VÉRIFICATION DES PRIVILÈGES
# ================================

# Vérifier si le script est exécuté avec élévation
$currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
$isElevated = $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $isElevated) {
    Write-Warning @"
`n╔══════════════════════════════════════════════════════════════════════════╗
║                              ATTENTION                                   ║
║                                                                          ║
║  Ce script est exécuté SANS privilèges administrateur !                  ║
║                                                                          ║
║  Conséquences possibles :                                                ║
║  • Certains dossiers système ne seront pas accessibles                   ║
║  • Les informations de propriétaire peuvent être incomplètes             ║
║  • Des erreurs "Accès refusé" peuvent apparaître                         ║
║                                                                          ║
║  Pour un audit complet, exécutez PowerShell en tant qu'administrateur    ║
╚══════════════════════════════════════════════════════════════════════════╝
"@
    
    $response = Read-Host "`nVoulez-vous continuer malgré tout ? (O/N)"
    if ($response -ne 'O' -and $response -ne 'o') {
        Write-Host "Script annulé." -ForegroundColor Yellow
        exit
    }
}

# ================================
# VALIDATION DU CHEMIN D'ENTRÉE
# ================================
if ($Path.Contains('[') -or $Path.Contains(']') -or $Path.Contains("'") -or $Path.Contains('"')) {
    Write-Warning "Le chemin contient des caractères spéciaux : [ ] ' `""
    Write-Warning "Cela peut causer des problèmes d'affichage dans l'interface web."
    Write-Warning "Le script continuera mais certains dossiers pourraient ne pas s'afficher correctement."
    Start-Sleep -Seconds 2
}

# ================================
# CACHE THREAD-SAFE POUR OPTIMISATION
# ================================

# Créer un cache thread-safe pour les résolutions SID
$script:sidCache = [System.Collections.Concurrent.ConcurrentDictionary[string,string]]::new()

# Créer un compteur thread-safe pour la progression
Add-Type -TypeDefinition @"
public class ProgressCounter {
    private static int count = 0;
    public static int Increment() {
        return System.Threading.Interlocked.Increment(ref count);
    }
    public static int GetValue() {
        return count;
    }
}
"@ -ErrorAction SilentlyContinue

# ================================
# FONCTIONS UTILITAIRES
# ================================

# Fonction pour afficher une barre de progression personnalisée
function Show-AuditProgress {
    param(
        [int]$Current,
        [int]$Total,
        [string]$CurrentPath
    )
    
    $percentComplete = if ($Total -gt 0) { [math]::Round(($Current / $Total) * 100, 2) } else { 0 }
    $progressBar = "[" + ("#" * [math]::Floor($percentComplete / 5)) + ("-" * (20 - [math]::Floor($percentComplete / 5))) + "]"
    
    $mode = if ($UseParallel) { " [PARALLÈLE]" } else { "" }
    Write-Host "`r$progressBar $percentComplete%$mode - Analyse : $CurrentPath" -NoNewline
}

# Fonction optimisée pour résoudre les SID en noms (avec cache thread-safe)
function Resolve-SIDtoName {
    param([string]$SID)
    
    # Vérifier le cache thread-safe
    $cachedName = $null
    if ($script:sidCache.TryGetValue($SID, [ref]$cachedName)) {
        return $cachedName
    }
    
    try {
        # Essayer de résoudre le SID
        $account = [System.Security.Principal.SecurityIdentifier]::new($SID).Translate([System.Security.Principal.NTAccount]).Value
        $script:sidCache.TryAdd($SID, $account) | Out-Null
        return $account
    }
    catch {
        # Si échec, retourner le SID et le mettre en cache
        $script:sidCache.TryAdd($SID, $SID) | Out-Null
        return $SID
    }
}

# Fonction pour convertir les droits FileSystemRights en texte lisible
function Convert-FileSystemRights {
    param([System.Security.AccessControl.FileSystemRights]$Rights)
    
    # Mappings des droits courants
    switch ($Rights) {
        'FullControl'     { return 'Contrôle total' }
        'Modify'          { return 'Modification' }
        'ReadAndExecute'  { return 'Lecture et exécution' }
        'Read'            { return 'Lecture' }
        'Write'           { return 'Écriture' }
        2147483648        { return 'Contrôle total' }  # GenericAll
        default {
            # Pour les combinaisons complexes, décomposer
            $permissions = @()
            if ($Rights -band [System.Security.AccessControl.FileSystemRights]::Read) { $permissions += 'Lecture' }
            if ($Rights -band [System.Security.AccessControl.FileSystemRights]::Write) { $permissions += 'Écriture' }
            if ($Rights -band [System.Security.AccessControl.FileSystemRights]::Delete) { $permissions += 'Suppression' }
            if ($Rights -band [System.Security.AccessControl.FileSystemRights]::ChangePermissions) { $permissions += 'Modifier permissions' }
            
            if ($permissions.Count -gt 0) {
                return ($permissions -join ', ')
            } else {
                return $Rights.ToString()
            }
        }
    }
}

# ================================
# FONCTION DE GÉNÉRATION DES FICHIERS DE LANGUE
# ================================

function New-LanguageFiles {
    param(
        [string]$OutputPath
    )
    
    # Créer le dossier lang
    $langPath = Join-Path $OutputPath "lang"
    if (-not (Test-Path $langPath)) {
        New-Item -ItemType Directory -Path $langPath -Force | Out-Null
    }
    
    # Traduction française (avec les nouvelles sections)
    $frenchTranslation = @'
{
  "meta": {
    "language": "Français",
    "code": "fr",
    "direction": "ltr"
  },
  "ui": {
    "title": "Audit des Permissions NTFS",
    "generatedOn": "Généré le",
    "rootPath": "Racine analysée",
    "loading": "Chargement des données d'audit...",
    "error": "Erreur lors du chargement des données."
  },
  "filters": {
    "title": "Filtres de recherche",
    "selectUser": "Sélectionner un utilisateur",
    "allUsers": "-- Tous les utilisateurs --",
    "searchUser": "Ou rechercher (saisie libre)",
    "userPlaceholder": "Ex: DOMAINE\\utilisateur",
    "path": "Chemin",
    "pathPlaceholder": "Ex: Finance",
    "permissionType": "Type de permission",
    "allPermissions": "Toutes",
    "apply": "🔍 Appliquer les filtres",
    "reset": "↻ Réinitialiser",
    "export": "📥 Exporter (CSV)"
  },
  "stats": {
    "foldersAnalyzed": "Dossiers analysés",
    "uniqueUsers": "Utilisateurs uniques",
    "accessErrors": "Erreurs d'accès",
    "visibleResults": "Résultats visibles"
  },
  "tree": {
    "title": "Arborescence des permissions",
    "expandAll": "📂 Tout développer",
    "collapseAll": "📁 Tout réduire",
    "folder": "Dossier",
    "usersGroups": "Utilisateurs / Groupes",
    "owner": "Propriétaire",
    "lastModified": "Dernière modification",
    "moreUsers": "+{count} autres",
    "clickForDetails": "Cliquez sur le dossier pour voir tous les détails"
  },
  "permissions": {
    "fullControl": "Contrôle total",
    "modify": "Modification",
    "readExecute": "Lecture et exécution",
    "read": "Lecture",
    "write": "Écriture"
  },
  "inheritance": {
    "containerInherit": "Héritage conteneurs",
    "objectInherit": "Héritage objets",
    "containerObjectInherit": "Héritage complet",
    "none": "Aucun",
    "noPropagateInherit": "Sans propagation",
    "inheritOnly": "Héritage uniquement"
  },
  "accessTypes": {
    "allow": "Autoriser",
    "deny": "Refuser"
  },
  "csv": {
    "headers": {
      "path": "Chemin",
      "owner": "Propriétaire",
      "user": "Utilisateur",
      "permission": "Permission",
      "type": "Type",
      "inherited": "Hérité",
      "lastModified": "Dernière modification"
    },
    "values": {
      "yes": "Oui",
      "no": "Non"
    }
  },
  "details": {
    "title": "📁 Détails des permissions",
    "close": "✖ Fermer",
    "generalInfo": "📋 Informations générales",
    "owner": "Propriétaire",
    "lastModified": "Dernière modification",
    "inheritance": "Héritage",
    "inheritanceEnabled": "✓ Activé",
    "inheritanceDisabled": "✗ Désactivé",
    "state": "État",
    "accessible": "✓ Accessible",
    "accessError": "✗ Erreur d'accès",
    "errorMessage": "Message d'erreur",
    "unknownError": "Erreur inconnue",
    "explicitPermissions": "🔐 Permissions explicites",
    "inheritedPermissions": "👥 Permissions héritées",
    "userGroup": "Utilisateur/Groupe",
    "rights": "Droits",
    "type": "Type",
    "allow": "Autoriser",
    "deny": "Refuser",
    "inheritanceCol": "Héritage",
    "propagation": "Propagation",
    "summary": "📊 Résumé des droits effectifs",
    "summaryText": "Ce dossier contient <strong>{total}</strong> entrées de permissions au total, affectant <strong>{users}</strong> utilisateurs/groupes distincts.",
    "inheritanceWarning": "⚠️ L'héritage est désactivé sur ce dossier."
  },
  "messages": {
    "noResults": "Aucun résultat ne correspond aux critères de recherche.",
    "usersFound": "({count} trouvés)",
    "exportError": "Erreur lors de l'export du fichier CSV"
  }
}
'@

    # Traduction anglaise (avec les nouvelles sections)
    $englishTranslation = @'
{
  "meta": {
    "language": "English",
    "code": "en",
    "direction": "ltr"
  },
  "ui": {
    "title": "NTFS Permissions Audit",
    "generatedOn": "Generated on",
    "rootPath": "Root path analyzed",
    "loading": "Loading audit data...",
    "error": "Error loading data."
  },
  "filters": {
    "title": "Search Filters",
    "selectUser": "Select a user",
    "allUsers": "-- All users --",
    "searchUser": "Or search (free text)",
    "userPlaceholder": "E.g: DOMAIN\\user",
    "path": "Path",
    "pathPlaceholder": "E.g: Finance",
    "permissionType": "Permission type",
    "allPermissions": "All",
    "apply": "🔍 Apply filters",
    "reset": "↻ Reset",
    "export": "📥 Export (CSV)"
  },
  "stats": {
    "foldersAnalyzed": "Folders analyzed",
    "uniqueUsers": "Unique users",
    "accessErrors": "Access errors",
    "visibleResults": "Visible results"
  },
  "tree": {
    "title": "Permissions Tree",
    "expandAll": "📂 Expand all",
    "collapseAll": "📁 Collapse all",
    "folder": "Folder",
    "usersGroups": "Users / Groups",
    "owner": "Owner",
    "lastModified": "Last modified",
    "moreUsers": "+{count} others",
    "clickForDetails": "Click on folder to see all details"
  },
  "permissions": {
    "fullControl": "Full Control",
    "modify": "Modify",
    "readExecute": "Read & Execute",
    "read": "Read",
    "write": "Write"
  },
  "inheritance": {
    "containerInherit": "Container Inherit",
    "objectInherit": "Object Inherit",
    "containerObjectInherit": "Full Inheritance",
    "none": "None",
    "noPropagateInherit": "No Propagate",
    "inheritOnly": "Inherit Only"
  },
  "accessTypes": {
    "allow": "Allow",
    "deny": "Deny"
  },
  "csv": {
    "headers": {
      "path": "Path",
      "owner": "Owner",
      "user": "User",
      "permission": "Permission",
      "type": "Type",
      "inherited": "Inherited",
      "lastModified": "Last Modified"
    },
    "values": {
      "yes": "Yes",
      "no": "No"
    }
  },
  "details": {
    "title": "📁 Permission Details",
    "close": "✖ Close",
    "generalInfo": "📋 General Information",
    "owner": "Owner",
    "lastModified": "Last modified",
    "inheritance": "Inheritance",
    "inheritanceEnabled": "✓ Enabled",
    "inheritanceDisabled": "✗ Disabled",
    "state": "State",
    "accessible": "✓ Accessible",
    "accessError": "✗ Access error",
    "errorMessage": "Error message",
    "unknownError": "Unknown error",
    "explicitPermissions": "🔐 Explicit Permissions",
    "inheritedPermissions": "👥 Inherited Permissions",
    "userGroup": "User/Group",
    "rights": "Rights",
    "type": "Type",
    "allow": "Allow",
    "deny": "Deny",
    "inheritanceCol": "Inheritance",
    "propagation": "Propagation",
    "summary": "📊 Effective Rights Summary",
    "summaryText": "This folder contains <strong>{total}</strong> permission entries in total, affecting <strong>{users}</strong> distinct users/groups.",
    "inheritanceWarning": "⚠️ Inheritance is disabled on this folder."
  },
  "messages": {
    "noResults": "No results match the search criteria.",
    "usersFound": "({count} found)",
    "exportError": "Error exporting CSV file"
  }
}
'@
    
    # Définir les chemins des fichiers
    $frFile = Join-Path $langPath "fr.json"
    $enFile = Join-Path $langPath "en.json"
    
    # Écrire les fichiers
    $frenchTranslation | Out-File -FilePath $frFile -Encoding UTF8
    $englishTranslation | Out-File -FilePath $enFile -Encoding UTF8
    
    # Retourner les chemins créés
    return @($frFile, $enFile)
}

# ================================
# FONCTION PRINCIPALE D'ANALYSE
# ================================

function Get-NTFSPermissions {
    param(
        [string]$FolderPath,
        [int]$CurrentDepth = 0,
        [int]$MaxDepth = [int]::MaxValue
    )
    
    # Vérifier la profondeur
    if ($CurrentDepth -gt $MaxDepth) { return }
    
    # Vérifier les exclusions
    foreach ($exclude in $script:ExcludeFolders) {
        if ($FolderPath -like $exclude) { return }
    }
    
    # Créer l'objet résultat
    $result = [PSCustomObject]@{
        Path = $FolderPath
        Name = Split-Path $FolderPath -Leaf
        Owner = $null
        LastModified = $null
        Permissions = @()
        InheritedPermissions = @()
        HasInheritance = $true
        Children = @()
        Depth = $CurrentDepth
        IsAccessible = $true
        ErrorMessage = $null
    }
    
    try {
        # Obtenir les informations du dossier
        $folderInfo = Get-Item -Path $FolderPath -Force -ErrorAction Stop
        $result.LastModified = $folderInfo.LastWriteTime.ToString("yyyy-MM-dd HH:mm:ss")
        
        # Obtenir l'ACL
        $acl = Get-Acl -Path $FolderPath -ErrorAction Stop
        
        # Propriétaire
        $ownerSid = $acl.Owner
        $result.Owner = if ($ownerSid -match '^S-\d-\d+-') {
            Resolve-SIDtoName -SID $ownerSid
        } else {
            $ownerSid
        }
        
        # Vérifier l'héritage
        $result.HasInheritance = -not $acl.AreAccessRulesProtected
        
        # Analyser les permissions
        foreach ($ace in $acl.Access) {
            $identity = $ace.IdentityReference.Value
            
            # Résoudre le SID si nécessaire
            if ($identity -match '^S-\d-\d+-') {
                $identity = Resolve-SIDtoName -SID $identity
            }
            
            $permission = [PSCustomObject]@{
                Identity = $identity
                Rights = Convert-FileSystemRights -Rights $ace.FileSystemRights
                AccessType = if ($ace.AccessControlType -eq 'Allow') { 'Autoriser' } else { 'Refuser' }
                IsInherited = $ace.IsInherited
                InheritanceFlags = $ace.InheritanceFlags.ToString()
                PropagationFlags = $ace.PropagationFlags.ToString()
            }
            
            if ($ace.IsInherited) {
                $result.InheritedPermissions += $permission
            } else {
                $result.Permissions += $permission
            }
        }
        
        # Parcourir les sous-dossiers
        if ($CurrentDepth -lt $MaxDepth) {
            $subFolders = Get-ChildItem -Path $FolderPath -Directory -Force -ErrorAction SilentlyContinue
            
            # Traitement parallèle ou séquentiel selon le choix
            if ($UseParallel -and $subFolders.Count -gt 5) {
                # Traitement parallèle avec ForEach-Object -Parallel (PowerShell 7+)
                # ou avec des runspaces pour PowerShell 5.1
                $childResults = Process-SubfoldersParallel -SubFolders $subFolders -CurrentDepth $CurrentDepth -MaxDepth $MaxDepth
                $result.Children = @($childResults | Where-Object { $_ -ne $null })
            } else {
                # Traitement séquentiel standard
                foreach ($subFolder in $subFolders) {
                    [ProgressCounter]::Increment() | Out-Null
                    $count = [ProgressCounter]::GetValue()
                    Show-AuditProgress -Current $count -Total $script:estimatedTotal -CurrentPath $subFolder.Name
                    
                    $childResult = Get-NTFSPermissions -FolderPath $subFolder.FullName -CurrentDepth ($CurrentDepth + 1) -MaxDepth $MaxDepth
                    if ($childResult) {
                        $result.Children += $childResult
                    }
                }
            }
        }
    }
    catch {
        $result.IsAccessible = $false
        $result.ErrorMessage = $_.Exception.Message
        Write-Verbose "Erreur d'accès sur : $FolderPath - $($_.Exception.Message)"
    }
    
    return $result
}

# ================================
# FONCTION POUR TRAITEMENT PARALLÈLE
# ================================

function Process-SubfoldersParallel {
    param(
        [System.IO.DirectoryInfo[]]$SubFolders,
        [int]$CurrentDepth,
        [int]$MaxDepth
    )
    
    # Créer un runspace pool pour le traitement parallèle
    $runspacePool = [RunspaceFactory]::CreateRunspacePool(1, $MaxThreads)
    $runspacePool.Open()
    
    $jobs = @()
    
    # Script à exécuter dans chaque runspace
    $scriptBlock = {
        param($FolderPath, $CurrentDepth, $MaxDepth, $Functions, $ExcludeFolders)
        
        # Charger les fonctions dans le runspace
        . ([ScriptBlock]::Create($Functions))
        
        # Variables globales nécessaires
        $script:ExcludeFolders = $ExcludeFolders
        
        # Exécuter l'analyse
        Get-NTFSPermissions -FolderPath $FolderPath -CurrentDepth ($CurrentDepth + 1) -MaxDepth $MaxDepth
    }
    
    # Exporter les fonctions nécessaires
    $functionDefinitions = @(
        "function Resolve-SIDtoName { ${function:Resolve-SIDtoName} }",
        "function Convert-FileSystemRights { ${function:Convert-FileSystemRights} }",
        "function Get-NTFSPermissions { ${function:Get-NTFSPermissions} }",
        "function Show-AuditProgress { ${function:Show-AuditProgress} }",
        "`$script:sidCache = [System.Collections.Concurrent.ConcurrentDictionary[string,string]]::new()"
    ) -join "`n"
    
    # Créer les jobs
    foreach ($subFolder in $SubFolders) {
        $powershell = [PowerShell]::Create().AddScript($scriptBlock).AddArgument($subFolder.FullName).AddArgument($CurrentDepth).AddArgument($MaxDepth).AddArgument($functionDefinitions).AddArgument($script:ExcludeFolders)
        $powershell.RunspacePool = $runspacePool
        
        $jobs += [PSCustomObject]@{
            PowerShell = $powershell
            Handle = $powershell.BeginInvoke()
            Folder = $subFolder.FullName
        }
        
        # Mettre à jour le compteur
        [ProgressCounter]::Increment() | Out-Null
    }
    
    # Attendre et collecter les résultats
    $results = @()
    foreach ($job in $jobs) {
        try {
            $result = $job.PowerShell.EndInvoke($job.Handle)
            if ($result) {
                $results += $result
            }
        }
        catch {
            Write-Warning "Erreur lors du traitement de $($job.Folder) : $_"
        }
        finally {
            $job.PowerShell.Dispose()
        }
        
        # Afficher la progression
        $count = [ProgressCounter]::GetValue()
        Show-AuditProgress -Current $count -Total $script:estimatedTotal -CurrentPath (Split-Path $job.Folder -Leaf)
    }
    
    $runspacePool.Close()
    $runspacePool.Dispose()
    
    return $results
}

# ================================
# FONCTION DE PRÉ-CHARGEMENT DU CACHE
# ================================

function Preload-CommonSIDs {
    Write-Host "`nPré-chargement des SID communs..." -ForegroundColor Yellow
    
    # SID bien connus
    $wellKnownSIDs = @{
        'S-1-5-32-544' = 'BUILTIN\Administrators'
        'S-1-5-32-545' = 'BUILTIN\Users'
        'S-1-5-32-546' = 'BUILTIN\Guests'
        'S-1-5-18' = 'NT AUTHORITY\SYSTEM'
        'S-1-5-19' = 'NT AUTHORITY\LOCAL SERVICE'
        'S-1-5-20' = 'NT AUTHORITY\NETWORK SERVICE'
        'S-1-1-0' = 'Everyone'
        'S-1-5-11' = 'NT AUTHORITY\Authenticated Users'
    }
    
    foreach ($sid in $wellKnownSIDs.Keys) {
        $script:sidCache.TryAdd($sid, $wellKnownSIDs[$sid]) | Out-Null
    }
    
    Write-Host "Cache initialisé avec $($script:sidCache.Count) SID connus" -ForegroundColor Green
}

# ================================
# GÉNÉRATION DU RAPPORT HTML
# ================================

function New-HTMLReport {
   param(
       [PSCustomObject]$AuditData,
       [string]$JsonFile,
       [string]$OutputFile
   )
   
   # Lire le contenu JSON
   $jsonContent = Get-Content -Path $JsonFile -Raw
   
   # Template HTML avec CSS complet
   $htmlTemplate = @'
<!DOCTYPE html>
<html lang="fr">
<head>
   <meta charset="UTF-8">
   <meta name="viewport" content="width=device-width, initial-scale=1.0">
   <title>Audit NTFS - Rapport généré le {DATE}</title>
   <style>
       * {
           margin: 0;
           padding: 0;
           box-sizing: border-box;
       }

       body {
           font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
           background-color: #f5f5f5;
           color: #333;
           line-height: 1.6;
       }

       .container {
           padding-bottom: 100px;
       }

       header {
           background-color: #2c3e50;
           color: white;
           padding: 20px 0;
           margin-bottom: 30px;
           box-shadow: 0 2px 5px rgba(0,0,0,0.1);
           position: relative;
       }

       .language-selector {
           position: absolute;
           top: 20px;
           right: 20px;
       }

       .language-selector select {
           background: rgba(255,255,255,0.2);
           color: white;
           border: 1px solid rgba(255,255,255,0.3);
           padding: 5px 10px;
           border-radius: 4px;
           font-size: 14px;
           cursor: pointer;
       }

       .language-selector select option {
           background: #2c3e50;
           color: white;
       }

       h1 {
           text-align: center;
           font-size: 2em;
           font-weight: 300;
       }

       .metadata {
           text-align: center;
           margin-top: 10px;
           opacity: 0.8;
       }

       .loading {
           text-align: center;
           padding: 40px;
       }

       .permissions-table {
           width: 100%;
           border-collapse: collapse;
           margin-top: 10px;
           font-size: 13px;
       }

       .permissions-table th {
           background-color: #ecf0f1;
           padding: 8px;
           text-align: left;
           font-weight: 600;
           border-bottom: 2px solid #bdc3c7;
       }

       .permissions-table td {
           padding: 6px 8px;
           border-bottom: 1px solid #ecf0f1;
       }

       .permissions-table tr:hover {
           background-color: #f8f9fa;
       }

       .permission-type-allow {
           color: #27ae60;
           font-weight: 600;
       }

       .permission-type-deny {
           color: #e74c3c;
           font-weight: 600;
       }

       .inheritance-badge {
           background-color: #3498db;
           color: white;
           padding: 2px 6px;
           border-radius: 3px;
           font-size: 11px;
           margin-right: 4px;
       }

       .filters {
           background: white;
           padding: 20px;
           border-radius: 8px;
           box-shadow: 0 2px 10px rgba(0,0,0,0.1);
           margin-bottom: 20px;
       }

       .filter-row {
           display: flex;
           gap: 20px;
           margin-bottom: 15px;
           flex-wrap: wrap;
       }

       .filter-group {
           flex: 1;
           min-width: 200px;
       }

       label {
           display: block;
           margin-bottom: 5px;
           font-weight: 500;
           color: #555;
       }

       input[type="text"], input[type="date"], select {
           width: 100%;
           padding: 8px 12px;
           border: 1px solid #ddd;
           border-radius: 4px;
           font-size: 14px;
       }

       .btn-group {
           display: flex;
           gap: 10px;
           margin-top: 20px;
       }

       button {
           padding: 10px 20px;
           border: none;
           border-radius: 4px;
           cursor: pointer;
           font-size: 14px;
           background-color: #3498db;
           color: white;
       }

       button:hover {
           background-color: #2980b9;
       }

       .btn-secondary {
           background-color: #95a5a6;
       }

       .btn-secondary:hover {
           background-color: #7f8c8d;
       }

       .stats {
           display: flex;
           gap: 20px;
           margin-bottom: 20px;
       }

       .stat-card {
           background: white;
           padding: 15px;
           border-radius: 8px;
           box-shadow: 0 2px 5px rgba(0,0,0,0.1);
           flex: 1;
           text-align: center;
       }

       .stat-number {
           font-size: 2em;
           font-weight: bold;
           color: #3498db;
       }

       .stat-label {
           color: #777;
           font-size: 0.9em;
       }

       .tree-container {
           background: white;
           border-radius: 8px;
           box-shadow: 0 2px 10px rgba(0,0,0,0.1);
           padding: 20px;
       }

       .tree-header {
           display: flex;
           justify-content: space-between;
           align-items: center;
           margin-bottom: 20px;
           padding-bottom: 15px;
           border-bottom: 2px solid #ecf0f1;
       }

       .tree-columns-header {
           display: flex;
           align-items: center;
           padding: 10px 8px;
           background-color: #34495e;
           color: white;
           font-weight: 600;
           font-size: 13px;
           border-radius: 4px 4px 0 0;
           margin-bottom: 5px;
           font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
       }

       .header-toggle {
           width: 16px;
           margin-right: 5px;
       }

       .header-icon {
           width: 20px;
           margin-right: 8px;
       }

       .header-name {
           flex: 0 0 auto;
           min-width: 200px;
           max-width: 400px;
       }

       .header-users {
           flex: 1;
           min-width: 300px;
           padding-right: 20px;
       }

       .header-owner {
           min-width: 200px;
           padding-right: 20px;
       }

       .header-date {
           min-width: 120px;
       }

       .tree {
           font-family: 'Consolas', 'Monaco', monospace;
           font-size: 14px;
       }

       .tree-item {
           margin: 2px 0;
           border-bottom: 1px solid #f0f0f0;
       }

       .tree-item:last-child {
           border-bottom: none;
       }

       .tree-row {
           display: flex;
           align-items: flex-start;
           padding: 6px 8px;
           border-radius: 4px;
           cursor: pointer;
           min-height: 32px;
       }

       .tree-row:hover {
           background-color: #ecf0f1;
       }

       .tree-row.selected {
           background-color: #e3f2fd;
       }

       .tree-row.error {
           color: #e74c3c;
           font-style: italic;
       }

       .tree-toggle {
           width: 16px;
           height: 16px;
           display: inline-flex;
           align-items: center;
           justify-content: center;
           cursor: pointer;
           user-select: none;
           font-size: 12px;
           color: #7f8c8d;
           margin-right: 5px;
       }

       .tree-icon {
           width: 20px;
           height: 20px;
           display: inline-flex;
           align-items: center;
           justify-content: center;
           margin-right: 8px;
       }

       .tree-name {
           flex: 0 0 auto;
           color: #2c3e50;
           font-weight: 500;
           min-width: 200px;
           max-width: 400px;
       }

       .tree-info {
           display: flex;
           gap: 20px;
           align-items: flex-start;
           color: #7f8c8d;
           font-size: 13px;
           flex: 1;
       }

       .users-container {
           display: flex;
           gap: 4px;
           flex-wrap: wrap;
           min-width: 300px;
           flex: 1;
           padding-right: 20px;
           align-items: flex-start;
       }

       .permission-badge {
           background-color: #e8f5e9;
           color: #2e7d32;
           padding: 2px 8px;
           border-radius: 3px;
           font-size: 11px;
           font-weight: 500;
       }

       .permission-badge.full {
           background-color: #ffebee;
           color: #c62828;
       }

       .permission-badge.write {
           background-color: #fff3e0;
           color: #ef6c00;
       }

       .user-badge {
           background-color: #f3e5f5;
           color: #6a1b9a;
           padding: 2px 8px;
           border-radius: 3px;
           font-size: 11px;
           cursor: help;
           white-space: nowrap;
           margin-bottom: 2px;
       }

       .user-badge:hover {
           background-color: #e1bee7;
       }

       .tree-owner {
           color: #16a085;
           min-width: 200px;
           padding-right: 20px;
           flex-shrink: 0;
       }

       .tree-date {
           color: #95a5a6;
           min-width: 120px;
           flex-shrink: 0;
       }

       .tree-children {
           margin-left: 20px;
           display: none;
       }

       .tree-item.expanded > .tree-children {
           display: block;
       }

       .tree-children .tree-row {
           padding-left: 28px;
       }

       .tree-children .tree-children .tree-row {
           padding-left: 48px;
       }

       .tree-children .tree-children .tree-children .tree-row {
           padding-left: 68px;
       }

       .details-panel {
           position: fixed;
           top: 0;
           right: 0;
           width: 40%;
           min-width: 400px;
           max-width: 600px;
           height: 100vh;
           background: white;
           border-left: 3px solid #2c3e50;
           box-shadow: -5px 0 20px rgba(0,0,0,0.2);
           padding: 20px;
           overflow-y: auto;
           transform: translateX(100%);
           transition: transform 0.3s ease-in-out;
           z-index: 1000;
       }

       .details-panel.active {
           transform: translateX(0);
       }

       .container.panel-open {
           margin-right: 40%;
           transition: margin-right 0.3s ease-in-out;
       }

       .details-header {
           display: flex;
           justify-content: space-between;
           align-items: center;
           border-bottom: 2px solid #ecf0f1;
           padding-bottom: 15px;
           margin-bottom: 20px;
       }

       .details-close {
           position: absolute;
           top: 10px;
           right: 10px;
           background: #e74c3c;
           color: white;
           border: none;
           border-radius: 4px;
           padding: 5px 15px;
           cursor: pointer;
           font-size: 14px;
       }

       .details-close:hover {
           background: #c0392b;
       }

       .hidden {
           display: none !important;
       }
   </style>
</head>
<body>
   <header>
       <div class="container">
           <h1 id="mainTitle">🔐 Audit des Permissions NTFS</h1>
           <div class="metadata">
               <p><span id="generatedOnLabel">Généré le</span> {DATE} | <span id="rootPathLabel">Racine analysée</span> : <strong>{ROOT_PATH}</strong></p>
           </div>
           <div class="language-selector">
               <select id="langSelector">
                   <option value="fr">🇫🇷 Français</option>
                   <option value="en">🇬🇧 English</option>
               </select>
           </div>
       </div>
   </header>

   <div class="container">
       <div class="filters">
           <h2 id="filtersTitle" style="margin-bottom: 20px; color: #2c3e50;">Filtres de recherche</h2>
   
           <div class="filter-row">
               <div class="filter-group">
                   <label for="userFilter" id="userFilterLabel">Sélectionner un utilisateur</label>
                   <select id="userFilter">
                       <option value="" id="allUsersOption">-- Tous les utilisateurs --</option>
                   </select>
               </div>
       
               <div class="filter-group">
                   <label for="userSearch" id="userSearchLabel">Ou rechercher (saisie libre)</label>
                   <input type="text" id="userSearch" placeholder="Ex: DOMAINE\utilisateur">
               </div>
       
               <div class="filter-group">
                   <label for="pathFilter" id="pathFilterLabel">Chemin</label>
                   <input type="text" id="pathFilter" placeholder="Ex: Finance">
               </div>
       
               <div class="filter-group">
                   <label for="permissionFilter" id="permissionFilterLabel">Type de permission</label>
                   <select id="permissionFilter">
                       <option value="" id="allPermissionsOption">Toutes</option>
                       <option value="Contrôle total">Contrôle total</option>
                       <option value="Modification">Modification</option>
                       <option value="Lecture">Lecture</option>
                       <option value="Écriture">Écriture</option>
                   </select>
               </div>
           </div>

           <div class="btn-group">
               <button id="applyFiltersBtn" onclick="applyFilters()">🔍 Appliquer les filtres</button>
               <button id="resetFiltersBtn" class="btn-secondary" onclick="resetFilters()">↻ Réinitialiser</button>
               <button id="exportBtn" class="btn-secondary" onclick="exportToCSV()">📥 Exporter (CSV)</button>
           </div>
       </div>

       <div class="stats">
           <div class="stat-card">
               <div class="stat-number" id="statFolders">0</div>
               <div class="stat-label" id="statFoldersLabel">Dossiers analysés</div>
           </div>
           <div class="stat-card">
               <div class="stat-number" id="statUsers">0</div>
               <div class="stat-label" id="statUsersLabel">Utilisateurs uniques</div>
           </div>
           <div class="stat-card">
               <div class="stat-number" id="statErrors">0</div>
               <div class="stat-label" id="statErrorsLabel">Erreurs d'accès</div>
           </div>
           <div class="stat-card">
               <div class="stat-number" id="statFiltered">0</div>
               <div class="stat-label" id="statFilteredLabel">Résultats visibles</div>
           </div>
       </div>

       <div class="tree-container">
           <div class="tree-header">
               <h3 id="treeTitle" style="color: #2c3e50;">Arborescence des permissions</h3>
               <div>
                   <button id="expandAllBtn" class="btn-secondary" onclick="expandAll()" style="font-size: 13px; padding: 6px 12px;">📂 Tout développer</button>
                   <button id="collapseAllBtn" class="btn-secondary" onclick="collapseAll()" style="font-size: 13px; padding: 6px 12px;">📁 Tout réduire</button>
               </div>
           </div>
           
           <div class="tree-columns-header">
               <span class="header-toggle"></span>
               <span class="header-icon"></span>
               <span class="header-name" id="headerFolder">Dossier</span>
               <span class="header-users" id="headerUsers">Utilisateurs / Groupes</span>
               <span class="header-owner" id="headerOwner">Propriétaire</span>
               <span class="header-date" id="headerDate">Dernière modification</span>
           </div>
           
           <div class="tree" id="treeView">
           </div>
       </div>

       <div class="details-panel" id="detailsPanel">
       </div>
   </div>

   <script>
       const auditData = {JSON_DATA};

       let allUsers = new Set();
       let errorCount = 0;
       let folderCount = 0;
       let visibleCount = 0;
       let currentLang = 'fr';
       let translations = {};

// Traductions par défaut intégrées (fallback)
        const defaultTranslations = {
            fr: {
                ui: {
                    title: "Audit des Permissions NTFS",
                    generatedOn: "Généré le",
                    rootPath: "Racine analysée",
                    loading: "Chargement des données d'audit...",
                    error: "Erreur lors du chargement des données."
                },
                filters: {
                    title: "Filtres de recherche",
                    selectUser: "Sélectionner un utilisateur",
                    allUsers: "-- Tous les utilisateurs --",
                    searchUser: "Ou rechercher (saisie libre)",
                    userPlaceholder: "Ex: DOMAINE\\utilisateur",
                    path: "Chemin",
                    pathPlaceholder: "Ex: Finance",
                    permissionType: "Type de permission",
                    allPermissions: "Toutes",
                    apply: "🔍 Appliquer les filtres",
                    reset: "↻ Réinitialiser",
                    export: "📥 Exporter (CSV)"
                },
                stats: {
                    foldersAnalyzed: "Dossiers analysés",
                    uniqueUsers: "Utilisateurs uniques",
                    accessErrors: "Erreurs d'accès",
                    visibleResults: "Résultats visibles"
                },
                tree: {
                    title: "Arborescence des permissions",
                    expandAll: "📂 Tout développer",
                    collapseAll: "📁 Tout réduire",
                    folder: "Dossier",
                    usersGroups: "Utilisateurs / Groupes",
                    owner: "Propriétaire",
                    lastModified: "Dernière modification",
                    moreUsers: "+{count} autres",
                    clickForDetails: "Cliquez sur le dossier pour voir tous les détails"
                },
                permissions: {
                    fullControl: "Contrôle total",
                    modify: "Modification",
                    readExecute: "Lecture et exécution",
                    read: "Lecture",
                    write: "Écriture"
                },
                inheritance: {
                    containerInherit: "Héritage conteneurs",
                    objectInherit: "Héritage objets",
                    containerObjectInherit: "Héritage complet",
                    none: "Aucun",
                    noPropagateInherit: "Sans propagation",
                    inheritOnly: "Héritage uniquement"
                },
                accessTypes: {
                    allow: "Autoriser",
                    deny: "Refuser"
                },
                csv: {
                    headers: {
                        path: "Chemin",
                        owner: "Propriétaire",
                        user: "Utilisateur",
                        permission: "Permission",
                        type: "Type",
                        inherited: "Hérité",
                        lastModified: "Dernière modification"
                    },
                    values: {
                        yes: "Oui",
                        no: "Non"
                    }
                },
                details: {
                    title: "📁 Détails des permissions",
                    close: "✖ Fermer",
                    generalInfo: "📋 Informations générales",
                    owner: "Propriétaire",
                    lastModified: "Dernière modification",
                    inheritance: "Héritage",
                    inheritanceEnabled: "✓ Activé",
                    inheritanceDisabled: "✗ Désactivé",
                    state: "État",
                    accessible: "✓ Accessible",
                    accessError: "✗ Erreur d'accès",
                    errorMessage: "Message d'erreur",
                    unknownError: "Erreur inconnue",
                    explicitPermissions: "🔐 Permissions explicites",
                    inheritedPermissions: "👥 Permissions héritées",
                    userGroup: "Utilisateur/Groupe",
                    rights: "Droits",
                    type: "Type",
                    allow: "Autoriser",
                    deny: "Refuser",
                    inheritanceCol: "Héritage",
                    propagation: "Propagation",
                    summary: "📊 Résumé des droits effectifs",
                    summaryText: "Ce dossier contient <strong>{total}</strong> entrées de permissions au total, affectant <strong>{users}</strong> utilisateurs/groupes distincts.",
                    inheritanceWarning: "⚠️ L'héritage est désactivé sur ce dossier."
                },
                messages: {
                    noResults: "Aucun résultat ne correspond aux critères de recherche.",
                    usersFound: "({count} trouvés)",
                    exportError: "Erreur lors de l'export du fichier CSV"
                }
            },
            en: {
                ui: {
                    title: "NTFS Permissions Audit",
                    generatedOn: "Generated on",
                    rootPath: "Root path analyzed",
                    loading: "Loading audit data...",
                    error: "Error loading data."
                },
                filters: {
                    title: "Search Filters",
                    selectUser: "Select a user",
                    allUsers: "-- All users --",
                    searchUser: "Or search (free text)",
                    userPlaceholder: "E.g: DOMAIN\\user",
                    path: "Path",
                    pathPlaceholder: "E.g: Finance",
                    permissionType: "Permission type",
                    allPermissions: "All",
                    apply: "🔍 Apply filters",
                    reset: "↻ Reset",
                    export: "📥 Export (CSV)"
                },
                stats: {
                    foldersAnalyzed: "Folders analyzed",
                    uniqueUsers: "Unique users",
                    accessErrors: "Access errors",
                    visibleResults: "Visible results"
                },
                tree: {
                    title: "Permissions Tree",
                    expandAll: "📂 Expand all",
                    collapseAll: "📁 Collapse all",
                    folder: "Folder",
                    usersGroups: "Users / Groups",
                    owner: "Owner",
                    lastModified: "Last modified",
                    moreUsers: "+{count} others",
                    clickForDetails: "Click on folder to see all details"
                },
                permissions: {
                    fullControl: "Full Control",
                    modify: "Modify",
                    readExecute: "Read & Execute",
                    read: "Read",
                    write: "Write"
                },
                inheritance: {
                    containerInherit: "Container Inherit",
                    objectInherit: "Object Inherit",
                    containerObjectInherit: "Full Inheritance",
                    none: "None",
                    noPropagateInherit: "No Propagate",
                    inheritOnly: "Inherit Only"
                },
                accessTypes: {
                    allow: "Allow",
                    deny: "Deny"
                },
                csv: {
                    headers: {
                        path: "Path",
                        owner: "Owner",
                        user: "User",
                        permission: "Permission",
                        type: "Type",
                        inherited: "Inherited",
                        lastModified: "Last Modified"
                    },
                    values: {
                        yes: "Yes",
                        no: "No"
                    }
                },
                details: {
                    title: "📁 Permission Details",
                    close: "✖ Close",
                    generalInfo: "📋 General Information",
                    owner: "Owner",
                    lastModified: "Last modified",
                    inheritance: "Inheritance",
                    inheritanceEnabled: "✓ Enabled",
                    inheritanceDisabled: "✗ Disabled",
                    state: "State",
                    accessible: "✓ Accessible",
                    accessError: "✗ Access error",
                    errorMessage: "Error message",
                    unknownError: "Unknown error",
                    explicitPermissions: "🔐 Explicit Permissions",
                    inheritedPermissions: "👥 Inherited Permissions",
                    userGroup: "User/Group",
                    rights: "Rights",
                    type: "Type",
                    allow: "Allow",
                    deny: "Deny",
                    inheritanceCol: "Inheritance",
                    propagation: "Propagation",
                    summary: "📊 Effective Rights Summary",
                    summaryText: "This folder contains <strong>{total}</strong> permission entries in total, affecting <strong>{users}</strong> distinct users/groups.",
                    inheritanceWarning: "⚠️ Inheritance is disabled on this folder."
                },
                messages: {
                    noResults: "No results match the search criteria.",
                    usersFound: "({count} found)",
                    exportError: "Error exporting CSV file"
                }
            }
        };

        // Fonction pour charger les traductions
        async function loadTranslations(lang) {
            try {
                const response = await fetch(`lang/${lang}.json`);
                if (!response.ok) throw new Error('Translation file not found');
                translations = await response.json();
                currentLang = lang;
                localStorage.setItem('auditLang', lang);
                applyTranslations();
            } catch (error) {
                console.warn('Fichier de traduction non trouvé, utilisation des traductions intégrées');
                translations = defaultTranslations[lang] || defaultTranslations.fr;
                currentLang = lang;
                localStorage.setItem('auditLang', lang);
                applyTranslations();
            }
        }

        // Fonction pour obtenir une traduction
        function t(key) {
            const keys = key.split('.');
            let value = translations;
            for (const k of keys) {
                value = value?.[k];
            }
            return value || key;
        }

        // Fonction pour appliquer les traductions avec template
        function tf(key, params) {
            let text = t(key);
            if (params) {
                Object.keys(params).forEach(param => {
                    text = text.replace(`{${param}}`, params[param]);
                });
            }
            return text;
        }

        // Fonction pour traduire les permissions
        function translatePermission(permission) {
            const permissionMap = {
                fr: {
                    'Contrôle total': 'Contrôle total',
                    'Modification': 'Modification',
                    'Lecture et exécution': 'Lecture et exécution',
                    'Lecture': 'Lecture',
                    'Écriture': 'Écriture',
                    'Full Control': 'Contrôle total',
                    'Modify': 'Modification',
                    'Read & Execute': 'Lecture et exécution',
                    'Read': 'Lecture',
                    'Write': 'Écriture'
                },
                en: {
                    'Contrôle total': 'Full Control',
                    'Modification': 'Modify',
                    'Lecture et exécution': 'Read & Execute',
                    'Lecture': 'Read',
                    'Écriture': 'Write',
                    'Full Control': 'Full Control',
                    'Modify': 'Modify',
                    'Read & Execute': 'Read & Execute',
                    'Read': 'Read',
                    'Write': 'Write'
                }
            };
    
            const map = permissionMap[currentLang] || permissionMap.fr;
            return map[permission] || permission;
        }

        // Fonction pour traduire les flags d'héritage
        function translateInheritanceFlags(flags) {
            if (!flags || flags === 'None') {
                // Essayer d'abord avec les traductions externes, sinon utiliser le fallback
                const noneTranslation = t('inheritance.none');
                return noneTranslation !== 'inheritance.none' ? noneTranslation : '-';
            }
    
            // Mapper les combinaisons courantes
            const mappings = {
                'ContainerInherit': 'containerInherit',
                'ObjectInherit': 'objectInherit',
                'ContainerInherit, ObjectInherit': 'containerObjectInherit',
                'NoPropagateInherit': 'noPropagateInherit',
                'InheritOnly': 'inheritOnly'
            };
    
            const key = mappings[flags];
            if (key) {
                const translation = t(`inheritance.${key}`);
                // Si la traduction n'est pas trouvée, retourner le flag original
                return translation !== `inheritance.${key}` ? translation : flags;
            }
    
            return flags;
        }

        // Fonction pour appliquer toutes les traductions
        function applyTranslations() {
            // Titre et métadonnées
            document.title = t('ui.title');
            document.getElementById('mainTitle').textContent = `🔐 ${t('ui.title')}`;
            document.getElementById('generatedOnLabel').textContent = t('ui.generatedOn');
            document.getElementById('rootPathLabel').textContent = t('ui.rootPath');
            
            // Filtres
            document.getElementById('filtersTitle').textContent = t('filters.title');
            document.getElementById('userFilterLabel').textContent = t('filters.selectUser');
            document.getElementById('allUsersOption').textContent = t('filters.allUsers');
            document.getElementById('userSearchLabel').textContent = t('filters.searchUser');
            document.getElementById('userSearch').placeholder = t('filters.userPlaceholder');
            document.getElementById('pathFilterLabel').textContent = t('filters.path');
            document.getElementById('pathFilter').placeholder = t('filters.pathPlaceholder');
            document.getElementById('permissionFilterLabel').textContent = t('filters.permissionType');
            document.getElementById('allPermissionsOption').textContent = t('filters.allPermissions');
            
            // Traduire les options de permissions
            const permissionFilter = document.getElementById('permissionFilter');
            if (permissionFilter.options.length > 1) {
                permissionFilter.options[1].text = t('permissions.fullControl');
                permissionFilter.options[2].text = t('permissions.modify');
                permissionFilter.options[3].text = t('permissions.read');
                permissionFilter.options[4].text = t('permissions.write');
            }
            
            // Boutons
            document.getElementById('applyFiltersBtn').innerHTML = t('filters.apply');
            document.getElementById('resetFiltersBtn').innerHTML = t('filters.reset');
            document.getElementById('exportBtn').innerHTML = t('filters.export');
            
            // Statistiques
            document.getElementById('statFoldersLabel').textContent = t('stats.foldersAnalyzed');
            document.getElementById('statUsersLabel').textContent = t('stats.uniqueUsers');
            document.getElementById('statErrorsLabel').textContent = t('stats.accessErrors');
            document.getElementById('statFilteredLabel').textContent = t('stats.visibleResults');
            
            // Arbre
            document.getElementById('treeTitle').textContent = t('tree.title');
            document.getElementById('expandAllBtn').innerHTML = t('tree.expandAll');
            document.getElementById('collapseAllBtn').innerHTML = t('tree.collapseAll');
            
            // En-têtes
            document.getElementById('headerFolder').textContent = t('tree.folder');
            document.getElementById('headerUsers').textContent = t('tree.usersGroups');
            document.getElementById('headerOwner').textContent = t('tree.owner');
            document.getElementById('headerDate').textContent = t('tree.lastModified');
            
            // Mise à jour du label des utilisateurs avec le nombre
           const userFilterLabel = document.querySelector('label[for="userFilter"]');
           if (userFilterLabel && allUsers.size > 0) {
               userFilterLabel.textContent = `${t('filters.selectUser')} ${tf('messages.usersFound', {count: allUsers.size})}`;
           }
           
           // Re-render des éléments dynamiques si nécessaire
           if (window.auditData) {
               // Rafraîchir les badges "+X autres"
               document.querySelectorAll('.user-badge').forEach(badge => {
                   if (badge.style.backgroundColor === 'rgb(224, 224, 224)') {
                       const match = badge.textContent.match(/\+(\d+)/);
                       if (match) {
                           badge.textContent = tf('tree.moreUsers', {count: match[1]});
                           badge.title = t('tree.clickForDetails');
                       }
                   }
               });
           }
       }

       // Initialisation avec détection de la langue
       window.addEventListener('DOMContentLoaded', async () => {
           // Charger la langue sauvegardée ou détecter
           const savedLang = localStorage.getItem('auditLang');
           const browserLang = navigator.language.substring(0, 2);
           const defaultLang = savedLang || (browserLang === 'fr' ? 'fr' : 'en');
           
           // Configurer le sélecteur
           document.getElementById('langSelector').value = defaultLang;
           document.getElementById('langSelector').addEventListener('change', (e) => {
               loadTranslations(e.target.value);
           });
           
           // Charger les traductions
           await loadTranslations(defaultLang);
           
           // Charger les données
           calculateStats(auditData);
           buildTree(auditData, document.getElementById('treeView'));
           populateUsersList();
           updateVisibleStats();
       });

       // Calculer les statistiques
       function calculateStats(node) {
           folderCount++;
           
           if (!node.IsAccessible) {
               errorCount++;
           }
           
           // Collecter les utilisateurs
           if (node.Permissions) {
               node.Permissions.forEach(p => allUsers.add(p.Identity));
           }
           if (node.InheritedPermissions) {
               node.InheritedPermissions.forEach(p => allUsers.add(p.Identity));
           }
           
           // Récursif pour les enfants
           if (node.Children) {
               node.Children.forEach(child => calculateStats(child));
           }
           
           // Mettre à jour l'affichage (seulement à la racine)
           if (node === auditData) {
               document.getElementById('statFolders').textContent = folderCount;
               document.getElementById('statUsers').textContent = allUsers.size;
               document.getElementById('statErrors').textContent = errorCount;
           }
       }

       // Peupler la liste des utilisateurs
       function populateUsersList() {
           const select = document.getElementById('userFilter');
           
           // Garder la première option
           select.innerHTML = `<option value="" id="allUsersOption">${t('filters.allUsers')}</option>`;
           
           // Trier les utilisateurs
           const sortedUsers = Array.from(allUsers).sort((a, b) => {
               // Trier en mettant les groupes de domaine en premier
               const aDomain = a.includes('\\') ? a.split('\\')[0] : '';
               const bDomain = b.includes('\\') ? b.split('\\')[0] : '';
               
               if (aDomain !== bDomain) {
                   return aDomain.localeCompare(bDomain);
               }
               return a.localeCompare(b);
           });
           
           // Grouper par domaine pour une meilleure lisibilité
           let currentDomain = '';
           sortedUsers.forEach(user => {
               const domain = user.includes('\\') ? user.split('\\')[0] : 'LOCAL';
               
               // Ajouter un séparateur visuel entre les domaines
               if (domain !== currentDomain && currentDomain !== '') {
                   const separator = document.createElement('option');
                   separator.disabled = true;
                   separator.text = '──────────────';
                   select.appendChild(separator);
               }
               currentDomain = domain;
               
               const option = document.createElement('option');
               option.value = user;
               option.text = user;
               select.appendChild(option);
           });
           
           // Afficher le nombre d'utilisateurs
           const label = document.querySelector('label[for="userFilter"]');
           label.textContent = `${t('filters.selectUser')} ${tf('messages.usersFound', {count: allUsers.size})}`;
       }

       // Construire l'arbre
       function buildTree(node, container, depth = 0) {
           const treeItem = document.createElement('div');
           treeItem.className = 'tree-item';
           treeItem.setAttribute('data-path', node.Path);
   
           const treeRow = document.createElement('div');
           treeRow.className = 'tree-row';
           if (!node.IsAccessible) treeRow.className += ' error';
   
           // Toggle
           const toggle = document.createElement('span');
           toggle.className = 'tree-toggle';
           toggle.textContent = node.Children && node.Children.length > 0 ? '▶' : '';
   
           // Icon
           const icon = document.createElement('span');
           icon.className = 'tree-icon';
           icon.textContent = depth === 0 ? '💾' : (node.IsAccessible ? '📁' : '🔒');
   
           // Name
           const name = document.createElement('span');
           name.className = 'tree-name';
          name.textContent = node.Name || node.Path;
  
          // Info
          const info = document.createElement('div');
          info.className = 'tree-info';
  
          // Collecter TOUS les utilisateurs/groupes uniques
          if (node.IsAccessible) {
              const allPermissions = [...(node.Permissions || []), ...(node.InheritedPermissions || [])];
              const uniqueUsers = new Map();
      
              // Grouper par utilisateur avec leurs permissions
              allPermissions.forEach(p => {
                  if (!uniqueUsers.has(p.Identity)) {
                      uniqueUsers.set(p.Identity, new Set());
                  }
                  uniqueUsers.get(p.Identity).add(p.Rights);
              });
      
              // Container pour les utilisateurs avec classe CSS
              const usersContainer = document.createElement('div');
              usersContainer.className = 'users-container';
              
              // Afficher les 5 premiers utilisateurs
              let userCount = 0;
              uniqueUsers.forEach((rights, identity) => {
                  if (userCount < 5) {
                      const userBadge = document.createElement('span');
                      userBadge.className = 'user-badge';
                      userBadge.textContent = identity;
                      userBadge.title = `Permissions : ${Array.from(rights).join(', ')}`;
                      usersContainer.appendChild(userBadge);
                      userCount++;
                  }
              });
              
              // Si plus de 5 utilisateurs, ajouter un indicateur
              if (uniqueUsers.size > 5) {
                  const moreUsers = document.createElement('span');
                  moreUsers.className = 'user-badge';
                  moreUsers.style.backgroundColor = '#e0e0e0';
                  moreUsers.style.color = '#666';
                  moreUsers.textContent = tf('tree.moreUsers', {count: uniqueUsers.size - 5});
                  moreUsers.title = t('tree.clickForDetails');
                  usersContainer.appendChild(moreUsers);
              }
              
              info.appendChild(usersContainer);
          }
  
          // Propriétaire
          if (node.Owner) {
              const owner = document.createElement('span');
              owner.className = 'tree-owner';
              owner.textContent = node.Owner;
              info.appendChild(owner);
          } else {
              // Placeholder pour maintenir l'alignement
              const owner = document.createElement('span');
              owner.className = 'tree-owner';
              owner.textContent = '-';
              info.appendChild(owner);
          }
  
          // Date
          if (node.LastModified) {
              const date = document.createElement('span');
              date.className = 'tree-date';
              date.textContent = node.LastModified.split(' ')[0];
              info.appendChild(date);
          } else {
              // Placeholder pour maintenir l'alignement
              const date = document.createElement('span');
              date.className = 'tree-date';
              date.textContent = '-';
              info.appendChild(date);
          }
  
          // Assembler la ligne
          treeRow.appendChild(toggle);
          treeRow.appendChild(icon);
          treeRow.appendChild(name);
          treeRow.appendChild(info);
  
          // Click handler
          treeRow.onclick = (e) => {
              e.stopPropagation();
              handleNodeClick(treeItem, node);
          };
  
          treeItem.appendChild(treeRow);
  
          // Enfants
          if (node.Children && node.Children.length > 0) {
              const childrenContainer = document.createElement('div');
              childrenContainer.className = 'tree-children';
      
              node.Children.forEach(child => {
                  buildTree(child, childrenContainer, depth + 1);
              });
      
              treeItem.appendChild(childrenContainer);
          }
  
          container.appendChild(treeItem);
      }

      // Gérer le clic sur un nœud
      function handleNodeClick(treeItem, node) {
          // Toggle expand/collapse
          if (node.Children && node.Children.length > 0) {
              treeItem.classList.toggle('expanded');
              const toggle = treeItem.querySelector('.tree-toggle');
              toggle.textContent = treeItem.classList.contains('expanded') ? '▼' : '▶';
          }
          
          // Sélection
          document.querySelectorAll('.tree-row').forEach(row => row.classList.remove('selected'));
          treeItem.querySelector('.tree-row').classList.add('selected');
          
          // Afficher les détails
          showDetails(node);
      }

        // Afficher les détails
        function showDetails(node) {
            const panel = document.getElementById('detailsPanel');

            let html = `
                <div class="details-header">
                    <h3 style="margin: 0; color: #2c3e50;">${t('details.title')}</h3>
                    <button class="details-close" onclick="closeDetails()">${t('details.close')}</button>
                </div>

                <div style="background-color: #f8f9fa; padding: 8px 12px; border-radius: 4px; font-size: 14px; margin-bottom: 15px; word-break: break-all; font-family: 'Consolas', 'Monaco', monospace;">
                    📍 ${node.Path}
                </div>

                <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(400px, 1fr)); gap: 20px;">
            `;

            // Informations générales
            html += `
                <div style="background: #f8f9fa; padding: 15px; border-radius: 6px;">
                    <h4 style="margin-bottom: 15px; color: #2c3e50;">${t('details.generalInfo')}</h4>
                    <table style="width: 100%; font-size: 13px;">
                        <tr>
                            <td style="padding: 4px 0; color: #7f8c8d;">${t('details.owner')} :</td>
                            <td style="padding: 4px 0;"><strong>${node.Owner || 'N/A'}</strong></td>
                        </tr>
                        <tr>
                            <td style="padding: 4px 0; color: #7f8c8d;">${t('details.lastModified')} :</td>
                            <td style="padding: 4px 0;"><strong>${node.LastModified || 'N/A'}</strong></td>
                        </tr>
                        <tr>
                            <td style="padding: 4px 0; color: #7f8c8d;">${t('details.inheritance')} :</td>
                            <td style="padding: 4px 0;"><strong style="color: ${node.HasInheritance ? '#27ae60' : '#e74c3c'}">
                                ${node.HasInheritance ? t('details.inheritanceEnabled') : t('details.inheritanceDisabled')}
                            </strong></td>
                        </tr>
                        <tr>
                            <td style="padding: 4px 0; color: #7f8c8d;">${t('details.state')} :</td>
                            <td style="padding: 4px 0;"><strong style="color: ${node.IsAccessible ? '#27ae60' : '#e74c3c'}">
                                ${node.IsAccessible ? t('details.accessible') : t('details.accessError')}
                            </strong></td>
                        </tr>
                        ${!node.IsAccessible ? `
                        <tr>
                            <td style="padding: 4px 0; color: #7f8c8d;">${t('details.errorMessage')} :</td>
                            <td style="padding: 4px 0; color: #e74c3c;"><em>${node.ErrorMessage || t('details.unknownError')}</em></td>
                        </tr>
                        ` : ''}
                    </table>
                </div>
            `;

            // Permissions explicites détaillées
            if (node.Permissions && node.Permissions.length > 0) {
                html += `
                    <div style="background: #f8f9fa; padding: 15px; border-radius: 6px;">
                        <h4 style="margin-bottom: 15px; color: #2c3e50;">${t('details.explicitPermissions')} (${node.Permissions.length})</h4>
                        <table class="permissions-table">
                            <thead>
                                <tr>
                                    <th>${t('details.userGroup')}</th>
                                    <th>${t('details.rights')}</th>
                                    <th>${t('details.type')}</th>
                                    <th>${t('details.inheritanceCol')}</th>
                                    <th>${t('details.propagation')}</th>
                                </tr>
                            </thead>
                            <tbody>
                `;

                node.Permissions.forEach(p => {
                    html += `
                        <tr>
                            <td><strong>${p.Identity}</strong></td>
                            <td>${translatePermission(p.Rights)}</td>
                            <td class="${p.AccessType === 'Autoriser' ? 'permission-type-allow' : 'permission-type-deny'}">
                                ${p.AccessType === 'Autoriser' ? t('accessTypes.allow') : t('accessTypes.deny')}
                            </td>
                            <td>
                                ${p.InheritanceFlags && p.InheritanceFlags !== 'None' ? `<span class="inheritance-badge">${translateInheritanceFlags(p.InheritanceFlags)}</span>` : '-'}
                            </td>
                            <td>
                                ${p.PropagationFlags && p.PropagationFlags !== 'None' ? `<span class="inheritance-badge">${translateInheritanceFlags(p.PropagationFlags)}</span>` : '<span style="color: #999;">-</span>'}
                            </td>
                        </tr>
                    `;
                });

                html += `
                            </tbody>
                        </table>
                    </div>
                `;
            }

            // Permissions héritées détaillées
            if (node.InheritedPermissions && node.InheritedPermissions.length > 0) {
                html += `
                    <div style="background: #f8f9fa; padding: 15px; border-radius: 6px;">
                        <h4 style="margin-bottom: 15px; color: #2c3e50;">${t('details.inheritedPermissions')} (${node.InheritedPermissions.length})</h4>
                        <table class="permissions-table">
                            <thead>
                                <tr>
                                    <th>${t('details.userGroup')}</th>
                                    <th>${t('details.rights')}</th>
                                    <th>${t('details.type')}</th>
                                    <th>${t('details.inheritanceCol')}</th>
                                    <th>${t('details.propagation')}</th>
                                </tr>
                            </thead>
                            <tbody>
                `;

                node.InheritedPermissions.forEach(p => {
                    html += `
                        <tr>
                            <td><strong>${p.Identity}</strong></td>
                            <td>${translatePermission(p.Rights)}</td>
                            <td class="${p.AccessType === 'Autoriser' ? 'permission-type-allow' : 'permission-type-deny'}">
                                ${p.AccessType === 'Autoriser' ? t('accessTypes.allow') : t('accessTypes.deny')}
                            </td>
                            <td>
                                ${p.InheritanceFlags && p.InheritanceFlags !== 'None' ? `<span class="inheritance-badge">${translateInheritanceFlags(p.InheritanceFlags)}</span>` : '-'}
                            </td>
                            <td>
                                ${p.PropagationFlags && p.PropagationFlags !== 'None' ? `<span class="inheritance-badge">${translateInheritanceFlags(p.PropagationFlags)}</span>` : '<span style="color: #999;">-</span>'}
                            </td>
                        </tr>
                    `;
                });

                html += `
                            </tbody>
                        </table>
                    </div>
                `;
            }

            // Résumé des droits effectifs
            html += `
                <div style="background: #fff3e0; padding: 15px; border-radius: 6px; grid-column: 1 / -1;">
                    <h4 style="margin-bottom: 10px; color: #ef6c00;">${t('details.summary')}</h4>
                    <p style="font-size: 13px; line-height: 1.6;">
                        ${tf('details.summaryText', {
                            total: (node.Permissions?.length || 0) + (node.InheritedPermissions?.length || 0),
                            users: countUniqueUsers(node)
                        })}
                        ${!node.HasInheritance ? '<br>' + t('details.inheritanceWarning') : ''}
                    </p>
                </div>
            `;

            html += `</div>`;

            panel.innerHTML = html;
            panel.classList.add('active');

            // Réduire la largeur du contenu principal
            document.querySelector('.container').classList.add('panel-open');
        }

       // Fonction pour fermer le panneau de détails
       function closeDetails() {
           document.getElementById('detailsPanel').classList.remove('active');
           document.querySelector('.container').classList.remove('panel-open');
       }

       // Fonction helper pour compter les utilisateurs uniques
       function countUniqueUsers(node) {
           const users = new Set();
           if (node.Permissions) {
               node.Permissions.forEach(p => users.add(p.Identity));
           }
           if (node.InheritedPermissions) {
               node.InheritedPermissions.forEach(p => users.add(p.Identity));
           }
           return users.size;
       }
   

      // Fonctions de filtrage
      function applyFilters() {
           const userFilter = document.getElementById('userFilter').value.toLowerCase();
           const userSearch = document.getElementById('userSearch').value.toLowerCase();
           const finalUserFilter = userSearch || userFilter; // Priorité à la recherche libre
           const pathFilter = document.getElementById('pathFilter').value.toLowerCase();
           const permFilter = document.getElementById('permissionFilter').value;
   
           // Réinitialiser la visibilité
           visibleCount = 0;
   
           // Appliquer le filtre récursivement
           const hasVisibleContent = filterTree(auditData, finalUserFilter, pathFilter, permFilter);
   
           // Si aucun résultat, afficher un message
           if (visibleCount === 0 && (finalUserFilter || pathFilter || permFilter)) {
               alert(t('messages.noResults'));
           }
   
           updateVisibleStats();
       }

      function filterTree(node, userFilter, pathFilter, permFilter) {
           // Remplacer la ligne problématique par :
            let treeItem;
            try {
                const escapedPath = CSS.escape(node.Path);
                treeItem = document.querySelector(`[data-path="${escapedPath}"]`);
            } catch (e) {
                treeItem = Array.from(document.querySelectorAll('.tree-item'))
                    .find(item => item.getAttribute('data-path') === node.Path);
            }
          if (!treeItem) return false;
  
          let nodeMatches = true;
  
          // Filtrer par chemin
          if (pathFilter && !node.Path.toLowerCase().includes(pathFilter)) {
              nodeMatches = false;
          }
  
          // Filtrer par utilisateur (vérifier dans toutes les permissions)
          if (userFilter && nodeMatches) {
              const allPermissions = [
                  ...(node.Permissions || []), 
                  ...(node.InheritedPermissions || [])
              ];
      
              const hasUser = allPermissions.some(p => {
                  // Normaliser la comparaison (gérer les variations de casse et format)
                  const identity = p.Identity.toLowerCase();
                  return identity.includes(userFilter) || 
                         identity.replace(/\s/g, '').includes(userFilter.replace(/\s/g, ''));
              });
      
              if (!hasUser) nodeMatches = false;
          }
  
          // Filtrer par type de permission
          if (permFilter && nodeMatches) {
              const allPermissions = [
                  ...(node.Permissions || []), 
                  ...(node.InheritedPermissions || [])
              ];
      
              const hasPerm = allPermissions.some(p => p.Rights === permFilter);
              if (!hasPerm) nodeMatches = false;
          }
  
          // Vérifier récursivement les enfants
          let hasVisibleChild = false;
          if (node.Children && node.Children.length > 0) {
              node.Children.forEach(child => {
                  if (filterTree(child, userFilter, pathFilter, permFilter)) {
                      hasVisibleChild = true;
                  }
              });
          }
  
          // Déterminer la visibilité finale
          const isVisible = nodeMatches || hasVisibleChild;
  
          if (isVisible) {
              treeItem.classList.remove('hidden');
              visibleCount++;
      
              // Si c'est visible à cause d'un enfant, s'assurer que le chemin est développé
              if (!nodeMatches && hasVisibleChild) {
                  treeItem.classList.add('expanded');
                  const toggle = treeItem.querySelector('.tree-toggle');
                  if (toggle && toggle.textContent) toggle.textContent = '▼';
              }
      
              // Mettre en évidence les correspondances directes
              if (nodeMatches && (userFilter || pathFilter || permFilter)) {
                  treeItem.querySelector('.tree-row').style.backgroundColor = '#fff59d';
              } else {
                  treeItem.querySelector('.tree-row').style.backgroundColor = '';
              }
          } else {
              treeItem.classList.add('hidden');
          }
  
          return isVisible;
      }

      function resetFilters() {
           document.getElementById('userFilter').value = '';
           document.getElementById('userSearch').value = ''; // Ajouter cette ligne
           document.getElementById('pathFilter').value = '';
           document.getElementById('permissionFilter').value = '';
   
           // Réinitialiser tous les éléments
           document.querySelectorAll('.tree-item').forEach(item => {
               item.classList.remove('hidden');
               item.querySelector('.tree-row').style.backgroundColor = '';
           });
   
           // Fermer le panneau de détails
           closeDetails();
   
           // Réduire tout sauf la racine
           collapseAll();
   
           updateVisibleStats();
       }

      function updateVisibleStats() {
          const visible = document.querySelectorAll('.tree-item:not(.hidden)').length;
          document.getElementById('statFiltered').textContent = visible;
      }

      // Fonction pour développer uniquement les résultats filtrés
      function expandFiltered() {
          document.querySelectorAll('.tree-item:not(.hidden)').forEach(item => {
              if (item.querySelector('.tree-children')) {
                  item.classList.add('expanded');
                  const toggle = item.querySelector('.tree-toggle');
                  if (toggle && toggle.textContent) toggle.textContent = '▼';
              }
          });
      }

      // Expand/Collapse
      function expandAll() {
          document.querySelectorAll('.tree-item').forEach(item => {
              const childrenContainer = item.querySelector('.tree-children');
              if (childrenContainer && childrenContainer.children.length > 0) {
                  item.classList.add('expanded');
                  const toggle = item.querySelector('.tree-toggle');
                  if (toggle) toggle.textContent = '▼';
              }
          });
      }

      function collapseAll() {
          document.querySelectorAll('.tree-item').forEach(item => {
              // Ne pas réduire le niveau racine
              if (item.getAttribute('data-path') !== auditData.Path) {
                  item.classList.remove('expanded');
                  const toggle = item.querySelector('.tree-toggle');
                  if (toggle && toggle.textContent !== '') toggle.textContent = '▶';
              }
          });
      }

        // Export CSV
        function exportToCSV() {
            try {
                // Fonction pour échapper les valeurs CSV
                function escapeCSV(value) {
                    if (!value) return '';
                    return value.toString().replace(/"/g, '""');
                }

                // Utiliser les traductions du fichier JSON
                const headers = `${t('csv.headers.path')};${t('csv.headers.owner')};${t('csv.headers.user')};${t('csv.headers.permission')};${t('csv.headers.type')};${t('csv.headers.inherited')};${t('csv.headers.lastModified')}`;
        
                // Créer le CSV avec les en-têtes traduits
                let csv = headers + '\n';
        
                // Ajouter le BOM UTF-8 pour Excel
                csv = '\ufeff' + csv;
        
                // Fonction récursive pour traiter les nœuds
                function processNode(node) {
                    // Traiter les permissions explicites
                    if (node.Permissions) {
                        node.Permissions.forEach(p => {
                            const translatedRights = translatePermission(p.Rights);
                            const translatedType = p.AccessType === 'Autoriser' ? t('accessTypes.allow') : t('accessTypes.deny');
                            csv += `"${escapeCSV(node.Path)}";"${escapeCSV(node.Owner)}";"${escapeCSV(p.Identity)}";"${escapeCSV(translatedRights)}";"${escapeCSV(translatedType)}";"${t('csv.values.no')}";"${escapeCSV(node.LastModified)}"\n`;
                        });
                    }
            
                    // Traiter les permissions héritées
                    if (node.InheritedPermissions) {
                        node.InheritedPermissions.forEach(p => {
                            const translatedRights = translatePermission(p.Rights);
                            const translatedType = p.AccessType === 'Autoriser' ? t('accessTypes.allow') : t('accessTypes.deny');
                            csv += `"${escapeCSV(node.Path)}";"${escapeCSV(node.Owner)}";"${escapeCSV(p.Identity)}";"${escapeCSV(translatedRights)}";"${escapeCSV(translatedType)}";"${t('csv.values.yes')}";"${escapeCSV(node.LastModified)}"\n`;
                        });
                    }
            
                    // Traiter les enfants récursivement
                    if (node.Children) {
                        node.Children.forEach(child => processNode(child));
                    }
                }
        
                // Traiter toutes les données
                processNode(auditData);
        
                // Créer le nom du fichier avec timestamp
                const now = new Date();
                const timestamp = now.toISOString().replace(/[:.]/g, '-').slice(0, -5);
                const filename = currentLang === 'en' 
                    ? `ntfs_audit_export_${timestamp}.csv`
                    : `audit_ntfs_export_${timestamp}.csv`;
        
                // Créer et télécharger le fichier
                const blob = new Blob([csv], { type: 'text/csv;charset=utf-8;' });
                const link = document.createElement('a');
                link.href = URL.createObjectURL(blob);
                link.download = filename;
                document.body.appendChild(link);
                link.click();
                document.body.removeChild(link);
        
                // Libérer l'URL
                setTimeout(() => {
                    URL.revokeObjectURL(link.href);
                }, 100);
        
            } catch (error) {
                console.error('Erreur lors de l\'export CSV:', error);
                alert(t('messages.exportError'));
            }
        }
       
   </script>
</body>
</html>
'@

 # Remplacer les placeholders
 $htmlContent = $htmlTemplate -replace '{DATE}', (Get-Date -Format "dd/MM/yyyy HH:mm:ss")
 $htmlContent = $htmlContent -replace '{ROOT_PATH}', $AuditData.Path
 $htmlContent = $htmlContent -replace '{JSON_DATA}', $jsonContent
 
 # Écrire le fichier HTML
 $htmlContent | Out-File -FilePath $OutputFile -Encoding UTF8
}

# ================================
# EXÉCUTION PRINCIPALE
# ================================

Write-Host "`n╔══════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║              AUDIT DES PERMISSIONS NTFS                      ║" -ForegroundColor Cyan
Write-Host "║                    Version Optimisée                         ║" -ForegroundColor Cyan
Write-Host "╚══════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan

Write-Host "`nConfiguration :" -ForegroundColor White
Write-Host "  • Chemin : $Path" -ForegroundColor Gray
Write-Host "  • Profondeur max : $(if ($MaxDepth -eq [int]::MaxValue) { 'Illimitée' } else { $MaxDepth })" -ForegroundColor Gray
Write-Host "  • Mode : $(if ($UseParallel) { "Parallèle ($MaxThreads threads)" } else { 'Séquentiel' })" -ForegroundColor Gray

# Créer le dossier de sortie
if (-not (Test-Path $OutputPath)) {
  New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
}

# Pré-charger les SID communs
Preload-CommonSIDs

# Estimer le nombre de dossiers
Write-Host "`nEstimation du nombre de dossiers..." -ForegroundColor Yellow
$script:estimatedTotal = (Get-ChildItem -Path $Path -Directory -Recurse -Force -ErrorAction SilentlyContinue | Measure-Object).Count

if ($script:estimatedTotal -gt 50000 -and $MaxDepth -eq [int]::MaxValue) {
    Write-Warning "Volume très important détecté (>50000 dossiers)"
    Write-Warning "Recommandation : Limiter la profondeur d'analyse avec -MaxDepth"
    $response = Read-Host "Continuer sans limite de profondeur ? (O/N)"
    if ($response -ne 'O' -and $response -ne 'o') {
        exit
    }
}

# Décider automatiquement du mode si non spécifié
if (-not $PSBoundParameters.ContainsKey('UseParallel')) {
   $UseParallel = $script:estimatedTotal -gt 1000
   if ($UseParallel) {
       Write-Host "Mode parallèle activé automatiquement (>1000 dossiers détectés)" -ForegroundColor Yellow
   }
}

Write-Host "Nombre de dossiers estimé : $script:estimatedTotal" -ForegroundColor White

# Lancer l'analyse
Write-Host "`nAnalyse en cours..." -ForegroundColor Green
$startTime = Get-Date

try {
  $auditResults = Get-NTFSPermissions -FolderPath $Path -MaxDepth $MaxDepth
  
  Write-Host "`n`nAnalyse terminée !" -ForegroundColor Green
  
  # Afficher les statistiques du cache
  Write-Host "`nStatistiques du cache SID : $($script:sidCache.Count) entrées" -ForegroundColor Gray
  
  # Exporter en JSON
  $jsonFile = Join-Path $OutputPath "audit_data.json"
  $auditResults | ConvertTo-Json -Depth 100 | Out-File -FilePath $jsonFile -Encoding UTF8
  
  # Générer le rapport HTML
  $htmlFile = Join-Path $OutputPath "audit_report.html"
  New-HTMLReport -AuditData $auditResults -JsonFile $jsonFile -OutputFile $htmlFile
  
  # Statistiques finales
  $endTime = Get-Date
  $duration = $endTime - $startTime
  
   Write-Host "`n╔══════════════════════════════════════════════════════════════╗" -ForegroundColor Green
   Write-Host "║                    ANALYSE TERMINÉE                          ║" -ForegroundColor Green
   Write-Host "╚══════════════════════════════════════════════════════════════╝" -ForegroundColor Green

   Write-Host "`nRésumé :" -ForegroundColor White
   Write-Host "  • Durée : $($duration.ToString('hh\:mm\:ss'))" -ForegroundColor Gray
   Write-Host "  • Dossiers analysés : $([ProgressCounter]::GetValue())" -ForegroundColor Gray
   Write-Host "  • Vitesse : $([math]::Round([ProgressCounter]::GetValue() / $duration.TotalSeconds, 2)) dossiers/seconde" -ForegroundColor Gray

   # Génération des fichiers de langue
   Write-Host "  • Génération des fichiers de langue..." -ForegroundColor Gray
   New-LanguageFiles -OutputPath $OutputPath

   # Afficher tous les fichiers générés
   Write-Host "  • Fichiers générés :" -ForegroundColor Gray
   Write-Host "    - $jsonFile" -ForegroundColor Cyan
   Write-Host "    - $htmlFile" -ForegroundColor Cyan
   Write-Host "    - $(Join-Path $OutputPath 'lang\fr.json')" -ForegroundColor Cyan
   Write-Host "    - $(Join-Path $OutputPath 'lang\en.json')" -ForegroundColor Cyan
  
  # Ouvrir le rapport HTML
  $openReport = Read-Host "`nVoulez-vous ouvrir le rapport maintenant ? (O/N)"
  if ($openReport -eq 'O' -or $openReport -eq 'o') {
      Start-Process $htmlFile
  }
}
catch {
  Write-Host "`nERREUR : $_" -ForegroundColor Red
  Write-Host $_.ScriptStackTrace -ForegroundColor Red
}

