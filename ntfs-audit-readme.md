# 🔐 NTFS Permissions Audit Tool

Un outil PowerShell professionnel pour auditer les permissions NTFS avec export HTML interactif et support multilingue.

![PowerShell](https://img.shields.io/badge/PowerShell-5.1+-blue.svg)
![Platform](https://img.shields.io/badge/Platform-Windows-green.svg)
![License](https://img.shields.io/badge/License-MIT-yellow.svg)

## 📋 Table des matières

- [Fonctionnalités](#-fonctionnalités)
- [Prérequis](#-prérequis)
- [Installation](#-installation)
- [Utilisation](#-utilisation)
- [Paramètres](#-paramètres)
- [Exemples](#-exemples)
- [Interface HTML](#-interface-html)
- [Performances](#-performances)
- [Dépannage](#-dépannage)
- [Structure des fichiers](#-structure-des-fichiers)
- [FAQ](#-faq)

## ✨ Fonctionnalités

### 🎯 Fonctionnalités principales

- **📁 Sélecteur de dossier graphique** : Interface intuitive pour choisir le dossier à analyser
- **🚀 Traitement parallèle** : Optimisé pour les gros volumes (activation automatique > 1000 dossiers)
- **🌍 Support multilingue** : Interface complète en Français et Anglais
- **📊 Export CSV** : Export des données avec en-têtes traduits
- **🔍 Filtres avancés** : Recherche par utilisateur, chemin, type de permission
- **📱 Interface responsive** : S'adapte à toutes les tailles d'écran

### 🔧 Fonctionnalités techniques

- **Cache SID optimisé** : Résolution rapide des identifiants de sécurité
- **Gestion des erreurs** : Capture et affichage des erreurs d'accès
- **Exclusion de dossiers** : Support des wildcards pour exclure des chemins
- **Profondeur configurable** : Limitation de la récursion pour les grosses arborescences
- **Mode administrateur** : Détection automatique et recommandations

## 📦 Prérequis

- **Windows PowerShell 5.1** ou supérieur
- **Windows 7/Server 2008 R2** ou supérieur
- **Droits de lecture** sur les dossiers à analyser
- **RSAT** (optionnel) : Pour une meilleure résolution des noms AD

### Vérifier votre version PowerShell

```powershell
$PSVersionTable.PSVersion
```

## 📥 Installation

1. **Télécharger le script**
   ```powershell
   # Créer un dossier pour le script
   New-Item -ItemType Directory -Path "C:\Scripts\NTFS-Audit" -Force
   
   # Télécharger le script (remplacer par votre méthode)
   # Copy-Item "dossiers-v5.ps1" -Destination "C:\Scripts\NTFS-Audit\"
   ```

2. **Débloquer le script** (si téléchargé d'Internet)
   ```powershell
   Unblock-File -Path "C:\Scripts\NTFS-Audit\dossiers-v5.ps1"
   ```

3. **Configurer la politique d'exécution** (si nécessaire)
   ```powershell
   Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
   ```

## 🚀 Utilisation

### Utilisation simple (avec sélecteur de dossier)

```powershell
.\dossiers-v5.ps1
```

### Utilisation avec paramètres

```powershell
.\dossiers-v5.ps1 -Path "C:\Partages" -MaxDepth 5 -UseParallel
```

### Mode administrateur (recommandé)

Pour un audit complet, exécutez PowerShell en tant qu'administrateur :

1. Clic droit sur PowerShell
2. "Exécuter en tant qu'administrateur"
3. Naviguer vers le dossier du script
4. Exécuter le script

## 📝 Paramètres

| Paramètre | Type | Par défaut | Description |
|-----------|------|------------|-------------|
| `-Path` | String | (Sélecteur) | Chemin racine à analyser |
| `-OutputPath` | String | Desktop\NTFS_Audit_[date] | Dossier de sortie |
| `-MaxDepth` | Int | Illimité | Profondeur maximale de récursion |
| `-IncludeInherited` | Switch | False | Inclure les permissions héritées |
| `-ExcludeFolders` | String[] | @() | Dossiers à exclure (wildcards supportés) |
| `-UseParallel` | Switch | Auto | Forcer le mode parallèle |
| `-MaxThreads` | Int | Nb CPU | Nombre de threads parallèles |

## 💡 Exemples

### Analyse basique avec sélecteur
```powershell
.\dossiers-v5.ps1
```

### Analyse d'un partage réseau
```powershell
.\dossiers-v5.ps1 -Path "\\serveur\partage" -UseParallel
```

### Analyse limitée en profondeur
```powershell
.\dossiers-v5.ps1 -Path "C:\Data" -MaxDepth 3
```

### Exclure des dossiers
```powershell
.\dossiers-v5.ps1 -Path "D:\" -ExcludeFolders @("*Windows*", "*Program Files*", "*temp*")
```

### Analyse complète avec toutes les options
```powershell
.\dossiers-v5.ps1 `
    -Path "E:\Partages" `
    -OutputPath "C:\Audits\$(Get-Date -Format 'yyyy-MM-dd')" `
    -MaxDepth 5 `
    -ExcludeFolders @("*cache*", "*temp*") `
    -UseParallel `
    -MaxThreads 8 `
    -IncludeInherited
```

## 🖥️ Interface HTML

### Navigation

- **🔍 Filtres** : En haut de page pour rechercher rapidement
- **📊 Statistiques** : Vue d'ensemble en temps réel
- **📁 Arborescence** : Navigation intuitive avec icônes
- **📋 Détails** : Panneau latéral avec informations complètes

### Fonctionnalités interactives

1. **Filtrage dynamique**
   - Sélection par utilisateur
   - Recherche libre
   - Filtre par chemin
   - Filtre par permission

2. **Arborescence**
   - Clic pour développer/réduire
   - Badges utilisateurs
   - Indicateurs visuels (erreurs, propriétaire)

3. **Export CSV**
   - Bouton d'export direct
   - Format compatible Excel
   - Traductions automatiques

### Changement de langue

- Sélecteur en haut à droite
- Traduction instantanée
- Mémorisation du choix

## ⚡ Performances

### Recommandations par volume

| Nombre de dossiers | Mode recommandé | Temps estimé |
|-------------------|-----------------|--------------|
| < 1 000 | Séquentiel (auto) | < 1 minute |
| 1 000 - 10 000 | Parallèle (auto) | 2-10 minutes |
| 10 000 - 50 000 | Parallèle + MaxDepth | 10-30 minutes |
| > 50 000 | Segmenter l'analyse | Variable |

### Optimisations

- **Cache SID** : Évite les résolutions multiples
- **Runspaces** : Traitement parallèle natif
- **Progression** : Feedback en temps réel
- **Mode auto** : Sélection intelligente du mode

## 🔧 Dépannage

### Problèmes courants

#### "Accès refusé" sur certains dossiers
**Solution** : Exécuter en tant qu'administrateur

#### Script bloqué par la politique d'exécution
```powershell
Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process
```

#### Caractères spéciaux dans les chemins
Le script gère automatiquement mais affiche un avertissement

#### Mémoire insuffisante sur gros volumes
**Solution** : Utiliser `-MaxDepth` pour limiter la profondeur

### Messages d'erreur

| Message | Cause | Solution |
|---------|-------|----------|
| "Le chemin n'existe pas" | Chemin invalide | Vérifier le chemin |
| "Impossible d'accéder au dossier" | Permissions insuffisantes | Utiliser un compte avec accès |
| "Volume très important détecté" | > 50 000 dossiers | Utiliser MaxDepth ou segmenter |

## 📁 Structure des fichiers générés

```
Desktop\NTFS_Audit_20250130_143022\
├── audit_data.json          # Données brutes de l'audit
├── audit_report.html        # Rapport interactif
└── lang/                    # Fichiers de traduction
    ├── fr.json             # Traduction française
    └── en.json             # Traduction anglaise
```

## ❓ FAQ

### Q: Puis-je analyser des partages réseau ?
**R:** Oui, utilisez le chemin UNC : `\\serveur\partage`

### Q: Comment limiter l'analyse à certains utilisateurs ?
**R:** Utilisez les filtres dans l'interface HTML après génération

### Q: Le script modifie-t-il les permissions ?
**R:** Non, le script est en lecture seule

### Q: Puis-je personnaliser les traductions ?
**R:** Oui, modifiez les fichiers JSON dans le dossier `lang/`

### Q: Comment analyser plusieurs dossiers ?
**R:** Exécutez le script plusieurs fois ou créez un script wrapper

### Q: Les fichiers sont-ils analysés ?
**R:** Non, seulement les dossiers et leurs permissions

## 📜 Licence

Ce script est fourni "tel quel" sans garantie. Libre d'utilisation et de modification.

## 🤝 Contribution

Pour signaler un bug ou suggérer une amélioration, n'hésitez pas à nous contacter.

---

**Note** : Ce script nécessite des droits appropriés pour lire les ACL. Pour un audit complet, l'exécution en tant qu'administrateur est recommandée.