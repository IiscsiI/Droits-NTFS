# 🔐 NTFS Permissions Audit Tool

A professional PowerShell tool for auditing NTFS permissions with interactive HTML export and multilingual support.

![PowerShell](https://img.shields.io/badge/PowerShell-5.1+-blue.svg)
![Platform](https://img.shields.io/badge/Platform-Windows-green.svg)
![License](https://img.shields.io/badge/License-MIT-yellow.svg)

## 📋 Table of Contents

- [Features](#-features)
- [Prerequisites](#-prerequisites)
- [Installation](#-installation)
- [Usage](#-usage)
- [Parameters](#-parameters)
- [Examples](#-examples)
- [HTML Interface](#-html-interface)
- [Performance](#-performance)
- [Troubleshooting](#-troubleshooting)
- [File Structure](#-file-structure)
- [FAQ](#-faq)

## ✨ Features

### 🎯 Main Features

- **📁 Graphical Folder Selector**: Intuitive interface to choose the folder to analyze
- **🚀 Parallel Processing**: Optimized for large volumes (automatic activation > 1000 folders)
- **🌍 Multilingual Support**: Complete interface in French and English
- **📊 CSV Export**: Data export with translated headers
- **🔍 Advanced Filters**: Search by user, path, permission type
- **📱 Responsive Interface**: Adapts to all screen sizes

### 🔧 Technical Features

- **Optimized SID Cache**: Fast resolution of security identifiers
- **Error Management**: Capture and display of access errors
- **Folder Exclusion**: Wildcard support to exclude paths
- **Configurable Depth**: Recursion limitation for large trees
- **Administrator Mode**: Automatic detection and recommendations

## 📦 Prerequisites

- **Windows PowerShell 5.1** or higher
- **Windows 7/Server 2008 R2** or higher
- **Read permissions** on folders to analyze
- **RSAT** (optional): For better AD name resolution

### Check your PowerShell version

```powershell
$PSVersionTable.PSVersion
```

## 📥 Installation

1. **Download the script**
   ```powershell
   # Create a folder for the script
   New-Item -ItemType Directory -Path "C:\Scripts\NTFS-Audit" -Force
   
   # Download the script (replace with your method)
   # Copy-Item "dossiers-v5.ps1" -Destination "C:\Scripts\NTFS-Audit\"
   ```

2. **Unblock the script** (if downloaded from Internet)
   ```powershell
   Unblock-File -Path "C:\Scripts\NTFS-Audit\dossiers-v5.ps1"
   ```

3. **Configure execution policy** (if necessary)
   ```powershell
   Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
   ```

## 🚀 Usage

### Simple usage (with folder selector)

```powershell
.\dossiers-v5.ps1
```

### Usage with parameters

```powershell
.\dossiers-v5.ps1 -Path "C:\Shares" -MaxDepth 5 -UseParallel
```

### Administrator mode (recommended)

For a complete audit, run PowerShell as administrator:

1. Right-click on PowerShell
2. "Run as administrator"
3. Navigate to the script folder
4. Run the script

## 📝 Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `-Path` | String | (Selector) | Root path to analyze |
| `-OutputPath` | String | Desktop\NTFS_Audit_[date] | Output folder |
| `-MaxDepth` | Int | Unlimited | Maximum recursion depth |
| `-IncludeInherited` | Switch | False | Include inherited permissions |
| `-ExcludeFolders` | String[] | @() | Folders to exclude (wildcards supported) |
| `-UseParallel` | Switch | Auto | Force parallel mode |
| `-MaxThreads` | Int | CPU count | Number of parallel threads |

## 💡 Examples

### Basic analysis with selector
```powershell
.\dossiers-v5.ps1
```

### Network share analysis
```powershell
.\dossiers-v5.ps1 -Path "\\server\share" -UseParallel
```

### Depth-limited analysis
```powershell
.\dossiers-v5.ps1 -Path "C:\Data" -MaxDepth 3
```

### Exclude folders
```powershell
.\dossiers-v5.ps1 -Path "D:\" -ExcludeFolders @("*Windows*", "*Program Files*", "*temp*")
```

### Complete analysis with all options
```powershell
.\dossiers-v5.ps1 `
    -Path "E:\Shares" `
    -OutputPath "C:\Audits\$(Get-Date -Format 'yyyy-MM-dd')" `
    -MaxDepth 5 `
    -ExcludeFolders @("*cache*", "*temp*") `
    -UseParallel `
    -MaxThreads 8 `
    -IncludeInherited
```

## 🖥️ HTML Interface

### Navigation

- **🔍 Filters**: At the top for quick search
- **📊 Statistics**: Real-time overview
- **📁 Tree view**: Intuitive navigation with icons
- **📋 Details**: Side panel with complete information

### Interactive Features

1. **Dynamic Filtering**
   - User selection
   - Free text search
   - Path filter
   - Permission filter

2. **Tree View**
   - Click to expand/collapse
   - User badges
   - Visual indicators (errors, owner)

3. **CSV Export**
   - Direct export button
   - Excel compatible format
   - Automatic translations

### Language Change

- Selector in top right
- Instant translation
- Choice memorization

## ⚡ Performance

### Recommendations by Volume

| Number of folders | Recommended mode | Estimated time |
|------------------|------------------|----------------|
| < 1,000 | Sequential (auto) | < 1 minute |
| 1,000 - 10,000 | Parallel (auto) | 2-10 minutes |
| 10,000 - 50,000 | Parallel + MaxDepth | 10-30 minutes |
| > 50,000 | Segment analysis | Variable |

### Optimizations

- **SID Cache**: Avoids multiple resolutions
- **Runspaces**: Native parallel processing
- **Progress**: Real-time feedback
- **Auto mode**: Intelligent mode selection

## 🔧 Troubleshooting

### Common Issues

#### "Access denied" on some folders
**Solution**: Run as administrator

#### Script blocked by execution policy
```powershell
Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process
```

#### Special characters in paths
The script handles automatically but displays a warning

#### Insufficient memory on large volumes
**Solution**: Use `-MaxDepth` to limit depth

### Error Messages

| Message | Cause | Solution |
|---------|-------|----------|
| "Path does not exist" | Invalid path | Check the path |
| "Cannot access folder" | Insufficient permissions | Use an account with access |
| "Very large volume detected" | > 50,000 folders | Use MaxDepth or segment |

## 📁 Generated File Structure

```
Desktop\NTFS_Audit_20250130_143022\
├── audit_data.json          # Raw audit data
├── audit_report.html        # Interactive report
└── lang/                    # Translation files
    ├── fr.json             # French translation
    └── en.json             # English translation
```

## ❓ FAQ

### Q: Can I analyze network shares?
**A:** Yes, use the UNC path: `\\server\share`

### Q: How to limit analysis to certain users?
**A:** Use filters in the HTML interface after generation

### Q: Does the script modify permissions?
**A:** No, the script is read-only

### Q: Can I customize translations?
**A:** Yes, modify the JSON files in the `lang/` folder

### Q: How to analyze multiple folders?
**A:** Run the script multiple times or create a wrapper script

### Q: Are files analyzed?
**A:** No, only folders and their permissions

## 📜 License

This script is provided "as is" without warranty. Free for use and modification.

## 🤝 Contributing

To report a bug or suggest an improvement, please feel free to contact us.

---

**Note**: This script requires appropriate rights to read ACLs. For a complete audit, running as administrator is recommended.