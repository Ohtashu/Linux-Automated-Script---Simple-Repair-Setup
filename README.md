# Linux System Integrity Repair & Optimizer

A powerful, automated Bash script designed to audit, repair, and optimize Linux systems. It supports major distribution families (Debian/Ubuntu, Arch, Fedora) and handles everything from corrupted packages to hardware health checks.

## 🚀 Features

### 🛠️ System Repair
- **Package Integrity:** Automatically detects and fixes broken or corrupted packages using `debsums` (Debian), `pacman -Qk` (Arch), or `rpm -V` (Fedora).
- **Service & Logic:** Checks and repairs Snap and Flatpak installations.
- **Kernel & Libraries:** Verifies kernel module dependencies and updates dynamic linker caches.
- **Filesystem Audit:** Monitors logs for filesystem errors and schedules `fsck` on next boot if issues are detected.

### 🔍 Hardware Diagnostics
- **SSD Support:** Checks for TRIM support and runs manual TRIM operations to maintain performance.
- **HDD Support:** Scans for bad/pending sectors and attempts to force reallocation to safe areas.
- **SMART Monitoring:** Real-time health diagnostics for all physical drives.

### ⚡ Optimizations (Arch Linux)
- **Gaming:** Applies sysctl tweaks (swappiness, inotify) and installs essential gaming tools like GameMode and MangoHud.
- **Development:** Optimizes file watcher limits (max_user_watches) for large IDEs and repositories.
- **Essentials:** One-click installation for common tools like git, vim, curl, and base-devel.

## 📋 Prerequisites
- **OS:** Debian/Ubuntu, Arch Linux, Fedora, or their derivatives.
- **Permissions:** Root/Sudo access is required.

## 💻 Usage

1. **Clone the repository:**
   ```bash
   git clone [https://github.com/yourusername/linux-integrity-repair.git](https://github.com/yourusername/linux-integrity-repair.git)
   cd linux-integrity-repair
