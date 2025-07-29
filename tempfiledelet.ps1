$dllName = "Neck_F8_Free.dll"
$tempPath = $env:TEMP
$dllFullPath = Join-Path -Path $tempPath -ChildPath $dllName

# TEMP থেকে DLL ডিলিট
if (Test-Path $dllFullPath) {
    try {
        Remove-Item -Path $dllFullPath -Force -ErrorAction Stop
        Write-Host "[+] Deleted $dllFullPath from TEMP folder"
    }
    catch {
        Write-Warning "[-] Failed to delete ${dllFullPath}: ${_}"
    }
} else {
    Write-Host "[*] $dllFullPath not found in TEMP folder"
}

# Recycle Bin থেকে DLL ডিলিট
try {
    $shell = New-Object -ComObject Shell.Application
    $recycleBin = $shell.NameSpace(0xA)  # Recycle Bin folder
    $items = $recycleBin.Items()

    $foundInRecycle = $false
    for ($i = 0; $i -lt $items.Count; $i++) {
        $item = $items.Item($i)
        if ($item.Name -eq $dllName) {
            $foundInRecycle = $true
            $item.InvokeVerb("delete")  # Permanent delete from recycle bin
            Write-Host "[+] Deleted $dllName from Recycle Bin"
            break
        }
    }

    if (-not $foundInRecycle) {
        Write-Host "[*] $dllName not found in Recycle Bin"
    }
}
catch {
    Write-Warning "[-] Failed to delete from Recycle Bin: ${_}"
}
