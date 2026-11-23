<#
.SYNOPSIS
    Read-only memory, CPU, Working Set page breakdown, and PE transitive dependency profiler for LocalEDR daemon.

.DESCRIPTION
    Profiles a running process (typically release ledr-daemon.exe) at 200 ms intervals using Win32
    GetProcessMemoryInfo (PROCESS_MEMORY_COUNTERS_EX2.PrivateWorkingSetSize, with PDH fallback only when unsupported)
    and GetProcessTimes, captures detailed VirtualQueryEx + QueryWorkingSetEx + GetMappedFileNameW snapshots
    at key milestones and spikes, optionally queries SQLite row counts read-only, and performs recursive PE
    static + delay-load import analysis on -DaemonExePath (excluding direct raw-dylib imports).

    Unit convention: 1 MB = 1 MiB = 1,048,576 bytes everywhere.
    Compatible with Windows PowerShell 5.1+ and PowerShell 7+.
#>
[CmdletBinding(DefaultParameterSetName = 'Profile')]
param(
    [Parameter(Mandatory = $true, ParameterSetName = 'Profile')]
    [Alias('Pid', 'ProcessId')]
    [int]$TargetPid,

    [Parameter(Mandatory = $false)]
    [string]$DbPath = '',

    [Parameter(Mandatory = $false)]
    [string]$DaemonExePath = '.\target\release\ledr-daemon.exe',

    [Parameter(Mandatory = $false)]
    [int]$DurationSec = 600,

    [Parameter(Mandatory = $false)]
    [int]$PollMs = 200,

    [Parameter(Mandatory = $false)]
    [int]$DumpCooldownSec = 5,

    [Parameter(Mandatory = $false)]
    [int]$MaxSnapshots = 20,

    [Parameter(Mandatory = $false)]
    [string]$OutDir = '',

    [Parameter(Mandatory = $true, ParameterSetName = 'PeOnly')]
    [switch]$AnalyzePeOnly
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$ONE_MB = 1048576.0
$utf8NoBom = New-Object System.Text.UTF8Encoding($false)

# Native Win32 + PE Transitive Dependency Analyzer compiled via C# (PS 5.1+ compatible)
$nativeSource = @'
using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;

namespace LedrProfiler {
    [StructLayout(LayoutKind.Sequential)]
    public struct PROCESS_MEMORY_COUNTERS_EX2 {
        public uint cb;
        public uint PageFaultCount;
        public ulong PeakWorkingSetSize;
        public ulong WorkingSetSize;
        public ulong QuotaPeakPagedPoolUsage;
        public ulong QuotaPagedPoolUsage;
        public ulong QuotaPeakNonPagedPoolUsage;
        public ulong QuotaNonPagedPoolUsage;
        public ulong PagefileUsage;
        public ulong PeakPagefileUsage;
        public ulong PrivateUsage;
        public ulong PrivateWorkingSetSize;
        public ulong SharedCommitUsage;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct PROCESS_MEMORY_COUNTERS_EX {
        public uint cb;
        public uint PageFaultCount;
        public ulong PeakWorkingSetSize;
        public ulong WorkingSetSize;
        public ulong QuotaPeakPagedPoolUsage;
        public ulong QuotaPagedPoolUsage;
        public ulong QuotaPeakNonPagedPoolUsage;
        public ulong QuotaNonPagedPoolUsage;
        public ulong PagefileUsage;
        public ulong PeakPagefileUsage;
        public ulong PrivateUsage;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct MEMORY_BASIC_INFORMATION {
        public IntPtr BaseAddress;
        public IntPtr AllocationBase;
        public uint AllocationProtect;
        public ushort PartitionId;
        public IntPtr RegionSize;
        public uint State;
        public uint Protect;
        public uint Type;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct PSAPI_WORKING_SET_EX_INFORMATION {
        public IntPtr VirtualAddress;
        public ulong VirtualAttributes;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct SYSTEM_INFO {
        public ushort wProcessorArchitecture;
        public ushort wReserved;
        public uint dwPageSize;
        public IntPtr lpMinimumApplicationAddress;
        public IntPtr lpMaximumApplicationAddress;
        public IntPtr dwActiveProcessorMask;
        public uint dwNumberOfProcessors;
        public uint dwProcessorType;
        public uint dwAllocationGranularity;
        public ushort wProcessorLevel;
        public ushort wProcessorRevision;
    }

    public class MemSampleResult {
        public bool Success;
        public int LastError;
        public bool UsedEx2;
        public uint PageFaultCount;
        public ulong PeakWorkingSetSize;
        public ulong WorkingSetSize;
        public ulong PrivateUsage;
        public ulong PrivateWorkingSetSize;
        public long KernelTime100ns;
        public long UserTime100ns;
    }

    public class SnapshotFileEntry {
        public string Path;
        public string TypeName;
        public string Category;
        public ulong TotalBytes;
        public ulong Shared0Bytes;
        public ulong Shared1Bytes;
        public ulong PageCount;
    }

    public class SnapshotProtectEntry {
        public string ProtectName;
        public ulong TotalBytes;
        public ulong Shared0Bytes;
        public ulong Shared1Bytes;
    }

    public class SnapshotResult {
        public bool Success;
        public string Error;
        public ulong WorkingSetSize;
        public ulong PeakWorkingSetSize;
        public ulong PrivateWorkingSetSize;
        public ulong PrivateUsage;
        public bool UsedEx2;
        public ulong ValidPagesTotal;
        public ulong ValidShared0Pages;
        public ulong ValidShared1Pages;
        public ulong LargePagesCount;
        public ulong QueryWsExFailedChunks;
        public ulong ImageBytes;
        public ulong ImageShared0Bytes;
        public ulong ImageShared1Bytes;
        public ulong MappedBytes;
        public ulong MappedShared0Bytes;
        public ulong MappedShared1Bytes;
        public ulong PrivateBytes;
        public ulong PrivateShared0Bytes;
        public ulong PrivateShared1Bytes;
        public ulong Track2AuthenticodeMappedBytes;
        public ulong Track2AuthenticodeIdleBytes;
        public Dictionary<string, ulong[]> ByCategory = new Dictionary<string, ulong[]>(StringComparer.OrdinalIgnoreCase);
        public List<SnapshotProtectEntry> ByProtect = new List<SnapshotProtectEntry>();
        public List<SnapshotFileEntry> Files = new List<SnapshotFileEntry>();
    }

    public class PeDirectEdge {
        public string Name;
        public string Kind; // "static" or "delay"
        public bool ExcludedRawDylib;
        public string ResolvedTarget;
        public string ResolvedPath;
        public string ResolutionNote;
    }

    public class PeNodeReachability {
        public string DllName;
        public string Kind;
        public string ResolvedPath;
        public bool ReachesCrypt32StaticOnly;
        public bool ReachesCrypt32WithDelay;
        public List<string> Crypt32StaticPath;
        public List<string> Crypt32AnyPath;
        public bool ReachesWintrustStaticOnly;
        public bool ReachesWintrustWithDelay;
        public List<string> WintrustStaticPath;
        public List<string> WintrustAnyPath;
    }

    public class PeUnresolvedEntry {
        public string ParentModule;
        public string ImportName;
        public string ImportKind;
        public string Reason;
    }

    public class PeAnalysisResult {
        public string RootExePath;
        public bool Success;
        public string Error;
        public int ApiSetNamespaceVersion;
        public int ApiSetEntryCount;
        public int TotalModulesVisited;
        public List<string> ExcludedRawDylibNames = new List<string>();
        public List<PeDirectEdge> DirectImports = new List<PeDirectEdge>();
        public List<PeNodeReachability> NonExcludedReachability = new List<PeNodeReachability>();
        public List<List<string>> StaticPathsToCrypt32 = new List<List<string>>();
        public List<List<string>> DelayPathsToCrypt32 = new List<List<string>>();
        public List<List<string>> StaticPathsToWintrust = new List<List<string>>();
        public List<List<string>> DelayPathsToWintrust = new List<List<string>>();
        public List<PeUnresolvedEntry> UnresolvedImports = new List<PeUnresolvedEntry>();
    }

    public static class Win32Native {
        public const uint PROCESS_QUERY_INFORMATION = 0x0400;
        public const uint PROCESS_VM_READ = 0x0010;
        public const uint PROCESS_QUERY_LIMITED_INFORMATION = 0x1000;
        public const uint MEM_COMMIT = 0x1000;
        public const uint MEM_PRIVATE = 0x20000;
        public const uint MEM_MAPPED = 0x40000;
        public const uint MEM_IMAGE = 0x1000000;

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, int dwProcessId);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool CloseHandle(IntPtr hObject);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool GetProcessTimes(IntPtr hProcess, out long lpCreationTime, out long lpExitTime, out long lpKernelTime, out long lpUserTime);

        [DllImport("kernel32.dll")]
        public static extern void GetSystemInfo(out SYSTEM_INFO lpSystemInfo);

        [DllImport("psapi.dll", SetLastError = true)]
        public static extern bool GetProcessMemoryInfo(IntPtr Process, out PROCESS_MEMORY_COUNTERS_EX2 ppsmemCounters, uint cb);

        [DllImport("psapi.dll", SetLastError = true, EntryPoint = "GetProcessMemoryInfo")]
        public static extern bool GetProcessMemoryInfoEx(IntPtr Process, out PROCESS_MEMORY_COUNTERS_EX ppsmemCounters, uint cb);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr VirtualQueryEx(IntPtr hProcess, IntPtr lpAddress, out MEMORY_BASIC_INFORMATION lpBuffer, uint dwLength);

        [DllImport("psapi.dll", SetLastError = true)]
        public static extern bool QueryWorkingSetEx(IntPtr hProcess, [In, Out] PSAPI_WORKING_SET_EX_INFORMATION[] pv, uint cb);

        [DllImport("psapi.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern uint GetMappedFileNameW(IntPtr hProcess, IntPtr lpv, StringBuilder lpFilename, uint nSize);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern uint GetLogicalDriveStringsW(uint nBufferLength, [Out] char[] lpBuffer);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern uint QueryDosDeviceW(string lpDeviceName, StringBuilder lpTargetPath, uint ucchMax);

        public static Dictionary<string, string> BuildDeviceDriveMap() {
            var map = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            char[] buf = new char[512];
            uint len = GetLogicalDriveStringsW((uint)buf.Length, buf);
            if (len == 0) return map;
            string all = new string(buf, 0, (int)len);
            string[] drives = all.Split(new char[] { '\0' }, StringSplitOptions.RemoveEmptyEntries);
            StringBuilder target = new StringBuilder(1024);
            foreach (string d in drives) {
                string dev = d.TrimEnd('\\');
                target.Clear();
                uint res = QueryDosDeviceW(dev, target, (uint)target.Capacity);
                if (res > 0) {
                    string ntPrefix = target.ToString().Split('\0')[0];
                    if (!string.IsNullOrEmpty(ntPrefix) && !map.ContainsKey(ntPrefix)) {
                        map[ntPrefix] = dev;
                    }
                }
            }
            return map;
        }

        public static string NormalizeDevicePath(string rawPath, Dictionary<string, string> deviceMap) {
            if (string.IsNullOrEmpty(rawPath)) return rawPath;
            string bestKey = null;
            foreach (var k in deviceMap.Keys) {
                if (rawPath.StartsWith(k + "\\", StringComparison.OrdinalIgnoreCase) ||
                    string.Equals(rawPath, k, StringComparison.OrdinalIgnoreCase)) {
                    if (bestKey == null || k.Length > bestKey.Length) bestKey = k;
                }
            }
            if (bestKey != null) {
                return deviceMap[bestKey] + rawPath.Substring(bestKey.Length);
            }
            return rawPath;
        }

        public static MemSampleResult PollSample(IntPtr hProcess) {
            var res = new MemSampleResult();
            PROCESS_MEMORY_COUNTERS_EX2 pmc2 = new PROCESS_MEMORY_COUNTERS_EX2();
            pmc2.cb = (uint)Marshal.SizeOf(typeof(PROCESS_MEMORY_COUNTERS_EX2));
            if (GetProcessMemoryInfo(hProcess, out pmc2, pmc2.cb)) {
                res.Success = true;
                res.UsedEx2 = true;
                res.PageFaultCount = pmc2.PageFaultCount;
                res.PeakWorkingSetSize = pmc2.PeakWorkingSetSize;
                res.WorkingSetSize = pmc2.WorkingSetSize;
                res.PrivateUsage = pmc2.PrivateUsage;
                res.PrivateWorkingSetSize = pmc2.PrivateWorkingSetSize;
            } else {
                PROCESS_MEMORY_COUNTERS_EX pmc1 = new PROCESS_MEMORY_COUNTERS_EX();
                pmc1.cb = (uint)Marshal.SizeOf(typeof(PROCESS_MEMORY_COUNTERS_EX));
                if (GetProcessMemoryInfoEx(hProcess, out pmc1, pmc1.cb)) {
                    res.Success = true;
                    res.UsedEx2 = false;
                    res.PageFaultCount = pmc1.PageFaultCount;
                    res.PeakWorkingSetSize = pmc1.PeakWorkingSetSize;
                    res.WorkingSetSize = pmc1.WorkingSetSize;
                    res.PrivateUsage = pmc1.PrivateUsage;
                    res.PrivateWorkingSetSize = 0;
                } else {
                    res.Success = false;
                    res.LastError = Marshal.GetLastWin32Error();
                    return res;
                }
            }

            long ct, et, kt, ut;
            if (GetProcessTimes(hProcess, out ct, out et, out kt, out ut)) {
                res.KernelTime100ns = kt;
                res.UserTime100ns = ut;
            }
            return res;
        }

        private static string ProtectToString(uint protect) {
            uint baseProt = protect & 0xFF;
            string name;
            switch (baseProt) {
                case 0x01: name = "PAGE_NOACCESS"; break;
                case 0x02: name = "PAGE_READONLY"; break;
                case 0x04: name = "PAGE_READWRITE"; break;
                case 0x08: name = "PAGE_WRITECOPY"; break;
                case 0x10: name = "PAGE_EXECUTE"; break;
                case 0x20: name = "PAGE_EXECUTE_READ"; break;
                case 0x40: name = "PAGE_EXECUTE_READWRITE"; break;
                case 0x80: name = "PAGE_EXECUTE_WRITECOPY"; break;
                default: name = string.Format("0x{0:X}", baseProt); break;
            }
            if ((protect & 0x100) != 0) name += "|GUARD";
            if ((protect & 0x200) != 0) name += "|NOCACHE";
            if ((protect & 0x400) != 0) name += "|WRITECOMBINE";
            return name;
        }

        private static string SafeFileName(string path) {
            if (string.IsNullOrEmpty(path)) return string.Empty;
            int idx = path.LastIndexOfAny(new char[] { '\\', '/' });
            return idx >= 0 ? path.Substring(idx + 1) : path;
        }

        private static string CategorizeRegion(uint memType, string normPath, string daemonExePath) {
            if (memType == MEM_PRIVATE) return "private_heap_stack";
            string lower = (normPath ?? string.Empty).ToLowerInvariant();
            string daemonLower = (daemonExePath ?? string.Empty).ToLowerInvariant();
            string daemonName = SafeFileName(daemonLower);
            string fileName = SafeFileName(lower);

            bool isCat = lower.EndsWith(".cat") || lower.Contains("\\catroot");
            bool isAuthDll = fileName == "wintrust.dll" || fileName == "crypt32.dll" ||
                             fileName == "cryptnet.dll" || fileName == "mssip32.dll" ||
                             fileName == "softpub.dll";
            bool isDaemon = (!string.IsNullOrEmpty(daemonLower) && lower == daemonLower) ||
                            (!string.IsNullOrEmpty(daemonName) && fileName == daemonName);
            bool isSqlite = lower.EndsWith("-wal") || lower.EndsWith("-shm") ||
                            (lower.EndsWith(".db") && !lower.Contains("\\windows\\"));
            bool isPeExt = lower.EndsWith(".exe") || lower.EndsWith(".dll") || lower.EndsWith(".sys");

            if (memType == MEM_IMAGE) {
                if (isDaemon) return "daemon_image";
                if (isAuthDll) return "authenticode_dlls";
                if (isCat) return "authenticode_catalogs";
                if (lower.Contains("\\windows\\")) return "other_os_dlls";
                return "other_non_daemon_images";
            }
            if (memType == MEM_MAPPED) {
                if (isCat) return "authenticode_catalogs";
                if (isSqlite) return "sqlite_mapped";
                if (isPeExt && !isDaemon) return "non_daemon_mapped_binary";
                return "other_mapped";
            }
            return "other";
        }

        private static bool IsTrack2AuthenticodeMapped(uint memType, string normPath, string daemonExePath) {
            if (memType != MEM_MAPPED || string.IsNullOrEmpty(normPath)) return false;
            string lower = normPath.ToLowerInvariant();
            string daemonName = SafeFileName((daemonExePath ?? string.Empty).ToLowerInvariant());
            string fileName = SafeFileName(lower);
            if (!string.IsNullOrEmpty(daemonName) && fileName == daemonName) return false;
            if (lower.EndsWith("-shm") || lower.EndsWith("-wal")) return false;
            if (lower.EndsWith(".cat") || lower.Contains("\\catroot")) return true;
            if (lower.EndsWith(".exe") || lower.EndsWith(".dll") || lower.EndsWith(".sys")) return true;
            return false;
        }

        private static bool IsTrack2AuthenticodeIdleArtifact(string normPath) {
            if (string.IsNullOrEmpty(normPath)) return false;
            string lower = normPath.ToLowerInvariant();
            string fileName = SafeFileName(lower);
            if (fileName == "wintrust.dll" || fileName == "crypt32.dll" ||
                fileName == "cryptnet.dll" || fileName == "mssip32.dll" ||
                fileName == "softpub.dll") {
                return true;
            }
            if (lower.EndsWith(".cat") || lower.Contains("\\catroot")) return true;
            return false;
        }

        public static SnapshotResult CaptureDetailedSnapshot(IntPtr hProcess, string daemonExePath) {
            var snap = new SnapshotResult();
            var memBefore = PollSample(hProcess);
            if (!memBefore.Success) {
                snap.Success = false;
                snap.Error = "PollSample failed with Win32 error " + memBefore.LastError;
                return snap;
            }
            snap.WorkingSetSize = memBefore.WorkingSetSize;
            snap.PeakWorkingSetSize = memBefore.PeakWorkingSetSize;
            snap.PrivateWorkingSetSize = memBefore.PrivateWorkingSetSize;
            snap.PrivateUsage = memBefore.PrivateUsage;
            snap.UsedEx2 = memBefore.UsedEx2;

            SYSTEM_INFO sysInfo;
            GetSystemInfo(out sysInfo);
            ulong pageSize = sysInfo.dwPageSize > 0 ? sysInfo.dwPageSize : 4096UL;
            ulong maxAddr = (ulong)sysInfo.lpMaximumApplicationAddress.ToInt64();
            ulong addr = (ulong)sysInfo.lpMinimumApplicationAddress.ToInt64();

            var deviceMap = BuildDeviceDriveMap();
            var allocFileCache = new Dictionary<ulong, string>();
            var fileAgg = new Dictionary<string, SnapshotFileEntry>(StringComparer.OrdinalIgnoreCase);
            var protectAgg = new Dictionary<string, ulong[]>(StringComparer.OrdinalIgnoreCase);
            var catAgg = snap.ByCategory;

            const int CHUNK_PAGES = 4096;
            PSAPI_WORKING_SET_EX_INFORMATION[] wsBuf = new PSAPI_WORKING_SET_EX_INFORMATION[CHUNK_PAGES];
            int wsStructSize = Marshal.SizeOf(typeof(PSAPI_WORKING_SET_EX_INFORMATION));
            uint mbiSize = (uint)Marshal.SizeOf(typeof(MEMORY_BASIC_INFORMATION));
            StringBuilder mappedSb = new StringBuilder(1024);

            while (addr < maxAddr) {
                MEMORY_BASIC_INFORMATION mbi;
                IntPtr ret = VirtualQueryEx(hProcess, new IntPtr((long)addr), out mbi, mbiSize);
                if (ret == IntPtr.Zero) break;

                ulong regionBase = (ulong)mbi.BaseAddress.ToInt64();
                ulong regionSize = (ulong)mbi.RegionSize.ToInt64();
                if (regionSize == 0) break;

                if (mbi.State == MEM_COMMIT) {
                    string normPath = null;
                    if (mbi.Type == MEM_IMAGE || mbi.Type == MEM_MAPPED) {
                        ulong allocBaseKey = (ulong)mbi.AllocationBase.ToInt64();
                        if (!allocFileCache.TryGetValue(allocBaseKey, out normPath)) {
                            mappedSb.Clear();
                            uint fnLen = GetMappedFileNameW(hProcess, mbi.BaseAddress, mappedSb, (uint)mappedSb.Capacity);
                            if (fnLen > 0) {
                                normPath = NormalizeDevicePath(mappedSb.ToString(), deviceMap);
                            } else {
                                normPath = mbi.Type == MEM_IMAGE ? "(unnamed_image)" : "(unnamed_mapped)";
                            }
                            allocFileCache[allocBaseKey] = normPath;
                        }
                    }

                    string typeName = mbi.Type == MEM_IMAGE ? "MEM_IMAGE" :
                                      mbi.Type == MEM_MAPPED ? "MEM_MAPPED" :
                                      mbi.Type == MEM_PRIVATE ? "MEM_PRIVATE" :
                                      string.Format("0x{0:X}", mbi.Type);
                    string protName = ProtectToString(mbi.Protect);
                    string category = CategorizeRegion(mbi.Type, normPath, daemonExePath);

                    ulong totalPagesInRegion = regionSize / pageSize;
                    ulong offsetPages = 0;
                    ulong regionValidPages = 0;
                    ulong regionShared0Pages = 0;
                    ulong regionShared1Pages = 0;

                    while (offsetPages < totalPagesInRegion) {
                        int batch = (int)Math.Min((ulong)CHUNK_PAGES, totalPagesInRegion - offsetPages);
                        for (int i = 0; i < batch; i++) {
                            wsBuf[i].VirtualAddress = new IntPtr((long)(regionBase + (offsetPages + (ulong)i) * pageSize));
                            wsBuf[i].VirtualAttributes = 0;
                        }
                        if (QueryWorkingSetEx(hProcess, wsBuf, (uint)(batch * wsStructSize))) {
                            for (int i = 0; i < batch; i++) {
                                ulong attrs = wsBuf[i].VirtualAttributes;
                                bool valid = (attrs & 1UL) != 0;
                                if (!valid) continue;
                                bool shared = (attrs & (1UL << 15)) != 0;
                                bool largePage = (attrs & (1UL << 23)) != 0;
                                if (largePage) snap.LargePagesCount++;
                                regionValidPages++;
                                if (shared) regionShared1Pages++;
                                else regionShared0Pages++;
                            }
                        } else {
                            snap.QueryWsExFailedChunks++;
                        }
                        offsetPages += (ulong)batch;
                    }

                    if (regionValidPages > 0) {
                        ulong bTotal = regionValidPages * pageSize;
                        ulong bShared0 = regionShared0Pages * pageSize;
                        ulong bShared1 = regionShared1Pages * pageSize;

                        snap.ValidPagesTotal += regionValidPages;
                        snap.ValidShared0Pages += regionShared0Pages;
                        snap.ValidShared1Pages += regionShared1Pages;

                        if (mbi.Type == MEM_IMAGE) {
                            snap.ImageBytes += bTotal;
                            snap.ImageShared0Bytes += bShared0;
                            snap.ImageShared1Bytes += bShared1;
                        } else if (mbi.Type == MEM_MAPPED) {
                            snap.MappedBytes += bTotal;
                            snap.MappedShared0Bytes += bShared0;
                            snap.MappedShared1Bytes += bShared1;
                        } else if (mbi.Type == MEM_PRIVATE) {
                            snap.PrivateBytes += bTotal;
                            snap.PrivateShared0Bytes += bShared0;
                            snap.PrivateShared1Bytes += bShared1;
                        }

                        if (IsTrack2AuthenticodeMapped(mbi.Type, normPath, daemonExePath)) {
                            snap.Track2AuthenticodeMappedBytes += bTotal;
                        }
                        if ((mbi.Type == MEM_IMAGE || mbi.Type == MEM_MAPPED) && IsTrack2AuthenticodeIdleArtifact(normPath)) {
                            snap.Track2AuthenticodeIdleBytes += bTotal;
                        }

                        ulong[] catCounts;
                        if (!catAgg.TryGetValue(category, out catCounts)) {
                            catCounts = new ulong[3];
                            catAgg[category] = catCounts;
                        }
                        catCounts[0] += bTotal;
                        catCounts[1] += bShared0;
                        catCounts[2] += bShared1;

                        ulong[] protCounts;
                        if (!protectAgg.TryGetValue(protName, out protCounts)) {
                            protCounts = new ulong[3];
                            protectAgg[protName] = protCounts;
                        }
                        protCounts[0] += bTotal;
                        protCounts[1] += bShared0;
                        protCounts[2] += bShared1;

                        if (mbi.Type == MEM_IMAGE || mbi.Type == MEM_MAPPED) {
                            string fileKey = typeName + "|" + normPath;
                            SnapshotFileEntry fe;
                            if (!fileAgg.TryGetValue(fileKey, out fe)) {
                                fe = new SnapshotFileEntry {
                                    Path = normPath,
                                    TypeName = typeName,
                                    Category = category
                                };
                                fileAgg[fileKey] = fe;
                            }
                            fe.TotalBytes += bTotal;
                            fe.Shared0Bytes += bShared0;
                            fe.Shared1Bytes += bShared1;
                            fe.PageCount += regionValidPages;
                        }
                    }
                }

                ulong nextAddr = regionBase + regionSize;
                if (nextAddr <= addr) break;
                addr = nextAddr;
            }

            foreach (var kv in protectAgg) {
                snap.ByProtect.Add(new SnapshotProtectEntry {
                    ProtectName = kv.Key,
                    TotalBytes = kv.Value[0],
                    Shared0Bytes = kv.Value[1],
                    Shared1Bytes = kv.Value[2]
                });
            }
            snap.ByProtect.Sort((a, b) => b.TotalBytes.CompareTo(a.TotalBytes));

            snap.Files.AddRange(fileAgg.Values);
            snap.Files.Sort((a, b) => b.TotalBytes.CompareTo(a.TotalBytes));

            snap.Success = true;
            return snap;
        }
    }

    public static class PeDependencyAnalyzer {
        private class SectionInfo {
            public uint VirtualAddress;
            public uint VirtualSize;
            public uint SizeOfRawData;
            public uint PointerToRawData;
        }

        private class ParsedImports {
            public List<string> StaticDlls = new List<string>();
            public List<string> DelayDlls = new List<string>();
        }

        private static string ReadAsciiZ(byte[] data, int offset) {
            if (offset < 0 || offset >= data.Length) return null;
            int end = offset;
            while (end < data.Length && data[end] != 0) end++;
            return Encoding.ASCII.GetString(data, offset, end - offset);
        }

        private static uint RvaToOffset(uint rva, List<SectionInfo> sections, uint sizeOfHeaders) {
            if (rva < sizeOfHeaders) return rva;
            foreach (var s in sections) {
                uint span = Math.Max(s.VirtualSize, s.SizeOfRawData);
                if (rva >= s.VirtualAddress && rva < s.VirtualAddress + span) {
                    return s.PointerToRawData + (rva - s.VirtualAddress);
                }
            }
            return uint.MaxValue;
        }

        private static ParsedImports ParsePeImports(string filePath) {
            byte[] data = File.ReadAllBytes(filePath);
            if (data.Length < 0x40 || data[0] != 0x4D || data[1] != 0x5A) {
                throw new InvalidDataException("Not a valid MZ PE file: " + filePath);
            }
            uint lfanew = BitConverter.ToUInt32(data, 0x3C);
            if (lfanew + 24 > data.Length || BitConverter.ToUInt32(data, (int)lfanew) != 0x00004550) {
                throw new InvalidDataException("Missing PE signature: " + filePath);
            }
            ushort numSections = BitConverter.ToUInt16(data, (int)lfanew + 6);
            ushort optHeaderSize = BitConverter.ToUInt16(data, (int)lfanew + 20);
            int optOffset = (int)lfanew + 24;
            if (optOffset + optHeaderSize > data.Length) {
                throw new InvalidDataException("Truncated PE optional header: " + filePath);
            }

            ushort magic = BitConverter.ToUInt16(data, optOffset);
            bool isPe64 = (magic == 0x020B);
            if (!isPe64 && magic != 0x010B) {
                throw new InvalidDataException("Unsupported PE optional header magic: " + magic);
            }

            uint sizeOfHeaders = BitConverter.ToUInt32(data, optOffset + 60);
            ulong imageBase = isPe64 ? BitConverter.ToUInt64(data, optOffset + 24) : BitConverter.ToUInt32(data, optOffset + 28);
            int dataDirOffset = optOffset + (isPe64 ? 112 : 96);
            uint numRvaAndSizes = BitConverter.ToUInt32(data, optOffset + (isPe64 ? 108 : 92));

            int secTableOffset = optOffset + optHeaderSize;
            var sections = new List<SectionInfo>(numSections);
            for (int i = 0; i < numSections; i++) {
                int so = secTableOffset + i * 40;
                if (so + 40 > data.Length) break;
                sections.Add(new SectionInfo {
                    VirtualSize = BitConverter.ToUInt32(data, so + 8),
                    VirtualAddress = BitConverter.ToUInt32(data, so + 12),
                    SizeOfRawData = BitConverter.ToUInt32(data, so + 16),
                    PointerToRawData = BitConverter.ToUInt32(data, so + 20)
                });
            }

            var result = new ParsedImports();
            var seenStatic = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            var seenDelay = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

            // Directory 1: Static Imports
            if (numRvaAndSizes > 1 && dataDirOffset + 16 <= optOffset + optHeaderSize) {
                uint impRva = BitConverter.ToUInt32(data, dataDirOffset + 8);
                uint impSize = BitConverter.ToUInt32(data, dataDirOffset + 12);
                if (impRva != 0 && impSize != 0) {
                    uint impOff = RvaToOffset(impRva, sections, sizeOfHeaders);
                    if (impOff != uint.MaxValue) {
                        int cur = (int)impOff;
                        while (cur + 20 <= data.Length) {
                            uint oft = BitConverter.ToUInt32(data, cur);
                            uint nameRva = BitConverter.ToUInt32(data, cur + 12);
                            uint ft = BitConverter.ToUInt32(data, cur + 16);
                            if (oft == 0 && nameRva == 0 && ft == 0) break;
                            if (nameRva != 0) {
                                uint nameOff = RvaToOffset(nameRva, sections, sizeOfHeaders);
                                if (nameOff != uint.MaxValue) {
                                    string dll = ReadAsciiZ(data, (int)nameOff);
                                    if (!string.IsNullOrEmpty(dll) && seenStatic.Add(dll)) {
                                        result.StaticDlls.Add(dll);
                                    }
                                }
                            }
                            cur += 20;
                        }
                    }
                }
            }

            // Directory 13: Delay-Load Imports
            if (numRvaAndSizes > 13 && dataDirOffset + 14 * 8 <= optOffset + optHeaderSize) {
                uint delRva = BitConverter.ToUInt32(data, dataDirOffset + 13 * 8);
                uint delSize = BitConverter.ToUInt32(data, dataDirOffset + 13 * 8 + 4);
                if (delRva != 0 && delSize != 0) {
                    uint delOff = RvaToOffset(delRva, sections, sizeOfHeaders);
                    if (delOff != uint.MaxValue) {
                        int cur = (int)delOff;
                        while (cur + 32 <= data.Length) {
                            uint attrs = BitConverter.ToUInt32(data, cur);
                            uint dllNameRaw = BitConverter.ToUInt32(data, cur + 4);
                            uint iatRaw = BitConverter.ToUInt32(data, cur + 12);
                            if (dllNameRaw == 0 && iatRaw == 0) break;
                            uint nameRva = (attrs & 1) != 0 ? dllNameRaw : (uint)(dllNameRaw - (uint)imageBase);
                            if (nameRva != 0) {
                                uint nameOff = RvaToOffset(nameRva, sections, sizeOfHeaders);
                                if (nameOff != uint.MaxValue) {
                                    string dll = ReadAsciiZ(data, (int)nameOff);
                                    if (!string.IsNullOrEmpty(dll) && seenDelay.Add(dll)) {
                                        result.DelayDlls.Add(dll);
                                    }
                                }
                            }
                            cur += 32;
                        }
                    }
                }
            }

            return result;
        }

        private static Dictionary<string, string> LoadApiSetSchema(string schemaPath, out int version, out int count) {
            version = 0;
            count = 0;
            var map = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            if (!File.Exists(schemaPath)) return map;

            byte[] data = File.ReadAllBytes(schemaPath);
            uint lfanew = BitConverter.ToUInt32(data, 0x3C);
            ushort numSections = BitConverter.ToUInt16(data, (int)lfanew + 6);
            ushort optHeaderSize = BitConverter.ToUInt16(data, (int)lfanew + 20);
            int secTableOffset = (int)lfanew + 24 + optHeaderSize;

            int apisetOff = -1;
            for (int i = 0; i < numSections; i++) {
                int so = secTableOffset + i * 40;
                string sname = Encoding.ASCII.GetString(data, so, 8).TrimEnd('\0');
                if (string.Equals(sname, ".apiset", StringComparison.OrdinalIgnoreCase)) {
                    apisetOff = (int)BitConverter.ToUInt32(data, so + 20);
                    break;
                }
            }
            if (apisetOff < 0 || apisetOff + 28 > data.Length) return map;

            version = (int)BitConverter.ToUInt32(data, apisetOff);
            if (version != 6) return map;
            count = (int)BitConverter.ToUInt32(data, apisetOff + 12);
            int entryOffset = (int)BitConverter.ToUInt32(data, apisetOff + 16);

            for (int i = 0; i < count; i++) {
                int eo = apisetOff + entryOffset + i * 24;
                if (eo + 24 > data.Length) break;
                int nameOff = (int)BitConverter.ToUInt32(data, eo + 4);
                int nameLen = (int)BitConverter.ToUInt32(data, eo + 8);
                int hashedLen = (int)BitConverter.ToUInt32(data, eo + 12);
                int valOff = (int)BitConverter.ToUInt32(data, eo + 16);
                int valCount = (int)BitConverter.ToUInt32(data, eo + 20);

                string fullName = Encoding.Unicode.GetString(data, apisetOff + nameOff, nameLen);
                string hashedName = hashedLen > 0 && hashedLen <= nameLen
                    ? Encoding.Unicode.GetString(data, apisetOff + nameOff, hashedLen)
                    : fullName;

                string defaultHost = null;
                for (int v = 0; v < valCount; v++) {
                    int vo = apisetOff + valOff + v * 20;
                    if (vo + 20 > data.Length) break;
                    int parentNameLen = (int)BitConverter.ToUInt32(data, vo + 8);
                    int hostOff = (int)BitConverter.ToUInt32(data, vo + 12);
                    int hostLen = (int)BitConverter.ToUInt32(data, vo + 16);
                    string host = hostLen > 0 ? Encoding.Unicode.GetString(data, apisetOff + hostOff, hostLen) : string.Empty;
                    if (parentNameLen == 0 && !string.IsNullOrEmpty(host)) {
                        defaultHost = host;
                        break;
                    }
                    if (defaultHost == null && !string.IsNullOrEmpty(host)) {
                        defaultHost = host;
                    }
                }
                if (!string.IsNullOrEmpty(defaultHost)) {
                    map[fullName] = defaultHost;
                    if (!map.ContainsKey(hashedName)) map[hashedName] = defaultHost;
                }
            }
            return map;
        }

        private static string ResolveApiSet(string dllName, Dictionary<string, string> apiSetMap) {
            string lower = dllName.ToLowerInvariant();
            if (!lower.StartsWith("api-ms-win-") && !lower.StartsWith("ext-ms-win-")) return null;
            string stem = lower.EndsWith(".dll") ? lower.Substring(0, lower.Length - 4) : lower;
            string host;
            if (apiSetMap.TryGetValue(stem, out host)) return host;
            int lastDash = stem.LastIndexOf('-');
            if (lastDash > 0) {
                string shorter = stem.Substring(0, lastDash);
                if (apiSetMap.TryGetValue(shorter, out host)) return host;
            }
            return null;
        }

        private static string ResolveDllOnDisk(string dllName, string exeDir, string sys32Dir, string sysWowDir) {
            string candidate = Path.Combine(exeDir, dllName);
            if (File.Exists(candidate)) return Path.GetFullPath(candidate);
            candidate = Path.Combine(sys32Dir, dllName);
            if (File.Exists(candidate)) return Path.GetFullPath(candidate);
            string downlevel = Path.Combine(sys32Dir, "downlevel", dllName);
            if (File.Exists(downlevel)) return Path.GetFullPath(downlevel);
            if (!string.IsNullOrEmpty(sysWowDir)) {
                candidate = Path.Combine(sysWowDir, dllName);
                if (File.Exists(candidate)) return Path.GetFullPath(candidate);
            }
            return null;
        }

        private class GraphEdge {
            public string TargetPath;
            public string TargetName;
            public string Kind; // "static" or "delay"
        }

        private static List<string> FindBfsPath(
            string startPath,
            string targetFileNameLower,
            bool allowDelay,
            Dictionary<string, List<GraphEdge>> graph
        ) {
            var q = new Queue<string>();
            var parent = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            var visited = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            q.Enqueue(startPath);
            visited.Add(startPath);

            while (q.Count > 0) {
                string cur = q.Dequeue();
                string curName = Path.GetFileName(cur).ToLowerInvariant();
                if (curName == targetFileNameLower) {
                    var chain = new List<string>();
                    string walk = cur;
                    while (walk != null) {
                        chain.Add(Path.GetFileName(walk));
                        string next;
                        parent.TryGetValue(walk, out next);
                        walk = next;
                    }
                    chain.Reverse();
                    return chain;
                }
                List<GraphEdge> edges;
                if (!graph.TryGetValue(cur, out edges)) continue;
                foreach (var e in edges) {
                    if (!allowDelay && e.Kind == "delay") continue;
                    if (string.IsNullOrEmpty(e.TargetPath)) continue;
                    if (visited.Add(e.TargetPath)) {
                        parent[e.TargetPath] = cur;
                        q.Enqueue(e.TargetPath);
                    }
                }
            }
            return null;
        }

        public static PeAnalysisResult Analyze(string rootExePath) {
            var res = new PeAnalysisResult();
            res.RootExePath = Path.GetFullPath(rootExePath);
            res.ExcludedRawDylibNames.AddRange(new string[] { "wintrust.dll", "crypt32.dll", "winhttp.dll" });
            var excludedSet = new HashSet<string>(res.ExcludedRawDylibNames, StringComparer.OrdinalIgnoreCase);

            try {
                if (!File.Exists(res.RootExePath)) {
                    res.Success = false;
                    res.Error = "Root executable not found: " + res.RootExePath;
                    return res;
                }

                string winDir = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
                string sys32Dir = Path.Combine(winDir, "System32");
                if (Environment.Is64BitOperatingSystem && !Environment.Is64BitProcess) {
                    string sysnative = Path.Combine(winDir, "Sysnative");
                    if (Directory.Exists(sysnative)) sys32Dir = sysnative;
                }
                string sysWowDir = Path.Combine(winDir, "SysWOW64");
                string exeDir = Path.GetDirectoryName(res.RootExePath);

                int apiVer, apiCnt;
                var apiSetMap = LoadApiSetSchema(Path.Combine(sys32Dir, "apisetschema.dll"), out apiVer, out apiCnt);
                res.ApiSetNamespaceVersion = apiVer;
                res.ApiSetEntryCount = apiCnt;

                ParsedImports rootImports = ParsePeImports(res.RootExePath);
                var graph = new Dictionary<string, List<GraphEdge>>(StringComparer.OrdinalIgnoreCase);
                var workQueue = new Queue<string>();
                var visitedModules = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                var unresolvedSeen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

                Action<string, string, string> resolveAndEnqueue = null;
                resolveAndEnqueue = (parentMod, impName, impKind) => {
                    string lowerImp = impName.ToLowerInvariant();
                    string targetName = impName;
                    string note = "direct";
                    if (lowerImp.StartsWith("api-ms-win-") || lowerImp.StartsWith("ext-ms-win-")) {
                        string host = ResolveApiSet(impName, apiSetMap);
                        if (!string.IsNullOrEmpty(host)) {
                            targetName = host;
                            note = "apiset->" + host;
                        } else {
                            string ukey = parentMod + "|" + impName + "|" + impKind;
                            if (unresolvedSeen.Add(ukey)) {
                                res.UnresolvedImports.Add(new PeUnresolvedEntry {
                                    ParentModule = Path.GetFileName(parentMod),
                                    ImportName = impName,
                                    ImportKind = impKind,
                                    Reason = "Unresolved ApiSet contract"
                                });
                            }
                            return;
                        }
                    }

                    string resolvedPath = ResolveDllOnDisk(targetName, exeDir, sys32Dir, sysWowDir);
                    if (string.IsNullOrEmpty(resolvedPath)) {
                        string ukey = parentMod + "|" + impName + "|" + impKind;
                        if (unresolvedSeen.Add(ukey)) {
                            res.UnresolvedImports.Add(new PeUnresolvedEntry {
                                ParentModule = Path.GetFileName(parentMod),
                                ImportName = impName,
                                ImportKind = impKind,
                                Reason = "DLL not found in exeDir/System32/SysWOW64 (target=" + targetName + ")"
                            });
                        }
                        return;
                    }

                    List<GraphEdge> edgeList;
                    if (!graph.TryGetValue(parentMod, out edgeList)) {
                        edgeList = new List<GraphEdge>();
                        graph[parentMod] = edgeList;
                    }
                    edgeList.Add(new GraphEdge {
                        TargetPath = resolvedPath,
                        TargetName = Path.GetFileName(resolvedPath),
                        Kind = impKind
                    });
                    if (visitedModules.Add(resolvedPath)) {
                        workQueue.Enqueue(resolvedPath);
                    }
                };

                var nonExcludedStarts = new List<PeDirectEdge>();
                Action<string, string> handleRootImport = (impName, impKind) => {
                    bool excluded = excludedSet.Contains(impName);
                    string targetName = impName;
                    string note = excluded ? "excluded_raw_dylib" : "direct";
                    if (impName.StartsWith("api-ms-win-", StringComparison.OrdinalIgnoreCase) ||
                        impName.StartsWith("ext-ms-win-", StringComparison.OrdinalIgnoreCase)) {
                        string host = ResolveApiSet(impName, apiSetMap);
                        if (!string.IsNullOrEmpty(host)) {
                            targetName = host;
                            note = (excluded ? "excluded_raw_dylib;" : "") + "apiset->" + host;
                        } else {
                            note = "unresolved_apiset";
                        }
                    }
                    string resolvedPath = (note != "unresolved_apiset")
                        ? ResolveDllOnDisk(targetName, exeDir, sys32Dir, sysWowDir)
                        : null;
                    if (resolvedPath == null && note != "unresolved_apiset") {
                        note = "not_found";
                    }

                    var edge = new PeDirectEdge {
                        Name = impName,
                        Kind = impKind,
                        ExcludedRawDylib = excluded,
                        ResolvedTarget = targetName,
                        ResolvedPath = resolvedPath,
                        ResolutionNote = note
                    };
                    res.DirectImports.Add(edge);

                    if (!excluded) {
                        if (resolvedPath != null) {
                            nonExcludedStarts.Add(edge);
                            if (visitedModules.Add(resolvedPath)) {
                                workQueue.Enqueue(resolvedPath);
                            }
                        } else {
                            res.UnresolvedImports.Add(new PeUnresolvedEntry {
                                ParentModule = Path.GetFileName(res.RootExePath),
                                ImportName = impName,
                                ImportKind = impKind,
                                Reason = note
                            });
                        }
                    }
                };

                foreach (string d in rootImports.StaticDlls) handleRootImport(d, "static");
                foreach (string d in rootImports.DelayDlls) handleRootImport(d, "delay");

                while (workQueue.Count > 0) {
                    string modPath = workQueue.Dequeue();
                    try {
                        ParsedImports imps = ParsePeImports(modPath);
                        foreach (string s in imps.StaticDlls) resolveAndEnqueue(modPath, s, "static");
                        foreach (string d in imps.DelayDlls) resolveAndEnqueue(modPath, d, "delay");
                    } catch (Exception ex) {
                        res.UnresolvedImports.Add(new PeUnresolvedEntry {
                            ParentModule = Path.GetFileName(modPath),
                            ImportName = "<parse_error>",
                            ImportKind = "pe",
                            Reason = ex.Message
                        });
                    }
                }

                res.TotalModulesVisited = visitedModules.Count;

                foreach (var start in nonExcludedStarts) {
                    var cStatic = FindBfsPath(start.ResolvedPath, "crypt32.dll", false, graph);
                    var cAny = FindBfsPath(start.ResolvedPath, "crypt32.dll", true, graph);
                    var wStatic = FindBfsPath(start.ResolvedPath, "wintrust.dll", false, graph);
                    var wAny = FindBfsPath(start.ResolvedPath, "wintrust.dll", true, graph);

                    var nr = new PeNodeReachability {
                        DllName = start.Name,
                        Kind = start.Kind,
                        ResolvedPath = start.ResolvedPath,
                        ReachesCrypt32StaticOnly = (cStatic != null),
                        ReachesCrypt32WithDelay = (cAny != null),
                        Crypt32StaticPath = cStatic,
                        Crypt32AnyPath = cAny,
                        ReachesWintrustStaticOnly = (wStatic != null),
                        ReachesWintrustWithDelay = (wAny != null),
                        WintrustStaticPath = wStatic,
                        WintrustAnyPath = wAny
                    };
                    res.NonExcludedReachability.Add(nr);

                    if (cStatic != null) res.StaticPathsToCrypt32.Add(cStatic);
                    else if (cAny != null) res.DelayPathsToCrypt32.Add(cAny);

                    if (wStatic != null) res.StaticPathsToWintrust.Add(wStatic);
                    else if (wAny != null) res.DelayPathsToWintrust.Add(wAny);
                }

                res.Success = true;
            } catch (Exception ex) {
                res.Success = false;
                res.Error = ex.ToString();
            }
            return res;
        }
    }
}
'@

if (-not ([System.Management.Automation.PSTypeName]'LedrProfiler.Win32Native').Type) {
    Add-Type -TypeDefinition $nativeSource -Language CSharp
}

function ConvertTo-MB {
    param([double]$Bytes)
    return [math]::Round($Bytes / $ONE_MB, 4)
}

function Get-Median {
    param([double[]]$Values)
    if ($null -eq $Values -or $Values.Count -eq 0) { return $null }
    $sorted = @($Values | Sort-Object)
    $n = $sorted.Count
    if (($n % 2) -eq 1) {
        return [double]$sorted[[int][math]::Floor($n / 2)]
    } else {
        return ([double]$sorted[($n / 2) - 1] + [double]$sorted[$n / 2]) / 2.0
    }
}

function Get-SqliteTableCounts {
    param([string]$DatabasePath)
    if ([string]::IsNullOrWhiteSpace($DatabasePath) -or -not (Test-Path -LiteralPath $DatabasePath)) {
        return $null
    }
    $pythonCmd = Get-Command python -ErrorAction SilentlyContinue
    if (-not $pythonCmd) {
        Write-Warning "python not found; skipping SQLite -DbPath read-only query."
        return $null
    }
    $resolved = (Resolve-Path -LiteralPath $DatabasePath).Path
    $pyCode = "import json, pathlib, sqlite3, sys; p = pathlib.Path(sys.argv[1]).resolve(); uri = p.as_uri() + '?mode=ro'; con = sqlite3.connect(uri, uri=True, timeout=1.0); con.execute('PRAGMA query_only = ON'); tables = ('processes', 'dns_queries', 'network_events', 'alerts'); out = {}; " +
              "`nfor t in tables:`n    try:`n        out[t] = con.execute('SELECT COUNT(*) FROM ' + t).fetchone()[0]`n    except Exception:`n        out[t] = None`ntry:`n    out['distinct_exes'] = con.execute('SELECT COUNT(DISTINCT exe_path) FROM processes').fetchone()[0]`nexcept Exception:`n    out['distinct_exes'] = None`ncon.close(); print(json.dumps(out))"
    try {
        $prevUtf8 = $env:PYTHONUTF8
        $env:PYTHONUTF8 = '1'
        $raw = & $pythonCmd.Source -c $pyCode $resolved 2>$null
        if ($LASTEXITCODE -eq 0 -and -not [string]::IsNullOrWhiteSpace($raw)) {
            return ($raw | ConvertFrom-Json)
        }
    } catch {
        Write-Warning ("SQLite read-only count failed: {0}" -f $_.Exception.Message)
    } finally {
        if ($null -eq $prevUtf8) { Remove-Item Env:PYTHONUTF8 -ErrorAction SilentlyContinue }
        else { $env:PYTHONUTF8 = $prevUtf8 }
    }
    return $null
}

function Get-PdhPrivateWorkingSetFallback {
    param([int]$ProcessId)
    try {
        $cat = New-Object System.Diagnostics.PerformanceCounterCategory('Process')
        $instances = $cat.GetInstanceNames()
        foreach ($inst in $instances) {
            try {
                $idCounter = New-Object System.Diagnostics.PerformanceCounter('Process', 'ID Process', $inst, $true)
                if ([int]$idCounter.RawValue -eq $ProcessId) {
                    $wsCounter = New-Object System.Diagnostics.PerformanceCounter('Process', 'Working Set - Private', $inst, $true)
                    $val = [uint64]$wsCounter.NextValue()
                    $wsCounter.Dispose()
                    $idCounter.Dispose()
                    return $val
                }
                $idCounter.Dispose()
            } catch {
            }
        }
    } catch {
    }
    return $null
}

function Save-SnapshotJson {
    param(
        [int]$Index,
        [double]$ElapsedSec,
        [string]$Reason,
        [LedrProfiler.SnapshotResult]$Snap,
        [string]$SnapshotsDir,
        [System.Text.UTF8Encoding]$Encoding
    )
    $catObj = [ordered]@{}
    foreach ($kv in ($Snap.ByCategory.GetEnumerator() | Sort-Object Key)) {
        $catObj[$kv.Key] = [ordered]@{
            total_bytes   = [uint64]$kv.Value[0]
            total_mb      = ConvertTo-MB $kv.Value[0]
            shared0_bytes = [uint64]$kv.Value[1]
            shared0_mb    = ConvertTo-MB $kv.Value[1]
            shared1_bytes = [uint64]$kv.Value[2]
            shared1_mb    = ConvertTo-MB $kv.Value[2]
        }
    }

    $protArr = @()
    foreach ($p in $Snap.ByProtect) {
        $protArr += [ordered]@{
            protect       = $p.ProtectName
            total_bytes   = [uint64]$p.TotalBytes
            total_mb      = ConvertTo-MB $p.TotalBytes
            shared0_bytes = [uint64]$p.Shared0Bytes
            shared1_bytes = [uint64]$p.Shared1Bytes
        }
    }

    $filesArr = @()
    foreach ($f in $Snap.Files) {
        $filesArr += [ordered]@{
            path          = $f.Path
            type          = $f.TypeName
            category      = $f.Category
            total_bytes   = [uint64]$f.TotalBytes
            total_mb      = ConvertTo-MB $f.TotalBytes
            shared0_bytes = [uint64]$f.Shared0Bytes
            shared0_mb    = ConvertTo-MB $f.Shared0Bytes
            shared1_bytes = [uint64]$f.Shared1Bytes
            shared1_mb    = ConvertTo-MB $f.Shared1Bytes
            pages         = [uint64]$f.PageCount
        }
    }

    $validBytesTotal = [uint64]($Snap.ValidPagesTotal * 4096)
    $validShared0Bytes = [uint64]($Snap.ValidShared0Pages * 4096)
    $validShared1Bytes = [uint64]($Snap.ValidShared1Pages * 4096)
    $wsDiffBytes = [int64]$Snap.WorkingSetSize - [int64]$validBytesTotal
    $privDiffBytes = if ($Snap.UsedEx2) { [int64]$Snap.PrivateWorkingSetSize - [int64]$validShared0Bytes } else { $null }

    $payload = [ordered]@{
        snapshot_index = $Index
        timestamp_utc  = [DateTime]::UtcNow.ToString('o')
        elapsed_sec    = [math]::Round($ElapsedSec, 3)
        trigger_reason = $Reason
        counters       = [ordered]@{
            working_set_bytes         = [uint64]$Snap.WorkingSetSize
            working_set_mb            = ConvertTo-MB $Snap.WorkingSetSize
            peak_working_set_bytes    = [uint64]$Snap.PeakWorkingSetSize
            peak_working_set_mb       = ConvertTo-MB $Snap.PeakWorkingSetSize
            private_ws_bytes          = [uint64]$Snap.PrivateWorkingSetSize
            private_ws_mb             = ConvertTo-MB $Snap.PrivateWorkingSetSize
            private_commit_bytes      = [uint64]$Snap.PrivateUsage
            private_commit_mb         = ConvertTo-MB $Snap.PrivateUsage
            used_ex2_private_ws       = [bool]$Snap.UsedEx2
        }
        working_set_pages = [ordered]@{
            valid_pages_total                = [uint64]$Snap.ValidPagesTotal
            valid_bytes_total                = $validBytesTotal
            valid_mb_total                   = ConvertTo-MB $validBytesTotal
            valid_shared0_pages              = [uint64]$Snap.ValidShared0Pages
            valid_shared0_bytes              = $validShared0Bytes
            valid_shared0_mb                 = ConvertTo-MB $validShared0Bytes
            valid_shared1_pages              = [uint64]$Snap.ValidShared1Pages
            valid_shared1_bytes              = $validShared1Bytes
            valid_shared1_mb                  = ConvertTo-MB $validShared1Bytes
            large_pages_count                 = [uint64]$Snap.LargePagesCount
            query_ws_ex_failed_chunks         = [uint64]$Snap.QueryWsExFailedChunks
            reconciliation_ws_diff_bytes      = $wsDiffBytes
            reconciliation_ws_diff_mb         = ConvertTo-MB $wsDiffBytes
            reconciliation_priv_ws_diff_bytes = $privDiffBytes
        }
        by_type = [ordered]@{
            MEM_IMAGE   = [ordered]@{ bytes = [uint64]$Snap.ImageBytes; mb = ConvertTo-MB $Snap.ImageBytes; shared0_bytes = [uint64]$Snap.ImageShared0Bytes; shared1_bytes = [uint64]$Snap.ImageShared1Bytes }
            MEM_MAPPED  = [ordered]@{ bytes = [uint64]$Snap.MappedBytes; mb = ConvertTo-MB $Snap.MappedBytes; shared0_bytes = [uint64]$Snap.MappedShared0Bytes; shared1_bytes = [uint64]$Snap.MappedShared1Bytes }
            MEM_PRIVATE = [ordered]@{ bytes = [uint64]$Snap.PrivateBytes; mb = ConvertTo-MB $Snap.PrivateBytes; shared0_bytes = [uint64]$Snap.PrivateShared0Bytes; shared1_bytes = [uint64]$Snap.PrivateShared1Bytes }
        }
        track2_metrics = [ordered]@{
            authenticode_mapped_bytes = [uint64]$Snap.Track2AuthenticodeMappedBytes
            authenticode_mapped_mb    = ConvertTo-MB $Snap.Track2AuthenticodeMappedBytes
            authenticode_idle_bytes   = [uint64]$Snap.Track2AuthenticodeIdleBytes
            authenticode_idle_mb      = ConvertTo-MB $Snap.Track2AuthenticodeIdleBytes
        }
        by_category = $catObj
        by_protect  = $protArr
        mapped_files = $filesArr
    }

    if ($Snap.QueryWsExFailedChunks -gt 0) {
        Write-Warning ("QueryWorkingSetEx failed for {0} chunk(s) during snapshot #{1} ({2})." -f $Snap.QueryWsExFailedChunks, $Index, $Reason)
    }
    $safeReason = ($Reason -replace '[^a-zA-Z0-9_-]', '_')
    $fileName = ("snapshot_{0:D3}_{1:D4}s_{2}.json" -f $Index, [int][math]::Floor($ElapsedSec), $safeReason)
    $filePath = Join-Path $SnapshotsDir $fileName
    $json = $payload | ConvertTo-Json -Depth 10
    [System.IO.File]::WriteAllText($filePath, $json, $Encoding)
    return [ordered]@{
        file_name                    = $fileName
        snapshot_index               = $Index
        elapsed_sec                  = [math]::Round($ElapsedSec, 3)
        trigger_reason               = $Reason
        working_set_mb               = ConvertTo-MB $Snap.WorkingSetSize
        private_ws_mb                = ConvertTo-MB $Snap.PrivateWorkingSetSize
        valid_mb_total               = ConvertTo-MB $validBytesTotal
        valid_shared0_mb             = ConvertTo-MB $validShared0Bytes
        valid_shared1_mb             = ConvertTo-MB $validShared1Bytes
        reconciliation_ws_diff_bytes = $wsDiffBytes
        query_ws_ex_failed_chunks    = [uint64]$Snap.QueryWsExFailedChunks
        daemon_image_mb              = if ($Snap.ByCategory.ContainsKey('daemon_image')) { ConvertTo-MB $Snap.ByCategory['daemon_image'][0] } else { 0.0 }
        authenticode_mapped_mb       = ConvertTo-MB $Snap.Track2AuthenticodeMappedBytes
        authenticode_idle_mb         = ConvertTo-MB $Snap.Track2AuthenticodeIdleBytes
    }
}

# Resolve OutDir
if ([string]::IsNullOrWhiteSpace($OutDir)) {
    $stamp = [DateTime]::Now.ToString('yyyyMMdd-HHmmss')
    $OutDir = Join-Path $env:TEMP ("ledr-memprof-" + $stamp)
}
$null = New-Item -ItemType Directory -Path $OutDir -Force
$resolvedDaemonPath = if (Test-Path -LiteralPath $DaemonExePath) { (Resolve-Path -LiteralPath $DaemonExePath).Path } else { $DaemonExePath }

# Always run PE Transitive Dependency Analysis
Write-Verbose "Running PE transitive dependency analysis on $resolvedDaemonPath"
$peAnalysis = [LedrProfiler.PeDependencyAnalyzer]::Analyze($resolvedDaemonPath)

if ($AnalyzePeOnly) {
    $peOutPath = Join-Path $OutDir 'pe-transitive-dependencies.json'
    $peJson = $peAnalysis | ConvertTo-Json -Depth 10
    [System.IO.File]::WriteAllText($peOutPath, $peJson, $utf8NoBom)
    Write-Output "PE transitive dependency analysis saved to: $peOutPath"
    $peJson
    exit 0
}

$snapshotsDir = Join-Path $OutDir 'snapshots'
$null = New-Item -ItemType Directory -Path $snapshotsDir -Force
$csvPath = Join-Path $OutDir 'timeseries.csv'
$summaryPath = Join-Path $OutDir 'memory-profile-summary.json'

# Open target process
$desiredAccess = [LedrProfiler.Win32Native]::PROCESS_QUERY_INFORMATION -bor [LedrProfiler.Win32Native]::PROCESS_VM_READ
$hProc = [LedrProfiler.Win32Native]::OpenProcess($desiredAccess, $false, $TargetPid)
if ($hProc -eq [IntPtr]::Zero) {
    $err = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
    throw "Failed to OpenProcess(PID=$TargetPid) with PROCESS_QUERY_INFORMATION|PROCESS_VM_READ (Win32 error=$err)."
}

$csvWriter = $null
try {
    $logicalCores = [Environment]::ProcessorCount
    $dbStartCounts = Get-SqliteTableCounts -DatabasePath $DbPath

    $firstSample = [LedrProfiler.Win32Native]::PollSample($hProc)
    if (-not $firstSample.Success) {
        throw "Initial GetProcessMemoryInfo failed for PID=$TargetPid (Win32 error=$($firstSample.LastError))."
    }
    $initialCpuSec = ($firstSample.KernelTime100ns + $firstSample.UserTime100ns) / 10000000.0
    $prevCpuSec = $initialCpuSec
    $spikeBaselineWsBytes = [uint64]$firstSample.WorkingSetSize

    $csvWriter = New-Object System.IO.StreamWriter($csvPath, $false, $utf8NoBom)
    $csvWriter.WriteLine('timestamp_utc,elapsed_sec,working_set_bytes,working_set_mb,peak_working_set_bytes,peak_working_set_mb,private_ws_bytes,private_ws_mb,private_ws_source,private_commit_bytes,private_commit_mb,page_fault_count,cpu_total_sec,interval_cpu_pct,cum_cpu_pct,snapshot_triggered,snapshot_reason')

    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    $prevElapsedSec = 0.0

    $allWsMb = New-Object System.Collections.Generic.List[double]
    $allPrivWsMb = New-Object System.Collections.Generic.List[double]
    $steadyWsMb = New-Object System.Collections.Generic.List[double]
    $steadyPrivWsMb = New-Object System.Collections.Generic.List[double]
    $steadyElapsedSec = New-Object System.Collections.Generic.List[double]
    $spikes100Mb = 0
    $peakWsBytesMax = [uint64]$firstSample.PeakWorkingSetSize
    $intervalPeakWsBytes = [uint64]$firstSample.WorkingSetSize
    $peakPrivWsBytesMax = [uint64]0
    $peakCommitBytesMax = [uint64]$firstSample.PrivateUsage
    $latestSample = $firstSample
    $latestPrivWsBytes = [uint64]0

    $captured10s = $false
    $captured60s = $false
    $capturedFinal = $false
    $lastDumpTimeSec = -9999.0
    $lastDumpPeakWs = [uint64]$firstSample.WorkingSetSize
    $snapshotCount = 0
    $snapshotIndexRecords = New-Object System.Collections.Generic.List[object]
    $processExitedEarly = $false
    $startPriv60sMb = $null
    $endPrivMb = $null
    $lastCumCpuPct = 0.0

    $reserveForFinal = if ($MaxSnapshots -ge 1) { 1 } else { 0 }

    while ($true) {
        $elapsedSec = $sw.Elapsed.TotalSeconds
        $targetProcObj = Get-Process -Id $TargetPid -ErrorAction SilentlyContinue
        if ($null -eq $targetProcObj) {
            $processExitedEarly = $true
            break
        }

        $sample = [LedrProfiler.Win32Native]::PollSample($hProc)
        if (-not $sample.Success) {
            $processExitedEarly = $true
            break
        }
        $latestSample = $sample

        $privSource = 'EX2'
        $privWsBytes = [uint64]$sample.PrivateWorkingSetSize
        if (-not $sample.UsedEx2) {
            $pdhVal = Get-PdhPrivateWorkingSetFallback -ProcessId $TargetPid
            if ($null -ne $pdhVal) {
                $privWsBytes = [uint64]$pdhVal
                $privSource = 'PDH'
            } else {
                $privSource = 'UNSUPPORTED'
            }
        }
        $latestPrivWsBytes = $privWsBytes

        $wsMb = ConvertTo-MB $sample.WorkingSetSize
        $peakWsMb = ConvertTo-MB $sample.PeakWorkingSetSize
        $privWsMb = ConvertTo-MB $privWsBytes
        $privCommitMb = ConvertTo-MB $sample.PrivateUsage

        $allWsMb.Add($wsMb)
        $allPrivWsMb.Add($privWsMb)
        if ($sample.WorkingSetSize -ge ([uint64]100 * [uint64]1048576)) { $spikes100Mb++ }
        if ($sample.PeakWorkingSetSize -gt $peakWsBytesMax) { $peakWsBytesMax = $sample.PeakWorkingSetSize }
        $intervalPeakWsBytes = [Math]::Max($intervalPeakWsBytes, [uint64]$sample.WorkingSetSize)
        if ($privWsBytes -gt $peakPrivWsBytesMax) { $peakPrivWsBytesMax = $privWsBytes }
        if ($sample.PrivateUsage -gt $peakCommitBytesMax) { $peakCommitBytesMax = $sample.PrivateUsage }

        if ($elapsedSec -ge 60.0) {
            $steadyWsMb.Add($wsMb)
            $steadyPrivWsMb.Add($privWsMb)
            $steadyElapsedSec.Add($elapsedSec)
            if ($null -eq $startPriv60sMb) { $startPriv60sMb = $privWsMb }
        }
        $endPrivMb = $privWsMb

        $cpuTotalSec = ($sample.KernelTime100ns + $sample.UserTime100ns) / 10000000.0
        $dt = $elapsedSec - $prevElapsedSec
        $intervalCpuPct = if ($dt -gt 0.001) {
            (($cpuTotalSec - $prevCpuSec) / ($dt * $logicalCores)) * 100.0
        } else { 0.0 }
        $cumCpuPct = if ($elapsedSec -gt 0.001) {
            (($cpuTotalSec - $initialCpuSec) / ($elapsedSec * $logicalCores)) * 100.0
        } else { 0.0 }
        $lastCumCpuPct = $cumCpuPct

        # Determine snapshot trigger
        $snapReason = $null
        if (-not $capturedFinal -and $elapsedSec -ge $DurationSec) {
            $snapReason = 'pre_exit'
            $capturedFinal = $true
        } elseif (-not $captured10s -and $elapsedSec -ge 10.0 -and $DurationSec -ge 10) {
            $snapReason = 'initial_10s'
            $captured10s = $true
        } elseif (-not $captured60s -and $elapsedSec -ge 60.0 -and $DurationSec -ge 60) {
            $snapReason = 'steady_60s'
            $captured60s = $true
        } else {
            $cooldownOk = (($elapsedSec - $lastDumpTimeSec) -ge $DumpCooldownSec)
            if ($cooldownOk) {
                if (($intervalPeakWsBytes -ge $lastDumpPeakWs) -and (($intervalPeakWsBytes - $lastDumpPeakWs) -ge ([uint64]2 * [uint64]1048576))) {
                    $snapReason = 'peak_ws_plus_2mb'
                } elseif (($sample.WorkingSetSize -ge $spikeBaselineWsBytes) -and (($sample.WorkingSetSize - $spikeBaselineWsBytes) -ge ([uint64]5 * [uint64]1048576))) {
                    $snapReason = 'ws_spike_plus_5mb'
                }
            }
        }

        $didSnap = $false
        $effectiveLimit = if ($snapReason -eq 'pre_exit') { $MaxSnapshots } else { $MaxSnapshots - $reserveForFinal }
        if ($null -ne $snapReason -and $snapshotCount -lt $effectiveLimit) {
            $snapResult = [LedrProfiler.Win32Native]::CaptureDetailedSnapshot($hProc, $resolvedDaemonPath)
            if ($snapResult.Success) {
                $snapshotCount++
                $didSnap = $true
                $lastDumpTimeSec = $elapsedSec
                if ($intervalPeakWsBytes -gt $lastDumpPeakWs) { $lastDumpPeakWs = $intervalPeakWsBytes }
                $spikeBaselineWsBytes = [uint64]$sample.WorkingSetSize
                $rec = Save-SnapshotJson -Index $snapshotCount -ElapsedSec $elapsedSec -Reason $snapReason -Snap $snapResult -SnapshotsDir $snapshotsDir -Encoding $utf8NoBom
                $snapshotIndexRecords.Add($rec)
            }
        }

        $tsUtc = [DateTime]::UtcNow.ToString('o')
        $csvLine = ('{0},{1},{2},{3},{4},{5},{6},{7},{8},{9},{10},{11},{12},{13},{14},{15},{16}' -f `
            $tsUtc,
            [math]::Round($elapsedSec, 3),
            $sample.WorkingSetSize,
            $wsMb,
            $sample.PeakWorkingSetSize,
            $peakWsMb,
            $privWsBytes,
            $privWsMb,
            $privSource,
            $sample.PrivateUsage,
            $privCommitMb,
            $sample.PageFaultCount,
            [math]::Round($cpuTotalSec, 6),
            [math]::Round($intervalCpuPct, 4),
            [math]::Round($cumCpuPct, 4),
            $didSnap,
            $(if ($didSnap) { $snapReason } else { '' })
        )
        $csvWriter.WriteLine($csvLine)

        $prevCpuSec = $cpuTotalSec
        $prevElapsedSec = $elapsedSec
        if ($sample.WorkingSetSize -lt $spikeBaselineWsBytes) { $spikeBaselineWsBytes = [uint64]$sample.WorkingSetSize }

        if ($capturedFinal -or $elapsedSec -ge $DurationSec) {
            break
        }
        Start-Sleep -Milliseconds $PollMs
    }

    # Ensure pre-exit snapshot if loop ended without capturing it (e.g. short DurationSec < 10 or boundary race)
    if (-not $capturedFinal -and -not $processExitedEarly -and $snapshotCount -lt $MaxSnapshots) {
        $snapResult = [LedrProfiler.Win32Native]::CaptureDetailedSnapshot($hProc, $resolvedDaemonPath)
        if ($snapResult.Success) {
            $snapshotCount++
            $rec = Save-SnapshotJson -Index $snapshotCount -ElapsedSec $sw.Elapsed.TotalSeconds -Reason 'pre_exit' -Snap $snapResult -SnapshotsDir $snapshotsDir -Encoding $utf8NoBom
            $snapshotIndexRecords.Add($rec)
        }
    }

    $csvWriter.Flush()
    $csvWriter.Dispose()
    $csvWriter = $null

    $dbEndCounts = Get-SqliteTableCounts -DatabasePath $DbPath
    $dbDelta = $null
    if ($null -ne $dbStartCounts -and $null -ne $dbEndCounts) {
        $dbDelta = [ordered]@{}
        foreach ($tbl in @('processes', 'dns_queries', 'network_events', 'alerts', 'distinct_exes')) {
            $sVal = $dbStartCounts.$tbl
            $eVal = $dbEndCounts.$tbl
            $dbDelta[$tbl] = if ($null -ne $sVal -and $null -ne $eVal) { [int64]$eVal - [int64]$sVal } else { $null }
        }
    }

    # Steady-state split medians (60s..DurationSec)
    $steadyMedianWs = Get-Median -Values $steadyWsMb.ToArray()
    $steadyMedianPrivWs = Get-Median -Values $steadyPrivWsMb.ToArray()
    $steadyFirstHalfWs = New-Object System.Collections.Generic.List[double]
    $steadySecondHalfWs = New-Object System.Collections.Generic.List[double]
    $steadyFirstHalfPriv = New-Object System.Collections.Generic.List[double]
    $steadySecondHalfPriv = New-Object System.Collections.Generic.List[double]
    if ($steadyElapsedSec.Count -gt 0) {
        $midSec = 60.0 + (($DurationSec - 60.0) / 2.0)
        for ($i = 0; $i -lt $steadyElapsedSec.Count; $i++) {
            if ($steadyElapsedSec[$i] -lt $midSec) {
                $steadyFirstHalfWs.Add($steadyWsMb[$i])
                $steadyFirstHalfPriv.Add($steadyPrivWsMb[$i])
            } else {
                $steadySecondHalfWs.Add($steadyWsMb[$i])
                $steadySecondHalfPriv.Add($steadyPrivWsMb[$i])
            }
        }
    }
    $firstHalfMedWs = Get-Median -Values $steadyFirstHalfWs.ToArray()
    $secondHalfMedWs = Get-Median -Values $steadySecondHalfWs.ToArray()
    $halfDiffWs = if ($null -ne $firstHalfMedWs -and $null -ne $secondHalfMedWs) { [math]::Round($secondHalfMedWs - $firstHalfMedWs, 4) } else { $null }
    $firstHalfMedPriv = Get-Median -Values $steadyFirstHalfPriv.ToArray()
    $secondHalfMedPriv = Get-Median -Values $steadySecondHalfPriv.ToArray()
    $halfDiffPriv = if ($null -ne $firstHalfMedPriv -and $null -ne $secondHalfMedPriv) { [math]::Round($secondHalfMedPriv - $firstHalfMedPriv, 4) } else { $null }

    # Snapshot-based Track gate values
    $maxDaemonImageMb = 0.0
    $peakAuthMappedMb = 0.0
    $steadyAuthMappedVals = New-Object System.Collections.Generic.List[double]
    $steadyAuthIdleVals = New-Object System.Collections.Generic.List[double]
    $maxWsReconcileDiff = 0L
    foreach ($sr in $snapshotIndexRecords) {
        if ($sr.daemon_image_mb -gt $maxDaemonImageMb) { $maxDaemonImageMb = $sr.daemon_image_mb }
        if ($sr.authenticode_mapped_mb -gt $peakAuthMappedMb) { $peakAuthMappedMb = $sr.authenticode_mapped_mb }
        if ($sr.elapsed_sec -ge 60.0) {
            $steadyAuthMappedVals.Add([double]$sr.authenticode_mapped_mb)
            $steadyAuthIdleVals.Add([double]$sr.authenticode_idle_mb)
        }
        $absDiff = [math]::Abs([int64]$sr.reconciliation_ws_diff_bytes)
        if ($absDiff -gt $maxWsReconcileDiff) { $maxWsReconcileDiff = $absDiff }
    }
    $steadyAuthMappedMed = Get-Median -Values $steadyAuthMappedVals.ToArray()
    $steadyAuthIdleMed = Get-Median -Values $steadyAuthIdleVals.ToArray()

    $endMinus60sPriv = if ($null -ne $startPriv60sMb -and $null -ne $endPrivMb) { [math]::Round($endPrivMb - $startPriv60sMb, 4) } else { $null }
    $peakMinusSteadyPriv = if ($null -ne $steadyMedianPrivWs) { [math]::Round((ConvertTo-MB $peakPrivWsBytesMax) - $steadyMedianPrivWs, 4) } else { $null }
    $authMappedSpikeOverSteady = if ($null -ne $steadyAuthMappedMed) { [math]::Round($peakAuthMappedMb - $steadyAuthMappedMed, 4) } else { $null }

    $gates = [ordered]@{
        track_1a_steady_priv_ws_gt_10mb = if ($null -ne $steadyMedianPrivWs) { $steadyMedianPrivWs -gt 10.0 } else { $null }
        track_1c_idle_growth_ge_3mb    = if ($null -ne $endMinus60sPriv) { $endMinus60sPriv -ge 3.0 } else { $null }
        track_1c_peak_delta_ge_5mb     = if ($null -ne $peakMinusSteadyPriv) { $peakMinusSteadyPriv -ge 5.0 } else { $null }
        track_1f_daemon_image_ge_4mb   = ($maxDaemonImageMb -ge 4.0)
        track_2_auth_mapped_spike_gt_5mb = if ($null -ne $authMappedSpikeOverSteady) { $authMappedSpikeOverSteady -gt 5.0 } else { $null }
        track_2_auth_idle_sum_ge_4mb     = if ($null -ne $steadyAuthIdleMed) { $steadyAuthIdleMed -ge 4.0 } else { $null }
        e2e_perf_01_avg_cpu_lt_0_5pct    = ($lastCumCpuPct -lt 0.5)
        e2e_perf_01_ws_le_20mb           = ((ConvertTo-MB $intervalPeakWsBytes) -le 20.0)
        e2e_perf_01_spikes_ge_100mb_zero = ($spikes100Mb -eq 0)
        e2e_perf_01_half_diff_le_1mb     = if ($null -ne $halfDiffWs) { $halfDiffWs -le 1.0 } else { $null }
    }

    $summary = [ordered]@{
        unit_convention             = '1 MB = 1 MiB = 1,048,576 bytes'
        target_pid                  = $TargetPid
        daemon_exe_path             = $resolvedDaemonPath
        db_path                     = $DbPath
        duration_requested_sec      = $DurationSec
        duration_actual_sec         = [math]::Round($sw.Elapsed.TotalSeconds, 3)
        process_exited_early        = $processExitedEarly
        poll_interval_ms            = $PollMs
        logical_cores               = $logicalCores
        samples_count               = $allWsMb.Count
        avg_cpu_percent             = [math]::Round($lastCumCpuPct, 4)
        latest_working_set_mb        = ConvertTo-MB $latestSample.WorkingSetSize
        interval_peak_working_set_mb = ConvertTo-MB $intervalPeakWsBytes
        os_peak_working_set_mb       = ConvertTo-MB $peakWsBytesMax
        latest_private_ws_mb         = ConvertTo-MB $latestPrivWsBytes
        peak_private_ws_mb          = ConvertTo-MB $peakPrivWsBytesMax
        peak_private_commit_mb      = ConvertTo-MB $peakCommitBytesMax
        spikes_ge_100mb_count       = $spikes100Mb
        steady_window_60s_to_end    = [ordered]@{
            sample_count                     = $steadyWsMb.Count
            median_working_set_mb            = if ($null -ne $steadyMedianWs) { [math]::Round($steadyMedianWs, 4) } else { $null }
            median_private_ws_mb             = if ($null -ne $steadyMedianPrivWs) { [math]::Round($steadyMedianPrivWs, 4) } else { $null }
            first_half_median_ws_mb          = if ($null -ne $firstHalfMedWs) { [math]::Round($firstHalfMedWs, 4) } else { $null }
            second_half_median_ws_mb         = if ($null -ne $secondHalfMedWs) { [math]::Round($secondHalfMedWs, 4) } else { $null }
            half_diff_ws_mb                  = $halfDiffWs
            half_diff_private_ws_mb          = $halfDiffPriv
            end_minus_60s_private_ws_mb      = $endMinus60sPriv
            peak_minus_steady_private_ws_mb  = $peakMinusSteadyPriv
        }
        snapshot_summary            = [ordered]@{
            snapshot_count                    = $snapshotIndexRecords.Count
            max_daemon_image_mb               = $maxDaemonImageMb
            peak_authenticode_mapped_mb       = $peakAuthMappedMb
            steady_authenticode_mapped_med_mb = $steadyAuthMappedMed
            auth_mapped_spike_over_steady_mb  = $authMappedSpikeOverSteady
            steady_authenticode_idle_med_mb   = $steadyAuthIdleMed
            max_abs_ws_reconciliation_bytes   = $maxWsReconcileDiff
            snapshots                         = $snapshotIndexRecords
        }
        track_gates                 = $gates
        sqlite_interval_counts      = [ordered]@{
            start = $dbStartCounts
            end   = $dbEndCounts
            delta = $dbDelta
        }
        pe_transitive_dependencies  = $peAnalysis
        outputs                     = [ordered]@{
            out_dir         = $OutDir
            timeseries_csv  = $csvPath
            snapshots_dir   = $snapshotsDir
            summary_json    = $summaryPath
        }
    }

    $summaryJson = $summary | ConvertTo-Json -Depth 10
    [System.IO.File]::WriteAllText($summaryPath, $summaryJson, $utf8NoBom)
    Write-Output "Profiling complete. Summary written to: $summaryPath"
} finally {
    if ($null -ne $csvWriter) {
        $csvWriter.Dispose()
    }
    if ($hProc -ne [IntPtr]::Zero) {
        [void][LedrProfiler.Win32Native]::CloseHandle($hProc)
    }
}
