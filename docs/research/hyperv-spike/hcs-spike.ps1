# Hyper-V spike: boot a Linux kernel + initrd as an HCS compute system with no
# NIC, and talk to its guest agent over hvsocket (AF_HYPERV on the host,
# AF_VSOCK/hv_sock in the guest). Run elevated. No WSL involved.
param(
  [string]$Dir = 'C:\rts-spike',
  [int]$Port = 5000,
  [string[]]$Commands = @('uname -a', 'id', 'ls /sys/class/net', 'cat /proc/cmdline', 'ls /mnt /media 2>&1; echo done')
)
$ErrorActionPreference = 'Stop'

Add-Type -TypeDefinition @'
using System;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;

public static class Hcs {
    [DllImport("computecore.dll", CharSet = CharSet.Unicode)] public static extern IntPtr HcsCreateOperation(IntPtr context, IntPtr callback);
    [DllImport("computecore.dll", CharSet = CharSet.Unicode)] public static extern void HcsCloseOperation(IntPtr op);
    [DllImport("computecore.dll", CharSet = CharSet.Unicode)] public static extern int HcsWaitForOperationResult(IntPtr op, uint timeoutMs, out IntPtr resultDocument);
    [DllImport("computecore.dll", CharSet = CharSet.Unicode)] public static extern int HcsCreateComputeSystem(string id, string configuration, IntPtr op, IntPtr securityDescriptor, out IntPtr computeSystem);
    [DllImport("computecore.dll", CharSet = CharSet.Unicode)] public static extern int HcsStartComputeSystem(IntPtr computeSystem, IntPtr op, string options);
    [DllImport("computecore.dll", CharSet = CharSet.Unicode)] public static extern int HcsTerminateComputeSystem(IntPtr computeSystem, IntPtr op, string options);
    [DllImport("computecore.dll", CharSet = CharSet.Unicode)] public static extern int HcsGetComputeSystemProperties(IntPtr computeSystem, IntPtr op, string propertyQuery);
    [DllImport("computecore.dll", CharSet = CharSet.Unicode)] public static extern void HcsCloseComputeSystem(IntPtr computeSystem);
    [DllImport("kernel32.dll")] public static extern IntPtr LocalFree(IntPtr mem);

    static string Take(IntPtr doc) { if (doc == IntPtr.Zero) return ""; string s = Marshal.PtrToStringUni(doc); LocalFree(doc); return s; }

    // Run one HCS call that completes through an operation; return its result document.
    public static string Call(Func<IntPtr, int> start, uint timeoutMs) {
        IntPtr op = HcsCreateOperation(IntPtr.Zero, IntPtr.Zero);
        try {
            int hr = start(op);
            if (hr < 0) throw new Exception(String.Format("HCS call failed: 0x{0:X8}", hr));
            IntPtr doc; hr = HcsWaitForOperationResult(op, timeoutMs, out doc);
            string result = Take(doc);
            if (hr < 0) throw new Exception(String.Format("HCS operation failed: 0x{0:X8} {1}", hr, result));
            return result;
        } finally { HcsCloseOperation(op); }
    }

    public static IntPtr Create(string id, string config) {
        IntPtr system = IntPtr.Zero;
        Call(op => HcsCreateComputeSystem(id, config, op, IntPtr.Zero, out system), 60000);
        return system;
    }
}

// SOCKADDR_HV: { ADDRESS_FAMILY Family; USHORT Reserved; GUID VmId; GUID ServiceId; }
public class HvSocketEndPoint : EndPoint {
    public const AddressFamily HyperV = (AddressFamily)34;
    public Guid VmId, ServiceId;
    public HvSocketEndPoint(Guid vmId, Guid serviceId) { VmId = vmId; ServiceId = serviceId; }
    public override AddressFamily AddressFamily { get { return HyperV; } }
    public override SocketAddress Serialize() {
        var sa = new SocketAddress(HyperV, 36);
        byte[] v = VmId.ToByteArray(), s = ServiceId.ToByteArray();
        for (int i = 0; i < 16; i++) { sa[4 + i] = v[i]; sa[20 + i] = s[i]; }
        return sa;
    }
    public override EndPoint Create(SocketAddress sa) {
        byte[] v = new byte[16], s = new byte[16];
        for (int i = 0; i < 16; i++) { v[i] = sa[4 + i]; s[i] = sa[20 + i]; }
        return new HvSocketEndPoint(new Guid(v), new Guid(s));
    }
    public override string ToString() { return VmId + "/" + ServiceId; }
}
'@

$serviceId = [Guid]::Parse(('{0:x8}-facb-11e6-bd58-64006a7986d3' -f $Port))
$vmId = [Guid]::NewGuid()
$name = "rts-spike-$($vmId.ToString().Substring(0, 8))"
"service $serviceId, compute system $name ($vmId)"

# Guest-initiated hvsocket connections to the host need the service registered.
$reg = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Virtualization\GuestCommunicationServices\$serviceId"
if (-not (Test-Path $reg)) { New-Item -Path $reg -Force | Out-Null; New-ItemProperty -Path $reg -Name ElementName -Value 'rts spike guest agent' | Out-Null }

$pipe = "\\.\pipe\$name-com1"
$config = @{
  Owner = 'rts-spike'
  SchemaVersion = @{ Major = 2; Minor = 1 }
  ShouldTerminateOnLastHandleClosed = $true
  VirtualMachine = @{
    StopOnReset = $true
    Chipset = @{ LinuxKernelDirect = @{
      KernelFilePath = "$Dir\vmlinuz"
      InitRdPath = "$Dir\initrd.img"
      KernelCmdLine = 'console=ttyS0 rdinit=/init panic=-1 loglevel=4'
    } }
    ComputeTopology = @{ Memory = @{ SizeInMB = 512 }; Processor = @{ Count = 1 } }
    Devices = @{
      ComPorts = @{ '0' = @{ NamedPipe = $pipe } }
      HvSocket = @{ HvSocketConfig = @{
        DefaultBindSecurityDescriptor = 'D:P(A;;FA;;;SY)(A;;FA;;;BA)'
        DefaultConnectSecurityDescriptor = 'D:P(A;;FA;;;SY)(A;;FA;;;BA)'
        # The one service the guest agent dials. Only SYSTEM and Administrators
        # may bind it on the host side.
        ServiceTable = @{ "$serviceId" = @{
          BindSecurityDescriptor = 'D:P(A;;FA;;;SY)(A;;FA;;;BA)'
          ConnectSecurityDescriptor = 'D:P(A;;FA;;;SY)(A;;FA;;;BA)'
          AllowWildcardBinds = $true
        } }
      } }
    }
  }
} | ConvertTo-Json -Depth 10
Set-Content -Path "$Dir\$name.json" -Value $config -Encoding ascii

$system = [Hcs]::Create($vmId.ToString(), $config)
"created"
# Listen before the guest boots, bound to this compute system's id only.
$listener = New-Object System.Net.Sockets.Socket([HvSocketEndPoint]::HyperV, [System.Net.Sockets.SocketType]::Stream, [System.Net.Sockets.ProtocolType]1)
$listener.Bind((New-Object HvSocketEndPoint($vmId, $serviceId)))
$listener.Listen(1)
"listening on hvsocket $vmId/$serviceId"
# Drain the serial console into a file.
$console = "$Dir\$name.console.log"
$job = Start-Job -ArgumentList $pipe, $console {
  param($p, $out)
  for ($i = 0; $i -lt 50; $i++) { try { $c = New-Object System.IO.Pipes.NamedPipeClientStream('.', $p.Substring(9), [System.IO.Pipes.PipeDirection]::In); $c.Connect(1000); break } catch { Start-Sleep -Milliseconds 200 } }
  $r = New-Object System.IO.StreamReader($c); while ($null -ne ($l = $r.ReadLine())) { Add-Content -Path $out -Value $l }
}
[Hcs]::Call({ param($op) [Hcs]::HcsStartComputeSystem($system, $op, $null) }, 60000) | Out-Null
"started"
$props = [Hcs]::Call({ param($op) [Hcs]::HcsGetComputeSystemProperties($system, $op, '{"PropertyTypes":[]}') }, 30000)
"properties: $props"

$accepted = $listener.BeginAccept($null, $null)
if (-not $accepted.AsyncWaitHandle.WaitOne(90000)) { throw 'guest never connected over hvsocket' }
$conn = $listener.EndAccept($accepted)
"guest connected from $($conn.RemoteEndPoint)"
$stream = New-Object System.Net.Sockets.NetworkStream($conn, $true)
$reader = New-Object System.IO.StreamReader($stream)
$writer = New-Object System.IO.StreamWriter($stream); $writer.NewLine = "`n"; $writer.AutoFlush = $true
"guest: $($reader.ReadLine())"
foreach ($c in $Commands) {
  "--- exec: $c"
  $writer.WriteLine($c)
  while ($null -ne ($l = $reader.ReadLine())) { if ($l -like 'RTS_EXIT *') { "exit status: $($l.Substring(9))"; break }; if ($l) { "  $l" } }
}
$writer.WriteLine('EXIT'); "guest: $($reader.ReadLine())"
$conn.Close(); $listener.Close()
Start-Sleep -Seconds 3
try { [Hcs]::Call({ param($op) [Hcs]::HcsTerminateComputeSystem($system, $op, $null) }, 30000) | Out-Null; 'terminated' } catch { "terminate: $_" }
[Hcs]::HcsCloseComputeSystem($system)
Start-Sleep -Seconds 1; Stop-Job $job -ErrorAction SilentlyContinue
'--- serial console'
if (Test-Path $console) { Get-Content $console | Select-Object -Last 40 }
