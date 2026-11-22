# Hyper-V (HCS) spike, 2026-11-21

The question: can rts boot its own Linux guest under Hyper-V on Windows, with
no network device, and run commands in it over hvsocket, using neither WSL nor
mvm? **Yes.** This also works for a non-admin user in Hyper-V Administrators.

Sources: `docs/research/hyperv-spike/` (`hvexec.c`, `init`,
`build-initrd.sh`, `hcs-spike.ps1`).

## Host

- `rts-win-dev`: Azure Standard_D4s_v4 (eastus2, nested virtualization),
  Windows 11 Pro 10.0.26100, PowerShell 5.1.
- `Microsoft-Hyper-V-All` was already **Enabled**; `HypervisorPresent=True`;
  services `vmms`, `vmcompute` and `hvhost` are running.
  `Get-VMHost` reports 4 logical processors and 16 GB.
- WSL is installed from the earlier spike but is not used: nothing here
  touches `wsl.exe`, its kernel or its VM.

## Results

| Check | Result |
|---|---|
| HCS compute system with `LinuxKernelDirect` (Ubuntu azure kernel + our initrd) | created and started; `State: Running`; the guest reaches `/init` about 0.6 s after boot |
| No NIC | the document has no `NetworkAdapters`; in the guest `/sys/class/net` = `lo` |
| hvsocket, guest -> host | the guest `AF_VSOCK` connect to CID 2 port 5000 (`hv_sock` module) reaches a host `AF_HYPERV` listener bound to `{VmId, 00001388-facb-11e6-bd58-64006a7986d3}` |
| Exec over hvsocket | `uname -a`, `id`, `ls /sys/class/net`, `cat /proc/cmdline` and a failing `ls` each returned output and an exit status |
| No host paths | `/mnt` and `/media` absent; no shares in the document |
| Shutdown | the guest's `poweroff -f` stops the system; a later `HcsTerminateComputeSystem` returns `0x80370110` (already stopped); `hcsdiag list` shows nothing left |
| Non-admin | as `rtsuser` (Hyper-V Administrators and Users only, Medium integrity), the same create/start/hvsocket/exec run succeeded |

**What failed first:**
- The guest's `connect` timed out while the host listener was bound to the
  wildcard VM id and the document had no `ServiceTable`.
- It worked once the listener was bound to the compute system's id and the
  service was listed in `HvSocketConfig.ServiceTable` with bind and connect
  security descriptors.
- The first initrd panicked because `/init`'s `#!/bin/sh` didn't exist yet;
  it now uses `#!/bin/busybox sh`.

## Commands

Build the guest on the Linux VM (Ubuntu 24.04, kernel `7.0.0-1020-azure`,
`CONFIG_HYPERV=y`, `CONFIG_HYPERV_VSOCKETS=m`, `CONFIG_VSOCKETS=m`):

```sh
bash build-initrd.sh   # busybox-static, static hvexec, vsock.ko + hv_sock.ko, cpio newc | gzip
# vmlinuz     sha256 eda095ff9e74c5a426a173efb513374af408517185ba8cee065a1352ca3cbd17 (= /boot/vmlinuz-7.0.0-1020-azure)
# initrd.img  sha256 recorded by the script (rebuilt after the shebang fix)
```

Copy to Windows (through the Mac) and check the digests:

```sh
scp rts@<linux-vm>:hvspike/vmlinuz rts@<linux-vm>:hvspike/initrd.img .
scp vmlinuz initrd.img hcs-spike.ps1 rtsdev@<win-vm>:C:/rts-spike/
ssh rtsdev@<win-vm> 'Get-FileHash C:\rts-spike\vmlinuz,C:\rts-spike\initrd.img'
```

Run the spike as the admin:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File C:\rts-spike\hcs-spike.ps1
```

`hcs-spike.ps1`:
- Calls `computecore.dll` through `Add-Type` P/Invoke (`HcsCreateOperation`,
  `HcsCreateComputeSystem`, `HcsStartComputeSystem`,
  `HcsGetComputeSystemProperties`, `HcsTerminateComputeSystem`).
- Registers the service GUID under
  `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Virtualization\GuestCommunicationServices`.
- Binds an `AF_HYPERV` socket to `{VmId, ServiceId}`, then starts the system.
- Reads the guest's serial console from the COM1 named pipe.
- Sends each command line and prints its output up to `RTS_EXIT <code>`.

The compute system document:

```json
{
  "Owner": "rts-spike",
  "SchemaVersion": { "Major": 2, "Minor": 1 },
  "ShouldTerminateOnLastHandleClosed": true,
  "VirtualMachine": {
    "StopOnReset": true,
    "Chipset": { "LinuxKernelDirect": {
      "KernelFilePath": "C:\\rts-spike\\vmlinuz",
      "InitRdPath": "C:\\rts-spike\\initrd.img",
      "KernelCmdLine": "console=ttyS0 rdinit=/init panic=-1 loglevel=4" } },
    "ComputeTopology": { "Memory": { "SizeInMB": 512 }, "Processor": { "Count": 1 } },
    "Devices": {
      "ComPorts": { "0": { "NamedPipe": "\\\\.\\pipe\\rts-spike-<id>-com1" } },
      "HvSocket": { "HvSocketConfig": {
        "DefaultBindSecurityDescriptor": "D:P(A;;FA;;;SY)(A;;FA;;;BA)",
        "DefaultConnectSecurityDescriptor": "D:P(A;;FA;;;SY)(A;;FA;;;BA)",
        "ServiceTable": { "00001388-facb-11e6-bd58-64006a7986d3": {
          "BindSecurityDescriptor": "D:P(A;;FA;;;SY)(A;;FA;;;BA)",
          "ConnectSecurityDescriptor": "D:P(A;;FA;;;SY)(A;;FA;;;BA)",
          "AllowWildcardBinds": true } } } }
    }
  }
}
```

The non-admin run:
- One-time admin setup:
  - created local user `rtsuser`;
  - `Add-LocalGroupMember -Group 'Hyper-V Administrators' -Member rtsuser`;
  - `icacls C:\rts-spike /grant 'rtsuser:(OI)(CI)M'`;
  - a throwaway SSH key for `rtsuser` (`C:\Users\rtsuser\.ssh\authorized_keys`).
- The script ran as a copy whose security descriptors also admit Hyper-V
  Administrators (`S-1-5-32-578`):
  `ssh rtsuser@<win-vm> 'powershell -NoProfile -ExecutionPolicy Bypass -File C:\rts-spike\hcs-spike-hva.ps1'`.
- `Start-Process -Credential` from an SSH session fails with `0xC0000142`, and
  the scheduled-task route produced no output, so the run went through the
  SSH key instead.

## Notes for the backend

- **Kernel:** the Ubuntu azure kernel builds `hv_sock` and `vsock` as
  modules, so the initrd must carry and load them, decompressed from
  `.ko.zst`. A pinned kernel with those built in (`=y`) and no NIC drivers
  avoids that.
- **Security descriptors:** they must admit the session user. Admin rights
  aren't needed: Hyper-V Administrators is enough for HCS and for binding
  hvsocket.
- **Service registration:** the `GuestCommunicationServices` key is the only
  admin-only step left; it belongs in the installer.
- **PCI:** the guest logs `PCI: Fatal: No config space access function
  found`. That's expected with no PCI devices and is harmless here.
