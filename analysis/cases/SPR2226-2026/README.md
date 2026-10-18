# SPR2226 / H713M variant

Start with the [joined component-chain analysis](chain-analysis.md), then the code reports for [netservice](netservice-code-analysis.md), [domain](code-analysis.md) and [native system services](native-system-services.md). The [offline verifier](tools/verify_samples.py) and [57-check result](sample-verification.json) make the sample and dispatch relationships reproducible.

> Device-specific case for the H713 projector family. This is a related but distinct firmware sample from the AT-M269 case in the main README.

Additional evidence: [ESET detection and provenance](eset-evidence.md) and [naturally captured update metadata](captured-domain-response.md). The latter has indirect process attribution and does not demonstrate a new installation.

## Executive conclusion

The examined `SPR2226` is not proven to be byte-identical to the AT-M269 firmware analysed in the main case. It is nevertheless a high-risk related platform: ADB is unauthorised, root is available, SELinux is permissive, and a system-UID update service had a concrete task to retrieve and install `com.android.domain`.

The [code-level analysis](code-analysis.md) traces `com.android.domain` through scheduled server selection, hardware-identifying headers, AES-CBC response parsing, remote APK tasks, domain-list replacement and installation. The known `.rf` proxy modules and the main-case package names were not found in the captured inventory.

### Evidence grading

| Claim | Evidence level | Basis |
| --- | --- | --- |
| The unit is an H713/H713M Android 11 device | Confirmed | ADB properties and USB identity |
| ADB/root/SELinux posture is unsafe | Confirmed | `ro.adb.secure=0`, `su 0`, permissive SELinux |
| `netservice` had an install task for `domain` | Confirmed | `sofa-db` task and package metadata match |
| `domain` was installed by `netservice` | Confirmed | Package installer and install time |
| `domain` processes remote APK update lists | Confirmed in reviewed code | Presenter, service, downloader and installer call chain |
| The unit ran the repository's four proxy modules | Not established | Modules/packages absent from snapshot |
| The unit acted as a residential proxy | Not established | No corresponding process traffic observed |
| Manufacturer or retailer operated the infrastructure | Not established | Hosting ownership is not attribution |

## Summary

A projector identified as `SPR2226` was examined over USB ADB. It is an Allwinner H713/H713M Android 11 device with an unusually permissive development configuration. The unit contains a system-level update component, `com.android.netservice`, with a concrete database task for `com.android.domain`.

This case documents a system-privileged downloader/update chain. The independent file-detection result is recorded in the [case report](reverse-engineering.md#7-apk-evidence). This unit is not established to have run the four `.rf` proxy modules described in the AT-M269 case.

## Device identity

Collected with read-only ADB property queries:

| Property | Observed value |
| --- | --- |
| USB identity | `SPR2226`, VID/PID `1F3A:1001` |
| Board/platform | `h713m-tuna_p3` / `ares` |
| Boot hardware | `sun50iw12p1` |
| Firmware | `H713M-android11-v1.0` |
| Android | 11, SDK 30 |
| Kernel | Linux 5.4.99, `armv7l` |
| Build date | 16 Apr 2026 11:38:29 CST |
| Build type | `userdebug` |
| ADB security | `ro.adb.secure=0` |
| SELinux | permissive |
| Verified boot | `green`; vbmeta device state `locked` |

`su 0 id` returned UID 0 on the examined unit.

## Observed timeline

| Time | Event | Evidence |
| --- | --- | --- |
| 16 Apr 2026 | Firmware build date | Android build properties |
| 30 Aug 2026 12:37:44 | `com.android.domain` first installed | Package manager metadata |
| 17 Oct 2026 around 23:57 | `domain` configuration recorded `d.rdnss.cloud` | Redacted `config.xml` |
| 18 Oct 2026 | APK/DEX extracted, hashed and statically analysed | Sample hashes and decompiler outputs |

The installation date and configuration timestamps are device-local observations. They do not prove when the remote service was first operated by its controller.

## Component map

```text
system image
├─ com.android.netservice
│  ├─ system package: netservice-3.4.9-allwinner
│  ├─ data update: version 3.6.0
│  └─ sofa-db: install task for com.android.domain 1.0.6
│
├─ appsdisable / gmsopt
│  └─ boot-triggered root scripts affecting Google boot receivers
│
└─ InstallXAPK / systemmix / qw
   └─ additional privileged installation, root and system-control surface

data package
└─ com.android.domain 1.0.6
   └─ com.android.systemss.SystemService (system UID)
```

The map describes observed package relationships, not an assertion that every component has the same author or purpose.

## `com.android.netservice`

Observed metadata:

```text
system base: /system/app/netserevice-release
system version: netservice-3.4.9-allwinner
data version: 3.6.0 (versionCode 60)
installer: com.android.netservice
```

The package has package-installation, boot, overlay and network-related permissions. Its private data contains a database named `sofa-db`.

The database contained an application configuration entry:

```text
package: com.android.domain
component: com.android.domain/com.android.systemss.SystemService
version: 1.0.6
auto-start: 1
```

The associated task record described this APK:

```text
file: Domain-1.0.6-20260709-release_aw.apk
size: 3959797 bytes
md5: 72ac40ce7df55d586f21c6d89cce6b7b
host: 40.160.68.219:38513
```

The database also contained a device token and hardware identifiers; those values are intentionally excluded.

## `com.android.domain`

Observed metadata:

```text
version: 1.0.6
firstInstallTime: 2026-08-30 12:37:44
installer: com.android.netservice
service: com.android.systemss.SystemService
```

The package runs as Android system UID and requests high-impact permissions including package installation/deletion, overlay, network, camera, microphone and system settings access.

Extracted APK hash:

```text
SHA-256: 5B029ABE4AD2CD6DFA18064899B50190E00CE0F50BAC57CBD849502AB3108F30
MD5:     72AC40CE7DF55D586F21C6D89CCE6B7B
size:    3959797 bytes
```

The retained APK was used for targeted Java decompilation. Binaries are excluded from this public case.

## Network indicators

Configuration referenced:

```text
business.dnsyc.top
heartbeat.dnsyc.top
d.rdnss.cloud
```

The task database referenced an HTTP download endpoint on `40.160.68.219:38513`. Hosting registration is not attribution to the hosting provider.

## Boot and privilege observations

The following system files were inspected read-only:

```text
/system/bin/appsdisable
/system/bin/gmsopt
/system/bin/qw
/system/bin/systemmixservice
/system/lib/libsystemmix_jni.so
/system/lib/libsystemmixservice.so
/system/app/InstallXAPK/InstallXAPK.apk
```

`appsdisable` and `gmsopt` are boot-triggered root scripts that query Google boot receiver components and can disable matching components. Both share a start_disable guard. Reinspection found that flag set and disabled GMS components, but the origin of those component states is unresolved. The [native report](native-system-services.md) distinguishes component state from package state.

## Comparison with the AT-M269 case

| Finding | AT-M269 case | SPR2226 case |
| --- | --- | --- |
| H713/H713M / `ares` | yes | yes |
| Android 11 | yes | yes |
| Unsecured ADB / permissive SELinux | yes | yes |
| `com.android.umanalytics.yiyou` | present | not found |
| `com.android.sysapp` | present | not found |
| `com.google.adtest` | present | not found |
| `.rf` proxy modules | present | not found |
| `com.android.netservice` | not established | present |
| `com.android.domain` | not established | present; code-level update chain traced |
| qw/systemmix binaries | repository samples | four exact SHA-256 matches |
| Proxy traffic | sample evidence | not observed in snapshot |

The defensible conclusion is shared platform or firmware lineage with a distinct suspicious update/service chain—not proof of identical payloads or proxy operation.

## Reproduction checklist

Use an isolated test unit and read-only collection:

```bash
adb devices -l
adb shell getprop > getprop.txt
adb shell pm list packages -f -i > packages-with-installers.txt
adb shell dumpsys package com.android.netservice > netservice-package.txt
adb shell dumpsys package com.android.domain > domain-package.txt
adb shell su 0 sha256sum /system/app/InstallXAPK/InstallXAPK.apk > system-hashes.txt
adb shell su 0 netstat -tnp > netstat.txt
```

Redact serial numbers, MAC addresses, CPU IDs, tokens and JWT-like values before publication. Do not publish the APK without an agreed malware-sample handling process.

## Limitations

- This build is related to, but not byte-identical with, the main README sample.
- Absence of `.rf` files in one snapshot does not prove they could never be downloaded.
- No active `com.android.domain` or `com.android.netservice` connection was observed in the captured process snapshot.
- Static client code does not identify the manufacturer, seller or remote controller.
- This case does not establish that the projector operated as a residential proxy.

## Evidence handling

Original APK hashes, detection records, package metadata, redacted database extracts and ADB logs are retained locally. Sensitive device identifiers and binaries are intentionally excluded from this public case.
