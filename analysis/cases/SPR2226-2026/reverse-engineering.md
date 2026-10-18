# Reverse-engineering report

## Senz / SPR2226 Android projector – H713M firmware variant

**Report type:** Redacted technical reverse-engineering report  
**Device aliases:** Senz, SPR2226  
**Platform:** Allwinner H713/H713M  
**Firmware:** H713M-android11-v1.0  
**Android:** 11 / SDK 30  
**Collection date:** 18 October 2026  
**Collection transport:** USB ADB

> This report follows the structure and level of detail of the public badbox-h713-projector analysis, but applies only to the examined Senz/SPR2226 unit. It must not be read as proof that all Senz devices or all H713 projectors contain the same software.

## 1. Executive conclusion

The examined Senz/SPR2226 projector is an Allwinner H713/H713M Android 11 device with an unusually weak security posture:

- unauthenticated ADB
- root available through su
- permissive SELinux
- userdebug build characteristics
- privileged package-installation components
- boot-time scripts that can disable Google boot receivers
- a system-level update service with a concrete APK download task

The most important observed chain is:

~~~text
com.android.netservice
  -> private sofa-db task record
  -> Domain-1.0.6-20260709-release_aw.apk
  -> com.android.domain 1.0.6
  -> com.android.systemss.SystemService
  -> Android system UID
~~~

The extracted com.android.domain APK was detected by ESET as:

~~~text
Android/TrojanDownloader.Agent.BOA
~~~

This is a confirmed security finding on this device. It is not, by itself, proof that the projector operated as a residential proxy node. The known proxy modules and package set from the public AT-M269/H713 case were not found in the captured Senz/SPR2226 inventory, and no active network connection owned by com.android.domain or com.android.netservice was observed in the process snapshot.

## 2. Identity and aliases

| Source | Value |
|---|---|
| Product/USB identity | SPR2226 |
| User-reported commercial name | Senz projector |
| Android model | SPR2226 |
| Manufacturer property | Allwinner |
| Device property | h713m-tuna_p3 |
| Board/platform | ares |
| Boot hardware | sun50iw12p1 |
| Firmware string | H713M-android11-v1.0 |

The Senz name is treated as a commercial alias, not as proof of manufacturer or firmware ownership.

## 3. Firmware identity

Relevant properties:

~~~text
ro.product.model=SPR2226
ro.product.manufacturer=Allwinner
ro.product.device=h713m-tuna_p3
ro.board.platform=ares
ro.boot.hardware=sun50iw12p1
ro.build.version.release=11
ro.build.version.sdk=30
ro.build.version.incremental=H713M-android11-v1.0
ro.build.type=userdebug
ro.debuggable=1
ro.adb.secure=0
service.adb.tcp.port=5555
ro.boot.verifiedbootstate=green
ro.boot.vbmeta.device_state=locked
~~~

Build information:

~~~text
Android build date: 16 April 2026 11:38:29 CST
Kernel: Linux 5.4.99
Architecture: armv7l
Display: 1280x720
SELinux: permissive
~~~

### Interpretation

The device reports green verified boot and locked VBMeta, but SELinux is permissive at runtime. Verified Boot establishes image-signature verification; it does not establish that every signed component is benign.

The userdebug build, root availability and unauthenticated ADB are not normal hardening choices for a consumer projector shipped to an ordinary customer.

## 4. Collection and analysis method

The investigation used:

- USB device identification
- ADB package and property queries
- read-only package metadata inspection
- read-only private configuration inspection
- read-only SQLite database inspection
- APK extraction and cryptographic hashing
- ESET local scanning
- process and socket snapshots
- static inspection of system init scripts and binaries
- comparison against the public H713/AT-M269 repository

The following activities were not performed:

- uncontrolled execution of the extracted APK
- dynamic instrumentation of com.android.domain
- complete firmware image comparison
- continuous packet capture
- attribution of infrastructure to Senz, a retailer or a hosting provider

## 5. Runtime security model

Observed state:

~~~text
su 0 id -> uid=0(root)
ro.adb.secure=0
ro.debuggable=1
SELinux=permissive
adbd TCP listener: 5555
~~~

| Surface | Observation | Risk |
|---|---|---|
| ADB authentication | Disabled | A reachable ADB service may accept unauthorised shell attempts |
| ADB privilege | Root path available | Full system modification may be possible |
| SELinux | Permissive | Policy enforcement is weakened |
| Package installation | Privileged services present | Silent APK installation is possible |
| Boot persistence | Boot receivers and init scripts | Components can restart automatically |
| Verified Boot | Green/locked | Signed content may still contain unsafe components |

## 6. Package architecture

### 6.1 com.android.netservice

~~~text
Path: /system/app/netserevice-release
System version: netservice-3.4.9-allwinner
Data version: 3.6.0
VersionCode: 60
First install: 2026-04-16 05:38:48
Last update: 2026-09-18 21:03:45
Installer: com.android.netservice
~~~

Observed permission groups:

~~~text
INSTALL_PACKAGES
REQUEST_INSTALL_PACKAGES
RECEIVE_BOOT_COMPLETED
SYSTEM_ALERT_WINDOW
INTERNET
~~~

The package has both a system-image component and mutable application data. Its data contained configuration and the SQLite database sofa-db.

This split is significant: a signed system component can provide privileged control while mutable task/configuration data changes independently.

### 6.2 com.android.domain

~~~text
Package: com.android.domain
VersionName: 1.0.6
VersionCode: 106
First install: 2026-08-30 12:37:44
Installer: com.android.netservice
Service: com.android.systemss.SystemService
Running UID: 1000 (system)
~~~

Observed capability groups:

- package installation and deletion
- overlay/system alert window
- network access
- camera and microphone
- system settings
- reboot/shutdown-related controls

A package running as UID 1000 is not equivalent to an ordinary user-installed Android application. It operates inside the Android system privilege boundary.

### 6.3 InstallXAPK

~~~text
Path: /system/app/InstallXAPK/InstallXAPK.apk
Package: com.ik.installxapk
Version: 1.0.5
VersionCode: 5
~~~

Its observed permission set included package-installation and boot-related capabilities. The name indicates XAPK-style package handling; the security issue is its privileged ability to participate in package installation.

## 7. Update-task reverse engineering

### 7.1 Database records

The netservice private database sofa-db contained records equivalent to:

~~~text
APP_CONFIG_BEAN
  taskId: 601
  package: com.android.domain
  component: com.android.domain/com.android.systemss.SystemService
  version: 1.0.6
  versionCode: 106
  AUTO_START: 1
  OPEN_TIMES: 2

TASK_INFO_BEAN
  taskType: 1
  taskId: 601
  file: Domain-1.0.6-20260709-release_aw.apk
  MIME: application/vnd.android.package-archive
  fileSize: 3959797
  MD5: 72ac40ce7df55d586f21c6d89cce6b7b
  host: 40.160.68.219:38513
~~~

### 7.2 Integrity relationship

The database task and extracted APK agree on:

- package family
- version
- file size
- MD5
- installer relationship

Extracted APK:

~~~text
SHA-256: 5B029ABE4AD2CD6DFA18064899B50190E00CE0F50BAC57CBD849502AB3108F30
MD5:     72AC40CE7DF55D586F21C6D89CCE6B7B
Size:    3959797 bytes
~~~

This is stronger than a package-name coincidence. It demonstrates that netservice had a concrete task record describing the same APK present in the investigation.

### 7.3 Reconstructed control flow

~~~text
boot/service initialization
        |
        v
com.android.netservice starts
        |
        v
configuration and task database loaded
        |
        v
task 601 identifies com.android.domain
        |
        v
APK download metadata is available
        |
        v
package installation/update path
        |
        v
com.android.domain runs as system UID
~~~

This report does not claim that the remote download was observed live during collection; the evidence is the local task record, package metadata and matching extracted file.

## 8. Configuration and command infrastructure

Redacted values:

~~~text
netservice CONFIG_DOMAINNAME=business.dnsyc.top
netservice CONFIG_HEARTBEAT_DOMAINNAME=heartbeat.dnsyc.top
domain CONFIG_DOMAINNAME=d.rdnss.cloud
domain CONFIG_TEST_DOMAINNAME=d.rdnss.cloud
~~~

The netservice configuration also contained:

- activation count
- heartbeat settings
- device CPU identifier
- device MAC address
- a system token containing device metadata

These values are not reproduced because they uniquely identify the device and may function as credentials or tracking identifiers.

Infrastructure indicators:

~~~text
business.dnsyc.top
heartbeat.dnsyc.top
d.rdnss.cloud
40.160.68.219:38513
~~~

IP registration information is not attribution. A hosting provider may host customer infrastructure without operating it.

## 9. Boot persistence and system control

Present files:

~~~text
/system/bin/appsdisable
/system/bin/gmsopt
/system/bin/qw
/system/bin/systemmixservice
/system/lib/libsystemmix_jni.so
/system/lib/libsystemmixservice.so
/system/app/InstallXAPK/InstallXAPK.apk
~~~

appsdisable and gmsopt are attached to boot completion through root init services. Their logic queries Google boot receivers and can disable matching packages using pm disable.

This is unusual in a consumer projector because it can interfere with normal Google startup and security-related checks. It does not prove that Google components were disabled on every boot; no disabled Google packages were present in the captured inventory.

systemmixservice creates an additional privileged native/Binder surface. Its full function set was not reverse-engineered on the Senz unit, so this report records presence and privilege rather than assigning a definitive purpose.

The public H713 analysis associates qw with a root/superuser daemon. On the Senz unit, presence was confirmed, but exact binary equivalence was not established.

## 10. ESET result

ESET scanned the extracted com.android.domain APK/DEX and reported:

~~~text
Android/TrojanDownloader.Agent.BOA
~~~

ESET removed the extracted copy.

This must be distinguished from the Git repository's separate plugin.jar sample, which ESET classified as Android/TrojanDownloader.Keenadu.A. The two detections have different filenames, hashes and acquisition paths.

The ESET result supports:

- the extracted file is recognised by a malware signature
- the file is not ordinary projector application data
- retaining or redistributing the binary is unsafe

It does not independently prove:

- who wrote the software
- who operated the server
- that proxy traffic was active
- that every Senz/SPR2226 projector is affected

## 11. Process and network behavior

Observed process state:

~~~text
com.android.netservice: system process
com.android.domain: system process
adbd: TCP 5555 listener
~~~

No active connection owned by com.android.domain or com.android.netservice was seen at collection time.

This is a negative observation from one time window. It cannot exclude earlier connections, later connections, scheduled heartbeat behavior, dormant task execution or activity from a child/renamed process.

## 12. Comparison with the public AT-M269 case

| Component/finding | AT-M269 sample | Senz/SPR2226 |
|---|---:|---:|
| H713/H713M platform | Confirmed | Confirmed |
| Android 11 | Confirmed | Confirmed |
| Unsecured ADB | Confirmed | Confirmed |
| Permissive SELinux | Confirmed | Confirmed |
| com.android.umanalytics.yiyou | Present | Not found |
| com.android.sysapp | Present | Not found |
| com.google.adtest | Present | Not found |
| plugin.jar | Present | Not found |
| Encrypted .rf proxy modules | Present | Not found |
| com.android.netservice | Not established | Present |
| com.android.domain | Not established | Present |
| ESET detection on domain | Not applicable | Confirmed |
| Active proxy traffic | Sample evidence | Not observed |

The defensible relationship is shared or related platform lineage with a distinct firmware and package set, not byte-for-byte identity.

## 13. Timeline

| Time | Event | Source |
|---|---|---|
| 16 Apr 2026 | Firmware build date | Android build properties |
| 16 Apr 2026 | netservice base package first installed | Package metadata |
| 30 Aug 2026 12:37:44 | com.android.domain first installed | Package metadata |
| 18 Sep 2026 21:03:45 | netservice data component last updated | Package metadata |
| 17 Oct 2026 around 23:57 | domain configuration recorded d.rdnss.cloud | Redacted config.xml |
| 18 Oct 2026 | APK extracted and scanned by ESET | ESET event |

The timeline documents local device state. It does not establish the first time a remote service was used.

## 14. Confidence matrix

| Area | Confidence | Reason |
|---|---|---|
| Hardware/platform identity | High | Multiple independent properties |
| ADB/root/SELinux state | High | Direct runtime checks |
| netservice package role | High | Package metadata, permissions and database |
| domain installer relationship | High | Installer field and matching task |
| APK identity | High | Matching size, MD5 and SHA-256 |
| ESET classification | High | Local ESET event |
| Boot-script behavior | High | Read-only script/init inspection |
| domain bytecode behavior | Limited | APK was removed after ESET detection |
| Active proxy operation | Not established | No matching modules or traffic snapshot |
| Firmware equivalence to AT-M269 | Low | Different build and package inventory |
| Manufacturer/retailer attribution | Not established | No attribution evidence |

## 15. Indicators of compromise

Packages:

~~~text
com.android.netservice
com.android.domain
com.ik.installxapk
~~~

Files:

~~~text
/system/bin/appsdisable
/system/bin/gmsopt
/system/bin/qw
/system/bin/systemmixservice
/system/lib/libsystemmix_jni.so
/system/lib/libsystemmixservice.so
/system/app/InstallXAPK/InstallXAPK.apk
~~~

Domains and endpoint:

~~~text
business.dnsyc.top
heartbeat.dnsyc.top
d.rdnss.cloud
40.160.68.219:38513
~~~

APK hashes:

~~~text
SHA-256 5B029ABE4AD2CD6DFA18064899B50190E00CE0F50BAC57CBD849502AB3108F30
MD5     72AC40CE7DF55D586F21C6D89CCE6B7B
~~~

## 16. Reproduction checklist

Use an isolated test unit. Do not execute untrusted APKs on a production computer.

~~~bash
adb devices -l
adb shell getprop > getprop.txt
adb shell su 0 id > root-check.txt
adb shell pm list packages -f -i > packages-with-installers.txt
adb shell dumpsys package com.android.netservice > netservice-package.txt
adb shell dumpsys package com.android.domain > domain-package.txt
adb shell su 0 netstat -tnp > netstat.txt
adb shell su 0 sha256sum /system/app/InstallXAPK/InstallXAPK.apk > system-hashes.txt
~~~

Before publication, redact ADB serial, MAC addresses, CPU IDs, Android ID, Wi-Fi SSID/BSSID, JWT-like tokens, user names and local filesystem paths.

## 17. Limitations

- The domain APK was deleted by ESET after detection, so full bytecode reverse engineering of that exact file is not included.
- The report uses package metadata, database records, configuration and system artifacts rather than a complete firmware image.
- No continuous packet capture was performed.
- No claim is made that Senz is the developer, operator or distributor of the observed software.
- No claim is made that every Senz or SPR2226 unit has the same firmware.
- No claim is made that the unit operated as a proxy node.
- Absence of a known module in a snapshot is not a lifetime guarantee.
- The public AT-M269 report is independent research and not vendor certification.

## 18. Recommended response

For the user:

1. Keep the device off the internet until the firmware is resolved.
2. Do not place it on a network containing NAS, workstations or sensitive accounts.
3. Preserve ESET screenshots, hashes and redacted logs.
4. Request a complete firmware hash and written explanation from the seller.
5. Prefer return/reklamasjon or a verified clean firmware image.

For seller/manufacturer:

1. Provide exact firmware image and SHA-256.
2. Explain the purpose and owner of com.android.netservice.
3. Explain why com.android.domain runs as system UID.
4. Explain the silent APK task for taskId 601.
5. Identify business.dnsyc.top, heartbeat.dnsyc.top and d.rdnss.cloud.
6. Provide firmware without the ESET-detected component.
7. Disable unauthenticated ADB and enforce SELinux in the shipping build.
8. Provide a signed change log for privileged system packages.

## 19. Final assessment

The examined Senz/SPR2226 projector is a high-risk Android firmware variant with a system-privileged updater/install chain and an ESET-detected domain service. The evidence is strong enough to justify quarantine, vendor escalation and a firmware replacement or return request.

The evidence is not strong enough to state that this exact device was an active residential proxy, that all Senz projectors are infected, or that a named manufacturer or retailer operated the observed infrastructure.
