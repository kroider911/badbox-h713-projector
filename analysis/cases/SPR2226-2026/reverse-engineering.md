# Senz / SPR2226: H713M variant analysis

**18 October 2026 · Device-specific case**

This case records a Senz projector identified by Android and USB as SPR2226. It extends the public H713/AT-M269 analysis with a separate firmware and package inventory. The device is related by platform, but is not assumed to be byte-identical to the public sample.

## 1. Assessment

The examined unit contains a privileged update/install chain:

~~~text
com.android.netservice
  └─ sofa-db task 601
       └─ Domain-1.0.6-20260709-release_aw.apk
            └─ com.android.domain 1.0.6
                 └─ com.android.systemss.SystemService
                      └─ Android UID 1000
~~~

The [code-level analysis](code-analysis.md) follows the retained APK through startup, scheduling, DNS selection, request headers, response decryption, download validation and installer submission.

The following are confirmed on this unit:

- Allwinner H713/H713M Android 11 platform
- unauthenticated ADB
- root available through su
- permissive SELinux
- system-level package installation capability
- a concrete database task for com.android.domain
- matching APK size, MD5 and SHA-256
- boot-time scripts capable of disabling Google boot receivers

The following are **not established**:

- operation as a residential proxy
- presence of the public sample's .rf proxy modules
- presence of yiyou, sysapp or adtest
- attribution to Senz, a retailer, a manufacturer or a hosting provider
- infection of every SPR2226 or Senz unit

## 2. Device

| Property | Value |
|---|---|
| Commercial name | Senz projector |
| Android/USB identity | SPR2226 |
| USB VID/PID | 1F3A:1001 |
| Manufacturer property | Allwinner |
| Device | h713m-tuna_p3 |
| Board/platform | ares |
| Boot hardware | sun50iw12p1 |
| Firmware | H713M-android11-v1.0 |
| Android | 11 / SDK 30 |
| Kernel | Linux 5.4.99 |
| Architecture | armv7l |
| Build type | userdebug |
| Build date | 16 Apr 2026 11:38:29 CST |
| Display | 1280×720 |
| Verified boot | green |
| VBMeta state | locked |

“Senz” is recorded as the commercial name supplied for the device. It is not used as attribution of the firmware or infrastructure.

## 3. Collection method

Collection was performed over USB ADB using read-only inspection wherever possible:

~~~bash
adb devices -l
adb shell getprop
adb shell su 0 id
adb shell pm list packages -f -i
adb shell dumpsys package <package>
adb shell netstat -tnp
adb shell sha256sum <file>
~~~

The investigation also included:

- inspection of private configuration files
- SQLite inspection of sofa-db
- static inspection of init scripts
- extraction and hashing of the domain APK
- independent scanning of the extracted file
- comparison against the public H713/AT-M269 case

No uncontrolled execution or dynamic instrumentation of the extracted APK was performed.

## 4. Runtime security posture

~~~text
ro.debuggable=1
ro.adb.secure=0
service.adb.tcp.port=5555
SELinux=permissive
su 0 id -> uid=0(root)
~~~

### Interpretation

This combination materially weakens the device security boundary:

- ADB is not protected by Android's normal authorization prompt.
- Root is available to the shell.
- SELinux is not enforcing policy.
- A userdebug build exposes development-oriented behavior.
- A reachable ADB service can expose the device to the local network.

Verified Boot being green and locked does not mean that the signed software is trustworthy; it only describes boot-image verification state.

## 5. Package inventory

### 5.1 com.android.netservice

~~~text
System path:       /system/app/netserevice-release
System version:    netservice-3.4.9-allwinner
Data version:      3.6.0
Version code:      60
First installed:   2026-04-16 05:38:48
Last updated:      2026-09-18 21:03:45
Installer:         com.android.netservice
~~~

Relevant permission groups:

~~~text
INSTALL_PACKAGES
REQUEST_INSTALL_PACKAGES
RECEIVE_BOOT_COMPLETED
SYSTEM_ALERT_WINDOW
INTERNET
~~~

The package has a system-image component and mutable application data. The data directory contained configuration and sofa-db.

### 5.2 com.android.domain

~~~text
Package:           com.android.domain
Version:           1.0.6
Version code:      106
First installed:   2026-08-30 12:37:44
Installer:         com.android.netservice
Service:           com.android.systemss.SystemService
Running UID:       1000 (system)
~~~

Observed high-impact capability groups included:

- package installation and deletion
- overlay/system alert window
- network access
- camera and microphone
- system settings
- reboot/shutdown-related system control

These permissions demonstrate capability, not proof that every capability was used.

### 5.3 InstallXAPK

~~~text
Path:        /system/app/InstallXAPK/InstallXAPK.apk
Package:     com.ik.installxapk
Version:     1.0.5
Version code: 5
~~~

The package has package-installation and boot-related capabilities. It is included here because it contributes to the privileged installation surface.

## 6. Update-task evidence

The netservice private database sofa-db contained the following logical records.

### APP_CONFIG_BEAN

~~~text
taskId:       601
package:      com.android.domain
component:    com.android.domain/com.android.systemss.SystemService
version:      1.0.6
version code: 106
AUTO_START:   1
OPEN_TIMES:   2
~~~

### TASK_INFO_BEAN

~~~text
task type:    1
taskId:       601
file:         Domain-1.0.6-20260709-release_aw.apk
MIME:         application/vnd.android.package-archive
file size:    3959797
MD5:          72ac40ce7df55d586f21c6d89cce6b7b
host:         40.160.68.219:38513
~~~

### Integrity relationship

The task record and the extracted APK agree on:

- package identity
- version
- file size
- MD5
- installer relationship

This establishes a local, device-specific relationship between netservice and the domain APK. It is stronger than a package-name match, but it does not prove that the remote download was observed live during collection.

## 7. APK evidence

Extracted APK:

~~~text
File size: 3959797 bytes
MD5:       72AC40CE7DF55D586F21C6D89CCE6B7B
SHA-256:   5B029ABE4AD2CD6DFA18064899B50190E00CE0F50BAC57CBD849502AB3108F30
~~~

ESET identified the extracted DEX as the threat `Android/TrojanDownloader.Agent.BOA`.

The APK was retained locally for targeted Java decompilation and instruction-level cross-checks; binaries are not published here.

## 8. Static bytecode findings

The retained APK was inspected with Android SDK `dexdump` and targeted JADX 1.5.6 single-class decompilation. The detailed [code-level report](code-analysis.md) gives method offsets, pseudocode, protocol framing, branch conditions and validation limitations. No extracted application code was executed.

### Network client and fallback domains

The DEX contains the following application classes and constants:

~~~text
com.android.nebulasdk.api.ServerInterface
com.android.nebulasdk.api.biz.BaseBiz
com.android.systemss.DomainPool
com.android.systemss.presenter.AppnetPresenter

default domain: d.rdnss.cloud
API path:       /app-api/hnc2fng/gnbht53hdv2/dhgb35dg
API path:       /app-api/hnc2fng/ghbn1hebdsh/yh65hbfvg3jfdbs
request base:   http://<resolved-address>:9901
HTTP client:    Retrofit + OkHttp
connect timeout: 30000 ms
~~~

`DomainPool` reads `CONFIG_DOMAINNAME` and `CONFIG_TEST_DOMAINNAME` through the app's configuration layer. It also queries the exported domain provider for `domainNames` and `type`, and can split comma-separated domain values into a candidate list. The server interface then selects a configured/test domain and constructs the HTTP base URL.

### Download and install path

The bytecode contains a concrete APK update path with the following indicators:

~~~text
postServerAppUpdate
downloadFile
down_file
local_file
PackageManager.getPackageInstaller()
PackageInstaller.SessionParams
PackageInstaller.createSession()
PackageInstaller.Session.openWrite()
PackageInstaller.Session.fsync()
PackageInstaller.Session.commit()
android.intent.action.PACKAGE_ADDED
~~~

The DEX also contains log strings for a new download task, download progress, completion and successful APK installation. The `PackageInstaller` sequence demonstrates that the application contains code to stage and commit an APK through Android's installer API. The task database and installer relationship show that this capability is relevant to the observed `com.android.domain` update chain; they do not, by themselves, prove which remote tasks were executed at every point in time.

### Device fingerprinting and command execution

The update client's Allwinner branch reads `/sys/class/sunxi_info/sys_info` for a chip/serial identifier and `eth0` for its MAC header. The separate `/proc/cpuinfo` parser is selected by the Rockchip branch. Command-execution references support these fixed local identifier reads; an arbitrary remote shell dispatcher was not demonstrated.

### Exported components

The manifest and bytecode identify exported components for the service, boot receiver and provider:

~~~text
com.android.systemss.SystemService
com.android.systemss.StartupBroadcast
com.android.provider.DomainProvider
~~~

`StartupBroadcast.onReceive()` processes only `BOOT_COMPLETED`; package add/remove actions are declared but ignored by this method. `DomainProvider` exposes CRUD operations for `domains` and `domains/#`. The inspected manifest declares no application/provider caller permission, and the reviewed CRUD methods contain no caller check. Cross-UID modification was not tested. See the code report for the provider's effect on future server selection.

## 9. Configuration and network indicators

Redacted configuration values:

~~~text
netservice CONFIG_DOMAINNAME=business.dnsyc.top
netservice CONFIG_HEARTBEAT_DOMAINNAME=heartbeat.dnsyc.top
domain CONFIG_DOMAINNAME=d.rdnss.cloud
domain CONFIG_TEST_DOMAINNAME=d.rdnss.cloud
~~~

Observed endpoint:

~~~text
40.160.68.219:38513
~~~

The configuration also contained device-specific identifiers and a system token. These are intentionally excluded.

### Attribution warning

The observed IP address belongs to hosting infrastructure. IP registration does not identify the software operator, manufacturer or retailer.

## 10. Boot and native components

Present system components:

~~~text
/system/bin/appsdisable
/system/bin/gmsopt
/system/bin/qw
/system/bin/systemmixservice
/system/lib/libsystemmix_jni.so
/system/lib/libsystemmixservice.so
/system/app/InstallXAPK/InstallXAPK.apk
~~~

### Boot scripts

appsdisable and gmsopt are attached to root init services triggered by sys.boot_completed=1. Their logic queries Google boot receivers and can call pm disable on matching packages.

This is a confirmed firmware behavior. It does not prove that Google packages were disabled on every boot; no disabled Google packages were present in the captured inventory.

### Native/Binder surface

systemmixservice and its JNI/native libraries are present as privileged system components. Their complete behavior was not reverse-engineered on this unit. The safe conclusion is presence of an additional privileged native/Binder surface, not a definitive claim about its purpose.

qw is present. Its exact equivalence to the public sample's binary was not established.

## 11. Process and network snapshot

Observed processes:

~~~text
com.android.netservice: system process
com.android.domain: system process
adbd: TCP 5555 LISTEN
~~~

At collection time, network connections were primarily associated with display functionality and ordinary Google/YouTube processes. No active connection owned by com.android.domain or com.android.netservice was observed.

This is a point-in-time negative observation. It cannot exclude:

- earlier or later connections
- scheduled heartbeat activity
- dormant task execution
- activity from a child or renamed process

## 12. Comparison with the public H713 case

| Indicator | AT-M269 public sample | Senz/SPR2226 |
|---|---:|---:|
| H713/H713M / ares | Confirmed | Confirmed |
| Android 11 | Confirmed | Confirmed |
| Unauthenticated ADB | Confirmed | Confirmed |
| Permissive SELinux | Confirmed | Confirmed |
| com.android.umanalytics.yiyou | Present | Not found |
| com.android.sysapp | Present | Not found |
| com.google.adtest | Present | Not found |
| plugin.jar | Present | Not found |
| Encrypted .rf modules | Present | Not found |
| com.android.netservice | Not established | Present |
| com.android.domain | Not established | Present |
| Active proxy traffic | Sample evidence | Not observed |

The defensible conclusion is related platform lineage with a distinct firmware and package set. The evidence does not support describing the two devices as byte-identical.

## 13. Timeline

| Time | Event | Source |
|---|---|---|
| 16 Apr 2026 | Firmware build date | Android properties |
| 16 Apr 2026 | netservice base package installed | Package metadata |
| 30 Aug 2026 12:37:44 | domain first installed | Package metadata |
| 18 Sep 2026 21:03:45 | netservice data component updated | Package metadata |
| 17 Oct 2026 around 23:57 | domain configuration recorded d.rdnss.cloud | Redacted config.xml |
| 18 Oct 2026 | APK extracted, hashed and statically analysed | Local sample and code outputs |

The timeline documents local device state. It does not establish the first time a remote operator used the service.

## 14. Confidence assessment

| Finding | Confidence | Basis |
|---|---|---|
| H713/H713M Android 11 identity | High | Independent USB and ADB properties |
| Unauthenticated ADB/root/permissive SELinux | High | Direct runtime checks |
| netservice is an install/update component | High | Permissions, package metadata and database |
| domain was installed by netservice | High | Installer field, task record and install time |
| APK identity | High | Matching size, MD5 and SHA-256 |
| Boot-script behavior | High | Read-only script/init inspection |
| domain update control flow | High for reviewed methods | Targeted Java decompilation and DEX instructions; runtime delivery unverified |
| Active proxy operation | Not established | No matching modules or traffic snapshot |
| Byte identity with AT-M269 sample | Low | Different build and inventory |
| Manufacturer/retailer attribution | Not established | No attribution evidence |

## 15. Indicators

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

APK:

~~~text
SHA-256 5B029ABE4AD2CD6DFA18064899B50190E00CE0F50BAC57CBD849502AB3108F30
MD5     72AC40CE7DF55D586F21C6D89CCE6B7B
~~~

## 16. Reproduction checklist

Use an isolated test unit and store output outside a public repository:

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

Redact ADB serial, MAC addresses, CPU IDs, Android ID, Wi-Fi SSID/BSSID, JWT-like tokens, user names and local filesystem paths before publication.

## 17. Limitations

- The retained APK was inspected with targeted JADX decompilation and `dexdump`; no dynamic execution or instrumentation was performed.
- The report uses package metadata, database records, configuration and system artifacts rather than a complete firmware image.
- No continuous packet capture was performed.
- No claim is made that Senz is the developer, operator or distributor of the observed software.
- No claim is made that every Senz or SPR2226 unit has the same firmware.
- No claim is made that the unit operated as a proxy node.
- Absence of a known module in one snapshot is not a lifetime guarantee.
- The public AT-M269 report is independent research, not vendor certification.

## 18. Recommended response

For the user:

1. Keep the device off the internet until the firmware is resolved.
2. Do not place it on a network containing NAS, workstations or sensitive accounts.
3. Preserve hashes, code evidence, detection records and redacted logs.
4. Request a complete firmware hash and written explanation from the seller.
5. Prefer return/reklamasjon or a verified clean firmware image.

For the seller/manufacturer:

1. Provide the exact firmware image and SHA-256.
2. Explain the purpose and owner of com.android.netservice.
3. Explain why com.android.domain runs as system UID.
4. Explain the silent APK task for taskId 601.
5. Identify business.dnsyc.top, heartbeat.dnsyc.top and d.rdnss.cloud.
6. Provide firmware with the identified component removed or independently remediated.
7. Disable unauthenticated ADB and enforce SELinux in the shipping build.
8. Provide a signed change log for privileged system packages.

## 19. Final assessment

The examined Senz/SPR2226 projector has a system-privileged updater/install chain. The reviewed code accepts encrypted remote application lists, replaces server candidates, stages downloads using size checks, and submits installer sessions without verifying the final result before reporting success. These code findings warrant vendor escalation and remediation; they do not establish proxy traffic or controller identity.

The evidence is not strong enough to state that this exact device was an active residential proxy, that all Senz projectors are infected, or that a named manufacturer or retailer operated the observed infrastructure.
