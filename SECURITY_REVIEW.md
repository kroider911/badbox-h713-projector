# Security review note

## Scope

This note records a local safety review of the repository and a separate Android projector investigation. It is documentation only; malware samples and decrypted payload modules are intentionally not restored or redistributed.

## ESET detections

ESET detected and removed the repository sample `plugin.jar` as:

```text
Android/TrojanDownloader.Keenadu.A
SHA-256: E2E5F86DF18E0CDEF9595BD886280F158001250F1565FA3E6DFE492B114BE6F7
```

The same hash was present in two repository paths:

```text
downloads/plugin.jar
evidence/data/data/com.android.umanalytics.yiyou/cache/plugin.jar
```

The detection occurred while Git for Windows accessed the repository. This does not indicate that `git.exe` was infected; Git was the process reading the sample.

## Separation of evidence

The repository sample is not evidence that the sample is currently installed on the projector. The projector was separately observed to contain `com.android.domain`, which ESET classified as `Android/TrojanDownloader.Agent.BOA`. That APK had a different hash and must be treated as a separate finding.

## Device comparison

The projector shares important H713/H713M platform characteristics with the repository's analysed device family, including Allwinner H713/H713M, the `ares` platform, Android 11, unsecured ADB, root access and permissive SELinux. However, the exact firmware build and package inventory differ. The repository's specific proxy modules and packages such as `com.android.umanalytics.yiyou`, `com.android.sysapp` and `com.google.adtest` were not found on the examined unit.

## Handling

Do not restore the deleted sample files. Preserve hashes, paths, ESET event details and device-collected APK hashes separately if further independent analysis is required.

## Verification record

The following checks were performed before preparing this change:

```text
git ls-files                 7239 tracked paths
git diff --check             passed
git status --short           clean after commit
```

The ESET event paths and the SHA-256 above were compared against the repository's documented `plugin.jar` hash. The two detected paths were duplicate copies of the same 398,664-byte sample. The sample was not restored after quarantine.

## Limitations

This note does not claim that every H713/H713M device is affected, that the projector operated as a proxy, or that the repository sample was present on the projector. Those claims require a matching firmware image, matching package/module hashes, or direct network/process evidence from the individual device.
