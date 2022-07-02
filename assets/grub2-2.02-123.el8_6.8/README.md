#

The following macros have been enabled:

```
%global with_legacy_modules 1
%global with_legacy_common 1
```

Build with

```
rpmbuild --define 'pe_signing_token YubiHSM' --define "pe_signing_cert eurolinux - EuroLinux Sp. z o.o." -ba *.spec
```
