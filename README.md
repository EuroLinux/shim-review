This repo is for review of requests for signing shim.  To create a request for review:

- clone this repo
- edit the template below
- add the shim.efi to be signed
- add build logs
- add any additional binaries/certificates/SHA256 hashes that may be needed
- commit all of that
- tag it with a tag of the form "myorg-shim-arch-YYYYMMDD"
- push that to github
- file an issue at https://github.com/rhboot/shim-review/issues with a link to your tag
- approval is ready when the "accepted" label is added to your issue

Note that we really only have experience with using GRUB2 or systemd-boot on Linux, so
asking us to endorse anything else for signing is going to require some convincing on
your part.

Check the docs directory in this repo for guidance on submission and
getting your shim signed.

Here's the template:

*******************************************************************************
### What organization or people are asking to have this signed?
*******************************************************************************
[EuroLinux Sp. z o.o.](https://en.euro-linux.com)

*******************************************************************************
### What product or service is this for?
*******************************************************************************
EuroLinux 9

*******************************************************************************
### What's the justification that this really does need to be signed for the whole world to be able to boot it?
*******************************************************************************
EuroLinux is an enterprise-class operating system that has been actively
maintained since 2015.EuroLinux is present in the top 100 on DistroWatch.
EuroLinux Sp. z o.o. is a company founded by people, who originally formed the
Open Source market in Central Europe.

*******************************************************************************
### Why are you unable to reuse shim from another distro that is already signed?
*******************************************************************************
Because we provide our own GRUB2 and kernel builds. Therefore we need to
provide our own shim for the bootchain to be complete.

*******************************************************************************
### Who is the primary contact for security updates, etc.?
The security contacts need to be verified before the shim can be accepted. For subsequent requests, contact verification is only necessary if the security contacts or their PGP keys have changed since the last successful verification.

An authorized reviewer will initiate contact verification by sending each security contact a PGP-encrypted email containing random words.
You will be asked to post the contents of these mails in your `shim-review` issue to prove ownership of the email addresses and PGP keys.
*******************************************************************************
- Name: [Jarosław Mazurkiewicz](https://github.com/jaromaz)
- Position: Senior DevOps Engineer
- Email address: jm@euro-linux.com
- [PGP key](pgp/jm.pub) fingerprint: EF0F D0ED C434 B608 079B  49C9 6695 4374 173C D866

(Key should be signed by the other security contacts, pushed to a keyserver
like keyserver.ubuntu.com, and preferably have signatures that are reasonably
well known in the Linux community.)

*******************************************************************************
### Who is the secondary contact for security updates, etc.?
*******************************************************************************
- Name: [Kamil Aronowski](https://github.com/aronowski)
- Position: Information System Security Engineer
- Email address: ka@euro-linux.com
- [PGP key](pgp/ka.pub) fingerprint: B761 A3E6 6292 3749 3C0A  6B4E FD76 C457 54FA DC09

(Key should be signed by the other security contacts, pushed to a keyserver
like keyserver.ubuntu.com, and preferably have signatures that are reasonably
well known in the Linux community.)

*******************************************************************************
### Were these binaries created from the 15.8 shim release tar?
Please create your shim binaries starting with the 15.8 shim release tar file: https://github.com/rhboot/shim/releases/download/15.8/shim-15.8.tar.bz2

This matches https://github.com/rhboot/shim/releases/tag/15.8 and contains the appropriate gnu-efi source.

*******************************************************************************
Yes, we are using the source from the URL:
`https://github.com/rhboot/shim/releases/download/15.8/shim-15.8.tar.bz2`

Furthermore, I've verified that the tarball is authentic in regard to its
checksums and the detached signature. The checksums are:

```
a9452c2e6fafe4e1b87ab2e1cac9ec00  shim-15.8.tar.bz2
cdec924ca437a4509dcb178396996ddf92c11183  shim-15.8.tar.bz2
a79f0a9b89f3681ab384865b1a46ab3f79d88b11b4ca59aa040ab03fffae80a9  shim-15.8.tar.bz2
30b3390ae935121ea6fe728d8f59d37ded7b918ad81bea06e213464298b4bdabbca881b30817965bd397facc596db1ad0b8462a84c87896ce6c1204b19371cd1  shim-15.8.tar.bz2
```

This tarball is also located inside the
[shim-unsigned-x64-15.8-1.el9.src.rpm](./shim-unsigned-x64-15.8-1.el9.src.rpm)
Source RPM.

*******************************************************************************
### URL for a repo that contains the exact code which was built to get this binary:
*******************************************************************************
https://github.com/rhboot/shim/releases/tag/15.8

*******************************************************************************
### What patches are being applied and why:
*******************************************************************************
No patches.

*******************************************************************************
### Do you have the NX bit set in your shim? If so, is your entire boot stack NX-compatible and what testing have you done to ensure such compatibility?

See https://techcommunity.microsoft.com/t5/hardware-dev-center/nx-exception-for-shim-community/ba-p/3976522 for more details on the signing of shim without NX bit.
*******************************************************************************
No - as far as we're aware Enterprise Linux 9.3 (the current release) does not
have the kernel patches that went into the upstream kernel 6.7 and provide
solid NX support. We have no information whatsoever if such support would be
ported to the 5.14 kernel in EL9. Therefore, we're not setting the NX
compatibility bit.

*******************************************************************************
### If shim is loading GRUB2 bootloader what exact implementation of Secureboot in GRUB2 do you have? (Either Upstream GRUB2 shim_lock verifier or Downstream RHEL/Fedora/Debian/Canonical-like implementation)
*******************************************************************************
RHEL-like implementation.

*******************************************************************************
### If shim is loading GRUB2 bootloader and your previously released shim booted a version of GRUB2 affected by any of the CVEs in the July 2020, the March 2021, the June 7th 2022, the November 15th 2022, or 3rd of October 2023 GRUB2 CVE list, have fixes for all these CVEs been applied?

* 2020 July - BootHole
  * Details: https://lists.gnu.org/archive/html/grub-devel/2020-07/msg00034.html
  * CVE-2020-10713
  * CVE-2020-14308
  * CVE-2020-14309
  * CVE-2020-14310
  * CVE-2020-14311
  * CVE-2020-15705
  * CVE-2020-15706
  * CVE-2020-15707
* March 2021
  * Details: https://lists.gnu.org/archive/html/grub-devel/2021-03/msg00007.html
  * CVE-2020-14372
  * CVE-2020-25632
  * CVE-2020-25647
  * CVE-2020-27749
  * CVE-2020-27779
  * CVE-2021-3418 (if you are shipping the shim_lock module)
  * CVE-2021-20225
  * CVE-2021-20233
* June 2022
  * Details: https://lists.gnu.org/archive/html/grub-devel/2022-06/msg00035.html, SBAT increase to 2
  * CVE-2021-3695
  * CVE-2021-3696
  * CVE-2021-3697
  * CVE-2022-28733
  * CVE-2022-28734
  * CVE-2022-28735
  * CVE-2022-28736
  * CVE-2022-28737
* November 2022
  * Details: https://lists.gnu.org/archive/html/grub-devel/2022-11/msg00059.html, SBAT increase to 3
  * CVE-2022-2601
  * CVE-2022-3775
* October 2023 - NTFS vulnerabilities
  * Details: https://lists.gnu.org/archive/html/grub-devel/2023-10/msg00028.html, SBAT increase to 4
  * CVE-2023-4693
  * CVE-2023-4692
*******************************************************************************
No, the Enterprise Linux 9-provided GRUB2 was not affected by the October 2023
CVEs, therefore the fixes from that timeframe were not applied.

*******************************************************************************
### If shim is loading GRUB2 bootloader, and if these fixes have been applied, is the upstream global SBAT generation in your GRUB2 binary set to 4?
The entry should look similar to: `grub,4,Free Software Foundation,grub,GRUB_UPSTREAM_VERSION,https://www.gnu.org/software/grub/`
*******************************************************************************
It's set to `3` as the Enterprise Linux 9-provided GRUB2 was not affected by
the October 2023 CVEs, therefore those fixes that resulted in a bump to `4`
were not applied.

*******************************************************************************
### Were old shims hashes provided to Microsoft for verification and to be added to future DBX updates?
### Does your new chain of trust disallow booting old GRUB2 builds affected by the CVEs?
*******************************************************************************
N/A: we haven't yet received a signed shim binary from Microsoft.

*******************************************************************************
### If your boot chain of trust includes a Linux kernel:
### Is upstream commit [1957a85b0032a81e6482ca4aab883643b8dae06e "efi: Restrict efivar_ssdt_load when the kernel is locked down"](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=1957a85b0032a81e6482ca4aab883643b8dae06e) applied?
### Is upstream commit [75b0cea7bf307f362057cc778efe89af4c615354 "ACPI: configfs: Disallow loading ACPI tables when locked down"](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=75b0cea7bf307f362057cc778efe89af4c615354) applied?
### Is upstream commit [eadb2f47a3ced5c64b23b90fd2a3463f63726066 "lockdown: also lock down previous kgdb use"](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=eadb2f47a3ced5c64b23b90fd2a3463f63726066) applied?
*******************************************************************************
The commits have been applied.

Furthermore, the issue fixed by commit eadb2f47a3ced5c64b23b90fd2a3463f63726066
does not affect us, since we're using the following config for x86\_64, the
architecture for which we apply to have our shim signed:

```
$ grep -r CONFIG_KDB_DEFAULT_ENABLE kernel-x86_64-*.config
kernel-x86_64-debug-rhel.config:CONFIG_KDB_DEFAULT_ENABLE=0x0
kernel-x86_64-rhel.config:CONFIG_KDB_DEFAULT_ENABLE=0x0
kernel-x86_64-rt-debug-rhel.config:CONFIG_KDB_DEFAULT_ENABLE=0x0
kernel-x86_64-rt-rhel.config:CONFIG_KDB_DEFAULT_ENABLE=0x0
```

*******************************************************************************
### Do you build your signed kernel with additional local patches? What do they do?
*******************************************************************************
Branding patches only.

*******************************************************************************
### Do you use an ephemeral key for signing kernel modules?
### If not, please describe how you ensure that one kernel build does not load modules built for another kernel.
*******************************************************************************
Yes, this is the configuration file responsible for the key's characteristics:

```
$ cat x509.genkey.rhel 
[ req ]
default_bits = 3072
distinguished_name = req_distinguished_name
prompt = no
x509_extensions = myexts

[ req_distinguished_name ]
O = EuroLinux
CN = EuroLinux kernel signing key
emailAddress = security@euro-linux.com

[ myexts ]
basicConstraints=critical,CA:FALSE
keyUsage=digitalSignature
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid
```

It normally resides inside a kernel's Source RPM and is used as part of the
build process when `rpmbuild` is invoked.

*******************************************************************************
### If you use vendor_db functionality of providing multiple certificates and/or hashes please briefly describe your certificate setup.
### If there are allow-listed hashes please provide exact binaries for which hashes are created via file sharing service, available in public with anonymous access for verification.
*******************************************************************************
We don't use vendor_db functionality in this build.

*******************************************************************************
### If you are re-using a previously used (CA) certificate, you will need to add the hashes of the previous GRUB2 binaries exposed to the CVEs to vendor_dbx in shim in order to prevent GRUB2 from being able to chainload those older GRUB2 binaries. If you are changing to a new (CA) certificate, this does not apply.
### Please describe your strategy.
*******************************************************************************
N/A: we haven't yet received a signed shim binary from Microsoft.

*******************************************************************************
### What OS and toolchain must we use to reproduce this build?  Include where to find it, etc.  We're going to try to reproduce your build as closely as possible to verify that it's really a build of the source tree you tell us it is, so these need to be fairly thorough. At the very least include the specific versions of gcc, binutils, and gnu-efi which were used, and where to find those binaries.
### If the shim binaries can't be reproduced using the provided Dockerfile, please explain why that's the case and what the differences would be.
*******************************************************************************
[Dockerfile](Dockerfile) to reproduce this build is included.

*******************************************************************************
### Which files in this repo are the logs for your build?
This should include logs for creating the buildroots, applying patches, doing the build, creating the archives, etc.
*******************************************************************************
[build.log](logs/build.log) and [root.log](logs/root.log).

The build process was ran on an Enterprise Linux 8 host with the
provider-supplied mock version and the
[mock-eurolinux-9-x86_64.cfg](./mock-eurolinux-9-x86_64.cfg) file.

*******************************************************************************
### What changes were made in the distor's secure boot chain since your SHIM was last signed?
For example, signing new kernel's variants, UKI, systemd-boot, new certs, new CA, etc..
*******************************************************************************
N/A: we haven't yet received a signed shim binary from Microsoft.

*******************************************************************************
### What is the SHA256 hash of your final SHIM binary?
*******************************************************************************
c6763bf19239ad8437dde50d8263b6ab776e0ecbb48cab85d55fe3e97771ae79

*******************************************************************************
### How do you manage and protect the keys used in your SHIM?
*******************************************************************************
The keys are stored on a FIPS 140-2 certified HSM. Access to machine used to
sign binaries is restricted physically. Only 2 trusted individuals have access
to it.

*******************************************************************************
### Do you use EV certificates as embedded certificates in the SHIM?
*******************************************************************************
No.

*******************************************************************************
### Do you add a vendor-specific SBAT entry to the SBAT section in each binary that supports SBAT metadata ( GRUB2, fwupd, fwupdate, systemd-boot, systemd-stub, shim + all child shim binaries )?
### Please provide exact SBAT entries for all SBAT binaries you are booting or planning to boot directly through shim.
### Where your code is only slightly modified from an upstream vendor's, please also preserve their SBAT entries to simplify revocation.
If you are using a downstream implementation of GRUB2 or systemd-boot (e.g.
from Fedora or Debian), please preserve the SBAT entry from those distributions
and only append your own. More information on how SBAT works can be found
[here](https://github.com/rhboot/shim/blob/main/SBAT.md).
*******************************************************************************
**`shimx64.efi`**:

```
sbat,1,SBAT Version,sbat,1,https://github.com/rhboot/shim/blob/main/SBAT.md
shim,4,UEFI shim,shim,1,https://github.com/rhboot/shim
shim.eurolinux,1,EuroLinux,shim,15.8,security@euro-linux.com
```

**`grubx64.efi`**:

The justification for the `grub,3` entry has been provided earlier in this
document.

```
sbat,1,SBAT Version,sbat,1,https://github.com/rhboot/shim/blob/main/SBAT.md
grub,3,Free Software Foundation,grub,2.06,https//www.gnu.org/software/grub/
grub.rh,2,Red Hat,grub2,2.06-70.el9_3.2,mailto:secalert@redhat.com
grub.eurolinux,1,EuroLinux,grub2,2.06-70.el9_3.2,mailto:security@euro-linux.com
```

**`fwupdx64.efi`**:

Yes, the error `sbat,1,UEFI shim` (rather than `sbat,1,SBAT Version`) in the
first line is intentional as that's the entry upstream uses, therefore we reuse
it.

```
sbat,1,UEFI shim,sbat,1,https://github.com/rhboot/shim/blob/main/SBAT.md
fwupd-efi,1,Firmware update daemon,fwupd-efi,1.4,https://github.com/fwupd/fwupd-efi
fwupd-efi.rhel,1,Red Hat Enterprise Linux,fwupd,1.8.16,mail:secalert@redhat.com
fwupd-efi.eurolinux,1,EuroLinux,fwupd,1.8.16,mail:security@euro-linux.com
```

*******************************************************************************
### If shim is loading GRUB2 bootloader, which modules are built into your signed GRUB2 image?
*******************************************************************************

The following ones (entries taken directly from `grub.macros`):

```
efi_netfs efifwsetup efinet lsefi lsefimmap connectefi

backtrace chain tpm usb usbserial_common usbserial_pl2303 usbserial_ftdi usbserial_usbdebug keylayouts at_keyboard

all_video boot blscfg
cat configfile cryptodisk
echo ext2 f2fs fat font
gcry_rijndael gcry_rsa gcry_serpent
gcry_sha256 gcry_twofish gcry_whirlpool
gfxmenu gfxterm gzio
halt http increment iso9660
jpeg loadenv loopback linux lvm luks
luks2 mdraid09 mdraid1x minicmd net
normal part_apple part_msdos part_gpt
password_pbkdf2 pgp png reboot regexp
search search_fs_uuid search_fs_file
search_label serial sleep syslinuxcfg
test tftp version video xfs zstd
```

*******************************************************************************
### If you are using systemd-boot on arm64 or riscv, is the fix for [unverified Devicetree Blob loading](https://github.com/systemd/systemd/security/advisories/GHSA-6m6p-rjcq-334c) included?
*******************************************************************************
N/A

*******************************************************************************
### What is the origin and full version number of your bootloader (GRUB2 or systemd-boot or other)?
*******************************************************************************
Same version as RHEL: `grub2-2.06-70.el9_3.2.src.rpm`. The only changes are
related to our SBAT entry and our certificate.

*******************************************************************************
### If your SHIM launches any other components, please provide further details on what is launched.
*******************************************************************************
It also launches fwupd.

*******************************************************************************
### If your GRUB2 or systemd-boot launches any other binaries that are not the Linux kernel in SecureBoot mode, please provide further details on what is launched and how it enforces Secureboot lockdown.
*******************************************************************************
GRUB2 is only used to load Linux kernel.

*******************************************************************************
### How do the launched components prevent execution of unauthenticated code?
*******************************************************************************
GRUB2 verifies signatures on booted kernels via shim. fwupd does not include
code to launch other binaries, it can only load UEFI updates.

*******************************************************************************
### Does your SHIM load any loaders that support loading unsigned kernels (e.g. GRUB2)?
*******************************************************************************
No - our shim loads only fwupd and the GRUB2 version that only supports loading
signed kernels.

*******************************************************************************
### What kernel are you using? Which patches does it includes to enforce Secure Boot?
*******************************************************************************
RHEL version of Linux kernel `kernel-5.14.0-362.18.1.el9_3.src.rpm`.
RHEL patches only for Secure Boot support

*******************************************************************************
### Add any additional information you think we may need to validate this shim.
*******************************************************************************
The key pair of the primary contact has changed since [this application
](https://github.com/rhboot/shim-review/issues/258)

While the [last review](https://github.com/rhboot/shim-review/issues/327) got
accepted, we haven't yet received a signed binary from Microsoft and it's been
agreed that there might be issues with signing 15.7 binaries. Furthermore, we
got our application accepted before the [Microsoft exception regarding NX
support](https://techcommunity.microsoft.com/t5/hardware-dev-center/nx-exception-for-shim-community/ba-p/3976522)
was made public.
