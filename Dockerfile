FROM eurolinux/eurolinux-9:eurolinux-9-9.0.13
RUN echo -e '\
[baseos-9.1]\n\
name = EL 9.1 BaseOS\n\
baseurl=https://vault.cdn.euro-linux.com/legacy/eurolinux/9/9.1/BaseOS/x86_64/os/\n\
enabled=1\n\
gpgcheck=1\n\
gpgkey=file:///etc/pki/rpm-gpg/RPM-GPG-KEY-eurolinux9\n\
\n\
[appstream-9.1]\n\
name = EL 9.1 AppStream\n\
baseurl=https://vault.cdn.euro-linux.com/legacy/eurolinux/9/9.1/AppStream/x86_64/os/\n\
enabled=1\n\
gpgcheck=1\n\
gpgkey=file:///etc/pki/rpm-gpg/RPM-GPG-KEY-eurolinux9\n\
\n\
[crb-9.1]\n\
name = EL 9.1 CRB\n\
baseurl=https://vault.cdn.euro-linux.com/legacy/eurolinux/9/9.1/CRB/x86_64/os/\n\
enabled=1\n\
gpgcheck=1\n\
gpgkey=file:///etc/pki/rpm-gpg/RPM-GPG-KEY-eurolinux9\n\
' > /etc/yum.repos.d/eurolinux.repo
RUN dnf -y install openssl openssl-devel pesign wget dos2unix \
                   rpm-build gcc make elfutils-libelf-devel git
ADD shim-unsigned-x64-15.7-1.el9.src.rpm /
RUN echo -e '%_topdir /builddir/build/\n%_tmp %{_topdir}/tmp' > /root/.rpmmacros
RUN rpm -ivh shim-unsigned-x64-15.7-1.el9.src.rpm
RUN sed -i 's/linux32 -B/linux32/g' /builddir/build/SPECS/shim-unsigned-x64.spec
RUN rpmbuild -bb /builddir/build/SPECS/shim-unsigned-x64.spec
COPY shimx64.efi /
RUN ls -lh --time-style=long-iso /builddir/build/RPMS/x86_64 | cut -d' ' -f5-8
RUN rpm2cpio /builddir/build/RPMS/x86_64/shim-unsigned-x64*.rpm | cpio -diu
RUN ls -l /*.efi ./usr/share/shim/15*.el9/*/shim*.efi
RUN objcopy -O binary --only-section=.sbat \
    ./usr/share/shim/15*.el9/x64/shimx64.efi /dev/stdout
RUN hexdump -Cv ./usr/share/shim/15*.el9/x64/shimx64.efi > built-x64.hex
RUN hexdump -Cv /shimx64.efi > orig-x64.hex
RUN objdump -h /usr/share/shim/15*.el9/x64/shimx64.efi
RUN diff -u orig-x64.hex built-x64.hex
RUN pesign -h -P -i /usr/share/shim/15*.el9/x64/shimx64.efi
RUN pesign -h -P -i /shimx64.efi
RUN sha256sum /usr/share/shim/15*.el9/x64/shimx64.efi /shimx64.efi 
