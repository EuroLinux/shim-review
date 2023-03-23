FROM oraclelinux:9
RUN dnf -y install openssl openssl-devel pesign wget dos2unix \
                   rpm-build gcc make elfutils-libelf-devel git
ADD shim-unsigned-x64-15.7-1.el9.src.rpm /
RUN echo -e '%_topdir /builddir/build/\n%_tmp %{_topdir}/tmp' > /root/.rpmmacros
RUN rpm -ivh shim-unsigned-x64-15.7-1.el9.src.rpm
RUN sed -i 's/linux32 -B/linux32/g' /builddir/build/SPECS/shim-unsigned-x64.spec
RUN sed -i 's/ol/eurolinux/g' /etc/os-release
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
