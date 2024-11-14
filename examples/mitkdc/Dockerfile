FROM opensuse/leap:15.6 AS ref_repo

RUN zypper --non-interactive mr -e -a &&\
    zypper --non-interactive --gpg-auto-import-keys ref --force && \
    zypper --non-interactive in hostname vim tcpdump iputils iproute2 netcat-openbsd krb5-client sudo \
      git-core vim tcpdump iputils iproute2 libopenssl-3-devel openldap2-devel \
      flex bison autoconf gettext-tools libtool make gcc awk gcc-c++ python3 strace gdb keyutils-devel

RUN pushd /root/ && git clone https://github.com/krb5/krb5.git && popd
COPY examples/mitkdc/*.patch /root/krb5
RUN pushd /root/krb5 && git apply *.patch && popd
ENV CFLAGS="-O0 -g -DDEBUG -D_GNU_SOURCE -fPIC"
ENV SS_LIB="-lss"
RUN pushd /root/krb5/src && autoreconf -fi && ./configure \
    --prefix=/usr \
    --exec-prefix=/usr \
    --bindir=/usr/bin \
    --sbindir=/usr/sbin \
    --sysconfdir=/etc \
    --datadir=/usr/share \
    --includedir=/usr/include \
    --libdir=/usr/lib64 \
    --libexecdir=/usr/libexec \
    --localstatedir=/var/lib/kerberos \
    --sharedstatedir=/var/lib \
    --mandir=/usr/share/man \
    --infodir=/usr/share/info \
    --localedir=/usr/share/locale \
    --without-system-et \
    --without-system-verto \
    --without-system-ss \
    --with-crypto-impl=openssl \
    --without-lmdb \
    --with-ldap \
    --with-pam \
    --without-selinux \
    --disable-rpath \
    --disable-static \
    --enable-shared \
    --enable-dns-for-realm \
    --enable-pkinit \
    && make && make install && popd && ldconfig

RUN ln -s /usr/lib64/krb5/plugins/kdb/db2.so /usr/lib64/krb5/plugins/kdb/db2
RUN ln -s /usr/lib64/krb5/plugins/kdb/kldap.so /usr/lib64/krb5/plugins/kdb/kldap

COPY examples/mitkdc/kadm5.acl /var/lib/kerberos/krb5kdc/kadm5.acl
COPY examples/mitkdc/kadm5.dict /var/lib/kerberos/krb5kdc/kadm5.dict
COPY examples/mitkdc/kdc.conf /var/lib/kerberos/krb5kdc/kdc.conf
COPY examples/mitkdc/krb5.conf /etc/krb5.conf
COPY examples/mitkdc/provision.sh /tmp/provision.sh

RUN id
RUN /tmp/provision.sh

RUN useradd --shell /bin/bash --create-home --home-dir /home/krime -u 2000 krime
RUN echo "krime ALL=(ALL:ALL) NOPASSWD:ALL" > /etc/sudoers.d/krime

COPY examples/mitkdc/entrypoint.sh /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]
SHELL ["/bin/bash", "--login", "-c"]
CMD ["/bin/bash", "--login"]

EXPOSE 88/tcp
EXPOSE 88/udp
