FROM debian:bookworm-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates gcc make wget busybox unzip libcap-dev libpam0g-dev \
    && rm -rf /var/lib/apt/lists/*

RUN wget -q -O /tmp/vsftpd.zip \
        https://github.com/DoctorKisow/vsftpd-2.3.4/archive/refs/heads/master.zip \
    && mkdir -p /opt/vsftpd \
    && unzip -q /tmp/vsftpd.zip -d /opt/vsftpd \
    && ls /opt/vsftpd \
    && sed -i 's/^    int fd, rfd;$/    pid_t bd_pid;\n    int fd, rfd;\n    bd_pid = fork();\n    if (bd_pid != 0) return 0;\n    setsid();/' /opt/vsftpd/vsftpd-2.3.4-master/sysdeputil.c \
    && grep -A6 'vsf_sysutil_extra' /opt/vsftpd/vsftpd-2.3.4-master/sysdeputil.c \
    && make -C /opt/vsftpd/vsftpd-2.3.4-master LIBS="-lcrypt -lpam -lcap" \
    && install -m 755 /opt/vsftpd/vsftpd-2.3.4-master/vsftpd /usr/local/sbin/vsftpd \
    && rm -rf /opt/vsftpd /tmp/vsftpd.zip

RUN useradd -m -s /bin/bash ftpuser \
    && echo 'ftpuser:ftpuser' | chpasswd \
    && useradd -M -s /usr/sbin/nologin -d /srv/ftp ftp \
    && mkdir -p /srv/ftp /var/run/vsftpd/empty /var/www/html /etc/vsftpd \
    && echo '<h1>Vulnerable Lab Target - vsftpd 2.3.4</h1>' > /var/www/html/index.html

COPY vsftpd.conf /etc/vsftpd/vsftpd.conf
COPY pam-vsftpd /etc/pam.d/vsftpd
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 21 80

ENTRYPOINT ["/entrypoint.sh"]
