#!/bin/sh
mkdir -p /var/run/vsftpd/empty
busybox httpd -f -p 80 -h /var/www/html &
exec /usr/local/sbin/vsftpd /etc/vsftpd/vsftpd.conf
