#!/bin/sh
# Copyright (c) 2011 Steve Grubb. ALL RIGHTS RESERVED.
# sgrubb@redhat.com
#
# This software may be freely redistributed under the terms of the GNU
# public license version 2.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
#
# In Feb 2011, DISA released UNIX Security Checklist Version 5,
# Release 1.28 to match with the OS SRG Unix.
# http://iase.disa.mil/stigs/downloads/zip/u_unix_v5r1-28_checklist_20110128.zip
# http://iase.disa.mil/stigs/downloads/zip/unclassified_os-srg-unix_v1r1_finalsrg.zip
#
# This file will test permission settings to see if they match what
# the STIG is asking for in places provided by the OS.

PATH=/bin:/usr/bin

#01) 0920 /root should be 0750 or less
find / -maxdepth 1 -type d -perm /0027 -name root -printf "GEN000920: %p is %m should be 0750 or less\n" 2>/dev/null

#02) 1180 network service daemon files should be 0755 or less
find /etc/sysconfig/network-scripts -type f -perm /0022 -printf "GEN001180: %p is %m should be 0755 or less\n" 2>/dev/null
find /etc/sysconfig/networking -type f -perm /0022 -printf "GEN001180: %p is %m should be 0755 or less\n" 2>/dev/null

#03) 1260 syslog logs should be 0640 or less
#find /var/log -type f -perm /0137 -printf "GEN001260: %p is %m should be 0640 or less\n" 2>/dev/null | egrep -v 'wtmp|lastlog'
find /var/log -maxdepth 2 -type f -perm /0137 -printf "GEN001260: %p is %m should be 0640 or less\n" 2>/dev/null | egrep -v 'wtmp|lastlog'
#files=`cat  /etc/rsyslog.conf | grep -v ^# | grep '/var/log/' | tr '-' ' ' | awk '{ print $2 }'`
#for f in $files ; do
#	find / -wholename "$f*" -type f -perm /0137 -printf "GEN001260: %p is %m should be 0640 or less\n" 2>/dev/null
#done

#04) 1800 skeleton /etc/skel/* files must be 0644 or less
find /etc/skel -type f -perm /0133 -printf "GEN001800: %p is %m should be 0644 or less\n" 2>/dev/null

#05) 1280 man pages must be 0644 or less
find /usr/share/man -type f -perm /0133 -printf "GEN001280: %p is %m should be 0644 or less\n" 2>/dev/null

#06) 1300 library files must be 0755 or less
find /lib -type f -perm /0022 -printf "GEN001300: %p is %m should be 0755 or less\n" 2>/dev/null
find /lib64 -type f -perm /0022 -printf "GEN001300: %p is %m should be 0755 or less\n" 2>/dev/null
find /usr/lib -type f -perm /0022 -printf "GEN001300: %p is %m should be 0755 or less\n" 2>/dev/null
find /usr/lib64 -type f -perm /0022 -printf "GEN001300: %p is %m should be 0755 or less\n" 2>/dev/null
find /usr/local/lib -type f -perm /0022 -printf "GEN001300: %p is %m should be 0755 or less\n" 2>/dev/null
find /usr/local/lib64 -type f -perm /0022 -printf "GEN001300: %p is %m should be 0755 or less\n" 2>/dev/null

#07) 1200 system command files must be 0755 or less
if [ ! -h /bin ] ; then
	find /bin -type f -perm /0022 -printf "GEN001200: %p is %m should be 0755 or less\n" 2>/dev/null
	find /sbin -type f -perm /0022 -printf "GEN001200: %p is %m should be 0755 or less\n" 2>/dev/null
fi
find /usr/bin -type f -perm /0022 -printf "GEN001200: %p is %m should be 0755 or less\n" 2>/dev/null
find /usr/sbin -type f -perm /0022 -printf "GEN001200: %p is %m should be 0755 or less\n" 2>/dev/null
find /usr/local/bin -type f -perm /0022 -printf "GEN001200: %p is %m should be 0755 or less\n" 2>/dev/null
find /usr/local/sbin -type f -perm /0022 -printf "GEN001200: %p is %m should be 0755 or less\n" 2>/dev/null
find /usr/lib64/qt-3.3/bin -type f -perm /0022 -printf "GEN001200: %p is %m should be 0755 or less\n" 2>/dev/null
find /usr/java/j2re1.4.2_06/bin -type f -perm /0022 -printf "GEN001200: %p is %m should be 0755 or less\n" 2>/dev/null
find /usr/libexec -type f -perm /0022 -printf "GEN001200: %p is %m should be 0755 or less\n" 2>/dev/null

#08) 1220 system command dirs must be own by a system account
if [ ! -h /bin ] ; then
	find /bin -type d \( ! -user root \) -printf "GEN001220: %p is user %u should be root\n" 2>/dev/null
	find /sbin -type d \( ! -user root \) -printf "GEN001220: %p is user %u should be root\n" 2>/dev/null
fi
find /usr/bin -type d \( ! -user root \) -printf "GEN001220: %p is user %u should be root\n" 2>/dev/null
find /usr/sbin -type d \( ! -user root \) -printf "GEN001220: %p is user %u should be root\n" 2>/dev/null
find /usr/local/bin -type d \( ! -user root \) -printf "GEN001220: %p is user %u should be root\n" 2>/dev/null
find /usr/local/sbin -type d \( ! -user root \) -printf "GEN001220: %p is user %u should be root\n" 2>/dev/null
find /usr/lib64/qt-3.3/bin -type d \( ! -user root \) -printf "GEN001220: %p is user %u should be root\n" 2>/dev/null
find /usr/java/j2re1.4.2_06/bin -type d \( ! -user root \) -printf "GEN001220: %p is user %u should be root\n" 2>/dev/null
find /usr/libexec -type d \( ! -user root \) -printf "GEN001220: %p is user %u should be root\n" 2>/dev/null

#09) 1240 system command dirs must be owned by a system group
if [ ! -h /bin ] ; then
	find /bin -type d \( ! -group root \) -printf "GEN001220: %p is group %g should be root\n" 2>/dev/null
	find /sbin -type d \( ! -group root \) -printf "GEN001220: %p is group %g should be root\n" 2>/dev/null
fi
find /usr/bin -type d \( ! -group root \) -printf "GEN001220: %p is group %g should be root\n" 2>/dev/null
find /usr/sbin -type d \( ! -group root \) -printf "GEN001220: %p is group %g should be root\n" 2>/dev/null
find /usr/local/bin -type d \( ! -group root \) -printf "GEN001220: %p is group %g should be root\n" 2>/dev/null
find /usr/local/sbin -type d \( ! -group root \) -printf "GEN001220: %p is group %g should be root\n" 2>/dev/null
find /usr/lib64/qt-3.3/bin -type d \( ! -group root \) -printf "GEN001220: %p is user %u should be root\n" 2>/dev/null
find /usr/java/j2re1.4.2_06/bin -type d \( ! -group root \) -printf "GEN001220: %p is user %u should be root\n" 2>/dev/null
find /usr/libexec -type d \( ! -group root \) -printf "GEN001220: %p is group %g should be root\n" 2>/dev/null

#10) 1400 shadow must be owned by root
find /etc -maxdepth 1 -type f \( ! -user root \) -name shadow -printf "GEN001400: %p is user %u should be root\n" 2>/dev/null

#11) 1380 passwd must be 0644 or less
find /etc -maxdepth 1 -type f -perm /0133 -name passwd -printf "GEN001380: %p is %m should be 0644 or less\n" 2>/dev/null

#12) 1420 shadow must be 0400 or less
find /etc -maxdepth 1 -type f -perm /0377 -name shadow -printf "GEN001420: %p is %m should be 0400 or less\n" 2>/dev/null

#13) 2500 sticky bit must be on all world writable dirs
find / -path /proc -prune -o -type d \( -perm -0002 -a ! -perm -1000 \) -printf "GEN002500: %p is %m should be 1777\n" 2>/dev/null

#14) 2520 all world writable dirs must be owned by system account
find / -path /proc -prune -o -type d \( -perm -0002 -a ! \( -user root -o -user gdm \) \) -printf "GEN002520: world writable %p is user %u should be root\n" 2>/dev/null

#15) 2680 all audit logs must be owned by root
find /var/log/audit -type f \( ! -user root \) -printf "GEN001220: %p is user %u should be root\n" 2>/dev/null

#16) 2700 all audit logs must be 0640 or less
find /var/log/audit -type f -perm /0137 -printf "GEN002700: %p is %m should be 0640 or less\n" 2>/dev/null

#17) 3720 all xinetd dirs must be owned by root
find /etc -maxdepth 1 -type f \( ! -user root \) -name xinetd.conf -printf "GEN003720: %p is user %u should be root\n" 2>/dev/null
find /etc/xinetd.d/ -type f \( ! -user root \) -printf "GEN003720: %p is user %u should be root\n" 2>/dev/null

#18) 3740 all xinetd files must be 0640 or less
find /etc -maxdepth 1 -type f -perm /0137 -name xinetd.conf -printf "GEN003740: %p is %m should be 0640 or less\n" 2>/dev/null
find /etc/xinetd.d/ -type f -perm /0137 -printf "GEN003740: %p is %m should be 0640 or less\n" 2>/dev/null

#19) 3760 services file must be owned by root
find /etc -maxdepth 1 -type f \( ! -user root \) -name services -printf "GEN003760: %p is user %u should be root\n" 2>/dev/null

#20) 3780 services file must be 0644 or less
find /etc -maxdepth 1 -type f -perm /0133 -name services -printf "GEN003780: %p is %m should be 0644 or less\n" 2>/dev/null

#21) 4360 the alias file must be owned by root
find /etc -maxdepth 1 -type f \( ! -user root \) -name alias -printf "GEN004360: %p is user %u should be root\n" 2>/dev/null

#22) 4380 the alias file must be 644 or less
find /etc -maxdepth 1 -type f -perm /0133 -name alias -printf "GEN004380: %p is %m should be 0644 or less\n" 2>/dev/null

#23) 1480 all home dirs must be 0750 or less
find /home -mindepth 1 -maxdepth 1 -type d -perm /0027 -printf "GEN001480: %p is %m should be 0750 or less\n" 2>/dev/null

#24) 1860 all shell files in /etc must be owned by root
find /etc -maxdepth 1 -type f \( ! -user root \) -name bashrc -printf "GEN001860: %p is user % should be root\n" 2>/dev/null
find /etc -maxdepth 1 -type f \( ! -user root \) -name profile -printf "GEN001860: %p is user %u should be root\n" 2>/dev/null
find /etc/profile.d/ -type f \( ! -user root \) -printf "GEN001860: %p is user %u should be root\n" 2>/dev/null

#25) 1880 all shell files must be 0755 or less  ???
find /etc -maxdepth 1 -type f -perm /0022 -name bashrc -printf "GEN001880: %p is %m should be 0755 or less\n" 2>/dev/null
find /etc -maxdepth 1 -type f -perm /0022 -name profile -printf "GEN001880: %p is %m should be 0755 or less\n" 2>/dev/null
find /etc/profile.d/ -type f -perm /0022 -printf "GEN001880: %p is %m should be 0755 or less\n" 2>/dev/null

#26) 1580 all /etc/rc files must be 0755 or less
find /etc/rc* -type f -perm /0022 -printf "GEN001580: %p is %m should be 0755 or less\n" 2>/dev/null
find /etc/init.d -type f -perm /0022 -printf "GEN001580: %p is %m should be 0755 or less\n" 2>/dev/null
# Add checks for upstart and systemd respectively
if [ -d /etc/init ] ; then
find /etc/init -type f -perm /0022 -printf "GEN001580: %p is %m should be 0755 or less\n" 2>/dev/null
elif [ -d /etc/systemd ] ; then
find /etc/systemd -type f -perm /0022 -printf "GEN001580: %p is %m should be 0755 or less\n" 2>/dev/null
# Actual service files should not be executable
find /etc/systemd/system -type f -perm /0133 -printf "GEN001580: %p is %m should be 0644 or less\n" 2>/dev/null
fi

#27) 1560 all files in home dirs must be 0750 or less
#find /home  -mindepth 2 \( -type d -o -type f \) -perm /0022 -printf "GEN001560: %p is %m should be 0750 or less\n" 2>/dev/null

#28) 2980 cron.allow must be 0600 or less
find /etc -maxdepth 1 -type f -perm /0177 -name cron.allow -printf "GEN002980: %p is %m should be 0600 or less\n" 2>/dev/null

#29) 3080 crontab files must be 0600 or less
#30) 3080 cron script must be 0700 or less
find /etc -maxdepth 1 -type f -perm /0177 -name crontab -printf "GEN003080: %p is %m should be 0600 or less\n" 2>/dev/null
find /etc/cron.d -type f -perm /0077 -printf "GEN003080: %p is %m should be 0700 or less\n" 2>/dev/null
find /etc/cron.d -type f -perm /0077 -printf "GEN003080: %p is %m should be 0700 or less\n" 2>/dev/null
find /etc/cron.daily -type f -perm /0077 -printf "GEN003080: %p is %m should be 0700 or less\n" 2>/dev/null
find /etc/cron.hourly -type f -perm /0077 -printf "GEN003080: %p is %m should be 0700 or less\n" 2>/dev/null
find /etc/cron.weekly -type f -perm /0077 -printf "GEN003080: %p is %m should be 0700 or less\n" 2>/dev/null
find /var/spool/cron/ -type f -perm /0077 -printf "GEN003080: %p is %m should be 0700 or less\n" 2>/dev/null

#31) 3100 cron dirs must be 0755 or more less
find /etc/cron.d -type d -perm /0022 -printf "GEN003100: %p is %m should be 0755 or less\n" 2>/dev/null
find /etc/cron.d -type d -perm /0022 -printf "GEN003100: %p is %m should be 0755 or less\n" 2>/dev/null
find /etc/cron.daily -type d -perm /0022 -printf "GEN003100: %p is %m should be 0755 or less\n" 2>/dev/null
find /etc/cron.hourly -type d -perm /0022 -printf "GEN003100: %p is %m should be 0755 or less\n" 2>/dev/null
find /etc/cron.weekly -type d -perm /0022 -printf "GEN003100: %p is %m should be 0755 or less\n" 2>/dev/null
find /var/spool/cron -type d -perm /0022 -printf "GEN003100: %p is %m should be 0755 or less\n" 2>/dev/null

#32) 3120 cron dirs must be owned by root
find /etc/cron.d -type d \( ! -user root \) -printf "GEN003120: %p is %u should be root\n" 2>/dev/null
find /etc/cron.d -type d \( ! -user root \) -printf "GEN003120: %p is %u should be root\n" 2>/dev/null
find /etc/cron.daily -type d \( ! -user root \) -printf "GEN003120: %p is %u should be root\n" 2>/dev/null
find /etc/cron.hourly -type d \( ! -user root \) -printf "GEN003120: %p is %u should be root\n" 2>/dev/null
find /etc/cron.weekly -type d \( ! -user root \) -printf "GEN003120: %p is %u should be root\n" 2>/dev/null
find /var/spool/cron -type d \( ! -user root \) -printf "GEN003120: %p is %u should be root\n" 2>/dev/null

#33) 3140 cron dirs must be group root
find /etc/cron.d -type d \( ! -group root \) -printf "GEN003140: %p is %g should be root\n" 2>/dev/null
find /etc/cron.d -type d \( ! -group root \) -printf "GEN003140: %p is %g should be root\n" 2>/dev/null
find /etc/cron.daily -type d \( ! -group root \) -printf "GEN003140: %p is %g should be root\n" 2>/dev/null
find /etc/cron.hourly -type d \( ! -group root \) -printf "GEN003140: %p is %g should be root\n" 2>/dev/null
find /etc/cron.weekly -type d \( ! -group root \) -printf "GEN003140: %p is %g should be root\n" 2>/dev/null
find /var/spool/cron -type d \( ! -group root \) -printf "GEN003140: %p is %g should be root\n" 2>/dev/null

#34) 6140 smb.conf must be 0644 or less
find /etc/samba -maxdepth 1 -type f -perm /0133 -name smb.conf -printf "GEN006140: %p is %m should be 0644 or less\n" 2>/dev/null

#35) 8720 grub.conf must be 0600 or less
find /boot/grub -maxdepth 1 -type f -perm /0177 -name grub.conf -printf "GEN008720: %p is %m should be 0600 or less\n" 2>/dev/null

#36) 4000 the traceroute command must be 0700 or less
# Commenting this out as its unlikely that we change this file's permission
# find /bin -maxdepth 1 -type f -perm /0077 -name traceroute -printf "GEN004000: %p is %m should be 0700 or less\n" 

