#
# Regular cron jobs for the snart package
#
0 4	* * *	root	[ -x /usr/bin/snart_maintenance ] && /usr/bin/snart_maintenance
