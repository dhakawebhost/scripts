#!/bin/bash
# pullsync.sh
# abrevick@liquidweb.com
# do some cpanel migrations!

# last updated: Feb 25 2015
version="1.8.0"

# variables
# these could be changed:
badusers="system|root" #excluded users when selecting all users.  filtered out by egrep -v. add more like this "system|root|alan|eric". HASH* is added to the function below so the wildcard is added properly.
rsync_excludes='--exclude=error_log --exclude=backup-*.tar.gz --exclude=mail/new' # filter out stuff like error_log, backup-*.tar.gz, only for homedir syncs.
if [[ -f /root/rsync_exclude.txt ]]; then
    rsync_excludes=`echo $rsync_excludes --exclude-from=/root/rsync_exclude.txt`
fi
#rsynced over from old server to the $dir
filelist="/etc/apf
/etc/cpbackup.conf
/etc/cron*
/etc/csf
/etc/exim.conf
/etc/passwd
/etc/sysconfig/network-scripts
/etc/userdomains
/etc/userdatadomains
/etc/wwwacct.conf
/root/.my.cnf
/usr/local/apache/conf
/usr/local/cpanel/version
/usr/local/lib/php.ini
/usr/share/ssl
/var/cpanel/databases
/var/cpanel/useclusteringdns
/var/lib/named/chroot/var/named/master
/var/spool/cron
/var/ssl
"

# vars that should not chnage
scriptname=`basename $0 .sh`
starttime=`date +%F.%T`
dir="/home/temp/pullsync"
pidfile="$dir/pullsync.pid"
pid="$$"
log="${dir}/$scriptname.log"
rsyncargs="-aqH"
userlistfile="/root/userlist.txt"
domainlistfile="/root/domainlist.txt"
remote_tempdir="/home/temp/pullsynctmp.$starttime" # cpmove files are created here on remote server
hostsfile="/usr/local/apache/htdocs/hosts.txt"
hostsfile_alt="/usr/local/apache/htdocs/hostsfile.txt"
sshargs="-o GSSAPIAuthentication=no" #disable "POSSIBLE BREAKIN ATTEMPT" messages
[ ! -f /etc/wwwacct.conf ] && echo "/etc/wwwacct.conf not found! Not a cpanel server?" && exit 99
cpanel_main_ip=`cat /etc/wwwacct.conf|grep ADDR|cut -d ' ' -f2`
proglist="ffmpeg
imagick
memcache
java
upcp
mysqlup
ea
postgres"

#pastebin functions
pastebin_url="paste.sysres.liquidweb.com"
pbfile="/tmp/pbfile"
#haste() { a=$(cat); curl -X POST -s -d "$a" https://$pastebin_url/documents | awk -F '"' -v url=$pastebin_url '{print "https://" url "/raw/"$4}'; }
haste() { 
	cat - > $pbfile ; 
	curl -X POST -s --data-binary @${pbfile} http://${pastebin_url}/documents | awk -F '"' -v url=$pastebin_url '{print "https://" url "/raw/"$4}' 
	rm $pbfile
}
#blahurl=`echo "blah blah blah" | haste`
#echo $blahurl

#colors
nocolor="\E[0m"
black="\033[0;30m"
grey="\033[1;30m"
red="\033[0;31m"
lightRed="\033[1;31m"
green="\033[0;32m"
lightGreen="\033[1;32m"
brown="\033[0;33m"
yellow="\033[1;33m"
blue="\033[0;34m"
lightBlue="\033[1;34m"
purple="\033[0;35m"
lightPurple="\033[1;35m"
cyan="\033[0;36m"
lightCyan="\033[1;36m"
white="\033[1;37m" # bold white
greyBg="\033[1;37;40m"

# check for newer version of script
fileserver="migration.sysres.liquidweb.com"
filepath="/pullsync.sh"
if host $fileserver ;then # check if we can connect to rmemote host
        server_version=`curl -s ${fileserver}${filepath} |grep ^version= | sed -e 's/^version="\([0-9.]*\)"/\1/'`
        echo "Detected server version as $server_version"
	    if echo $server_version | egrep -q '[0-9]+\.[0-9]+\.[0-9]+' ; then # check for a valid version format
	        if [[ $version < $server_version ]]; then
	                echo $version is less than server $server_version, downloading new version to /root/pullsync.sh.
	                wget -q -O /root/pullsync.sh ${fileserver}${filepath}
	                chmod +x /root/pullsync.sh
	                echo "Please rerun the script for the updated version."
	                exit 0;
	        else
	                echo $version is equal or greater than server $server_version
	        fi
	    else
	        echo "Script version on $fileserver is not in expected format, problem with the server? Continuing afer a few seconds..."
	        echo "Detected version as $server_version"
	        sleep 5
    	fi
else
        echo "Couldn't resolve host $fileserver to check for updates."
fi

# check for previous directory so we can load variables from it for finalsync
# could get vars from an older migration by linking /home/temp/pullsync.xxxx to /home/temp/pullsync
if [ -d "$dir" ]; then 
	#check for another running pullsync!
	if [ -f "$pidfile" ]; then
		echo "Found existing pullsync process id `cat $pidfile` in $pidfile, double check that another sync isnt running. exiting..."
		exit 1
	fi
	oldstarttime=`cat $dir/starttime.txt` ;
	olddir="$dir.$oldstarttime" ; 
	[ -f $olddir/ip.txt ] && oldip=`cat $olddir/ip.txt`
	[ -f $olddir/port.txt ] && oldport=`cat $olddir/port.txt`
	[ -f $olddir/userlist.txt ] && oldusercount=`cat $olddir/userlist.txt |wc -w` && someoldusers=`cat $olddir/userlist.txt | tr '\n' ' '| cut -d' ' -f1-6`
	rm -rf $dir
fi

# initalize working directory. $dir is a symlink to $dir.$starttime from last migration
mkdir -p "$dir.$starttime"
ln -s "$dir.$starttime" "$dir"
[ $olddir ] && echo "$olddir" > $dir/olddir.txt
# quit if something went really wrong 
[ ! -d "$dir" ] && echo "ERROR: could not find $dir!"  && exit 1
echo "$starttime" > $dir/starttime.txt
/bin/ls -A /var/cpanel/users > $dir/existing_users.txt
#create lock file
echo "$pid" > "$pidfile"

yesNo() { #generic yesNo function
	#repeat if yes or no option not valid
	while true; do
		# $* read every parameter given to the yesNo function which will be the message
		echo -ne "${yellow}${*}${white} (Y/N)?${nocolor} " 
		#junk holds the extra parameters yn holds the first parameters
		read yn junk
		case $yn in
			yes|Yes|YES|y|Y)
				return 0  ;;
			no|No|n|N|NO)
				return 1  ;;
			*) 
				ec lightRed "Please enter y or n." 
		esac
	done    
#usage:
#if yesNo 'do you want to continue?' ; then
#    echo 'You choose to continue'
#else
#    echo 'You choose not to continue'
#fi
}

ec() { # `echo` in a color function
	# Usage: ec $color "text"
	ecolor=${!1} #get the color
	shift #  $1 is removed here
	echo -e ${ecolor}"${*}"${nocolor} #echo the rest
}


main() {

	mainloop=0
	while [ $mainloop == 0 ] ; do
		clear
		# menu
		echo "$scriptname
version: $version
Started at $starttime
"
		ec yellow: "Choose your Destiny:"
		ec white "		1) Single cpanel account
		2) List of cpanel users from /root/userlist.txt
		3) List of domains from /root/domainlist.txt
		4) All users

		9) Final Sync

		a) Homedir Sync only
		b) Mysql Sync only
		c) Pgsql Sync only
		d) Version Matching only
		e) Regenerate hostsfile.txt for all users
		f) Regenerate hostsfile.txt from /root/userlist.txt
		g) Remove lwHostsCheck.php files
		0) Quit
		"
		[[ ! "${STY}" ]] && ec lightRed "Warning! You are not in a screen session!" 
		echo -n "Input Choice: "
		read choice
		case $choice in 
			1) 
				synctype="single"
				synctype_logic
				mainloop=1 ;;
			2) 
				synctype="list"
				synctype_logic
				mainloop=1 ;;
			3)
				synctype="domainlist"
				synctype_logic
				mainloop=1 ;;
			4) 	
				synctype="all"
				synctype_logic
				mainloop=1 ;;
			9) 	
				synctype="final"
				synctype_logic
				mainloop=1 ;;
			a)	
				synctype="homedir"
				synctype_logic
				mainloop=1
				;;
			b)	
				synctype="mysql"
				synctype_logic
				mainloop=1
				;;
			c)	
				synctype="pgsql"
				synctype_logic
				mainloop=1
				;;
			d)
				synctype="versionmatching"
				synctype_logic
				mainloop=1
				;;
			e)
				#nothing is needed from external server for this. 
				synctype="hostsgenonly"
				userlist=`/bin/ls -A /var/cpanel/users`
				domainlist=$(for user in $userlist; do
					grep ^DNS.*= /var/cpanel/users/$user | cut -d= -f2
				done)
				echo $domainlist > $dir/domainlist.txt
				> $hostsfile_alt
				for user in $userlist; do 
					hosts_file $user
				done
				hostsfile_gen
				mainloop=1
				;;
			f)
				synctype="hostsgenonly"
				userlist=`cat /root/userlist.txt`
				domainlist=$(for user in $userlist; do
					grep ^DNS.*= /var/cpanel/users/$user | cut -d= -f2
				done)
				echo $domainlist > $dir/domainlist.txt
				> $hostsfile_alt
				for user in $userlist; do 
					hosts_file $user
				done
				hostsfile_gen
				mainloop=1
				;;
			g) 
				remove_lwHostsCheck
				mainloop=1
				;;
			0) 
				echo "Bye..."; exitcleanup ; exit 10 ;;
			*)  
			   ec lightRed "Not a valid choice. Try again!"; sleep 3; clear
		esac	
	done

}

synctype_logic() { #yeah, its a mess
	# all types
	oldmigrationcheck #also gets ips 
	ec yellow "Transferring some config files over from old server to $dir"
	# we need /etc/userdomains for the domainlist conversion, might as well get things now.
	rsync -R $rsyncargs -e "ssh $sshargs" $ip:"`echo $filelist`" $dir/ 2> /dev/null
	if ! [[ "$synctype" == "versionmatching" ]] ; then
		getuserlist
	fi
	getversions
	### initial syncs ###
	if [[ "$synctype" =~ "single" || "$synctype" =~ "list" || "$synctype" =~ "domainlist" || "$synctype" =~ "all" ]] ;then
		lower_ttls
		initialsync_main
	### final sync stuff ##		
	elif [ "$synctype" == "final" ]; then
		finalsync_main
	### other sync stuff ###
	elif [ "$synctype" == "homedir" ]; then
		ec yellow "Running homedir only sync."
		user_count=1
		for user in $userlist; do
			user_total=`echo $userlist |wc -w`
			progress="$user_count/$user_total | $user:"
			rsync_homedir #needs to run in a userlist loop
			user_count=$(( $user_count+1 ))
		done
	elif [ "$synctype" == "mysql" ]; then
		ec yellow "Running mysql only sync."
		mysql_dbsync
		noncp_mysql_dbsync
	elif [ "$synctype" == "pgsql" ]; then
		ec yellow "Running pgsql only sync."
		pgsql_dbsync
	elif [ "$synctype" == "versionmatching" ]; then
		do_installs=1
		upcp_check
		mysqlversion
		phpversion
		postgres_install_check
		installs
	fi
	#mailperm
	echo "Fixing mail permissions..."
	screen -S mailperm -d -m /scripts/mailperm &
	#fix quotas
	echo "Fixing cpanel quotas..."
	screen -S fixquotas -d -m /scripts/fixquotas &
	exitcleanup
}


initialsync_main() {

	#cpanel is more picky about not restoring subdomains in 11.44, set this up.
	sed -i 's/\(allowparkhostnamedomainsubdomains=\)0/\11/' /var/cpanel/cpanel.config
	sed -i 's/\(allowremotedomains=\)0/\11/' /var/cpanel/cpanel.config
	/usr/local/cpanel/whostmgr/bin/whostmgr2 –updatetweaksettings 
	
	#get versions/version matching
	if  [ "$synctype" == "list" ] || [ "$synctype" == "domainlist" ] || [ "$synctype" == "all" ];then # no single
		ec lightGreen "Here is what we found to install:"
		for prog in $proglist; do 
			[ "${!prog}" ] && echo "$prog"
		done
		# version matching run here.
		if yesNo "Run version matching?"; then
			do_installs=1
			upcp_check
			mysqlversion
			phpversion
			postgres_install_check
			modsec_rules_check
		fi
		rsync $rsyncargs -e "ssh $sshargs" $ip:"/var/cpanel/packages /var/cpanel/features" /var/cpanel/
		dedipcheck
	fi
	# back to syncing data
	noncp_mysql_dbsync
	ec lightCyan "Ready to do the initial sync! Please press enter to continue."
	read
	[ $do_installs ] && installs
	
	package_accounts # runs rsync_homedir, hosts_file in tandem
	
	 # get non cpanel dbs

	# final checks!
	[ "$mysqlupcheck" = "1" ] && ec yellow "Mysql was updated, remember to run EA!" && read
	echo

	# exim ports
	remote_exim_ports=`grep ^daemon_smtp_ports $dir/etc/exim.conf`
	local_exim_ports=`grep ^daemon_smtp_ports /etc/exim.conf`
	if [ "$remote_exim_ports" != "$local_exim_ports" ]; then
		ec lightRed "Alternate exim ports found!"
		echo $remote_exim_ports
		ec yellow "Please set them up in WHM > Service Manager"
		ec yellow "Press enter to continue."
		read
	fi

	if [ -f $dir/did_not_restore.txt ]; then
		ec lightRed "Found users that did not restore."
		cat $dir/did_not_restore.txt
		ec yellow "Press enter to continue."
		read
	fi

	hostsfile_gen

}

rsyncupdate() {
	if yesNo 'Use --update flag for final rsync? If files were updated on the destination server they wont be overwritten'; then
 		rsync_update="--update"
	fi
}

finalsync_main() {
	if yesNo "Stop services for final sync?";then
		stopservices=1
		 if yesNo 'Restart services after sync?'; then
			restartservices=1
		fi
	fi
	#rsyncupdate
	rsyncupdate

	# named 
	if yesNo 'Copy zone files back to old server? Will backup current directory on old server.' ;then 
		if [ "$domainlist" ]; then
			copydns=1
		else
			ec red "Warning: Domainlist not found. cannot copy dns back to old server!"
		fi
	fi
	#pull the trigger...
	noncp_mysql_dbsync
	ec lightBlue "Press enter to begin final sync..."
	read

	#run this now to save time later... short reduction of downtime.
	perlYaml

	if [ "$stopservices" ]; then
	  ec yellow "Stopping Services..." 
	  ssh $sshargs $ip "[ -s /etc/init.d/chkservd ] && /etc/init.d/chkservd stop"
	  ssh $sshargs $ip  "/usr/local/cpanel/bin/tailwatchd --disable=Cpanel::TailWatch::ChkServd"
	  ssh $sshargs $ip "/etc/init.d/httpd stop"
	  ssh $sshargs $ip "/etc/init.d/exim stop"
	  ssh $sshargs $ip "/etc/init.d/cpanel stop"
	else
	 ec yellow "Not stopping services." 
	fi

	# actual data copying functions:
	mysql_dbsync
	pgsql_dbsync
	
	user_count=1
	user_total=`echo $userlist |wc -w`
	for user in $userlist; do
		progress="$user_count/$user_total | $user:"
		rsync_homedir #needs to run in a userlist loop
		user_count=$(( $user_count+1 ))
	done
	mailman_copy

	# copy dns back to old server
	if [ "$copydns" ]; then 
		ec yellow "Backing up /var/named to $remote_tempdir on remote server..."
	 	ssh $sshargs $ip "rsync -avqR /var/named $remote_tempdir/"
	 	ec yellow "Copying zone files back to old server..."
	 	for domain in $domainlist; do 
	 		if [ -f "/var/named/${domain}.db" ]; then
 				sed -i -e 's/^\$TTL.*/$TTL 300/g' -e 's/[0-9]\{10\}/'`date +%Y%m%d%H`'/g' /var/named/$domain.db
	 			rsync $rsyncargs -e "ssh $sshargs" /var/named/$domain.db $ip:/var/named/
	 		fi
	 	done
	 	ssh $sshargs $ip "service named restart; rndc reload"
	 	#for the one time i encountered NSD
	 	nsdcheck=`ssh $sshargs $ip "ps aux |grep nsd |grep -v grep"`
	 	if [ "$nsdcheck" ]; then
	  		echo "Nsd found, reloading" 
	  		ssh $sshargs $ip "nsdc rebuild"
			ssh $sshargs $ip "nsdc reload"
	 	fi
	fi

	#restart services
	if [ "$restartservices" ]; then
		ec yellow "Restarting Services..." 
		ssh $sshargs $ip "[ -s /etc/init.d/chkservd ] && /etc/init.d/chkservd start"
		ssh $sshargs $ip  "/usr/local/cpanel/bin/tailwatchd --enable=Cpanel::TailWatch::ChkServd"
		ssh $sshargs $ip "/etc/init.d/httpd start"
		ssh $sshargs $ip "/etc/init.d/exim start"
		ssh $sshargs $ip "/etc/init.d/cpanel start"
	else
	 ec yellow "Skipping restart of services." 
	fi
	#give cpanel time to spam to screen
	sleep 10

	[ "$stopservices" ] || [ "$restartservices" ] || [ "$copydns" ] && ec yellow "== Actions Taken =="
	[ "$stopservices" ] && ec white "Stopped services."
	[ "$restartservices" ] && ec white "Restarted services."
	[ "$copydns" ] && ec white "Copied zone files back to old server."

	remove_lwHostsCheck
}

remove_lwHostsCheck() {
	if yesNo "Remove lwHostsCheck.php files?"; then
		if [ "$userlist" ]; then
			for user in $userlist; do 
				userhome_local=`grep ^$user: /etc/passwd | tail -n1 |cut -d: -f6`
				docroots=`grep DocumentRoot /usr/local/apache/conf/httpd.conf |grep $userhome_local| awk '{print $2}'`
			done
		else
			docroots=`grep DocumentRoot /usr/local/apache/conf/httpd.conf | grep -v /usr/local/apache/htdocs | sort -u | awk '{print $2}' `
		fi
		for docroot in $docroots; do 
			if [ -f "$docroot/lwHostsCheck.php" ]; then
				rm $docroot/lwHostsCheck.php
			fi
		done
	fi
}

oldmigrationcheck() { #always run, to get old ip/port if needed.
	ec white "Checking for previous migration..."
	# if olddir is defined, there was a previous migration, or at least, the script ran once before.
	if [ "$oldip" ]; then
		ec yellow "Files from old migration found, dated $oldstarttime !"
		[ "$oldip" ] && ec yellow "Old IP: $oldip"
		[ "$oldport" ] && ec yellow "Old Port: $oldport"
		[ "$oldusercount" ] && ec yellow "Old User count: $oldusercount"
		[ "$someoldusers" ] && ec yellow "Some old users (not all): $someoldusers"
		if yesNo "Is $oldip the server you want? " ;then
		    echo "Ok, continuing with $oldip" 
		    ip=$oldip
		    echo $ip > $dir/ip.txt
		    getport
		else
		    getip 
		fi
	else
		echo "No previous migration found." #maybe list /home/temp/pullsync dirs?
		getip
	fi
}

getip() {
	echo
	echo -n 'Source IP: '; 
	read ip 
	echo $ip > $dir/ip.txt
	getport
	
}

getport() {
	if [ "$oldport" ]; then
		if yesNo "Use old Ssh port $oldport?"; then
			port=$oldport
		fi
	fi
	[ -z "$port" ] && echo -n "SSH Port [22]: " && read port
	if [ -z $port ]; then
		echo "No port given, assuming 22"
		port=22
	fi
	echo $port > $dir/port.txt
	sshargs="$sshargs -p$port"
	sshkeygen
}

whitelist_source() {
	#detect firewall software?
	ec yellow "Whitelisting source IP in firewall..."
	if [ `which csf` ] ; then
		ec yellow "CSF found"
		csf -a $ip
	elif [ `which apf` ]; then
		ec yellow "APF Found"
		apf -a $ip
		apf -r
	fi
}

sshkeygen() { 
	mkdir -p /root/.ssh
	# we're just going to ask for the password everytime, remove the key if it it was cancelled midway for some reason though.
	if [ -f /root/.ssh/pullsync.pub ]; then 
		rm -rf /root/.ssh/pullsync*
	fi
	ec yellow "Generating SSH key /root/.ssh/pullsync ..." 
	ssh-keygen -q -N "" -t rsa -f /root/.ssh/pullsync -C "pullsync"
	whitelist_source
	ec yellow "Copying Key to remote server..." 	
	# since we are using our own sshkey, we don't need to worry about overwriting others. we can just delete it when done. Cent4 is missing ssh-copy-id, fall back to old method if not detected.
	if which ssh-copy-id; then
		ssh-copy-id -i ~/.ssh/pullsync.pub " -p $port $ip"
	else
		cat ~/.ssh/pullsync.pub | ssh $sshargs $ip "mkdir -p ~/.ssh; cat >> ~/.ssh/authorized_keys"
	fi
	#append our key pullsync.pub to sshargs
	sshargs="$sshargs -i /root/.ssh/pullsync"
	# now test the ssh connection 
	ec yellow "Testing ssh connection..."
	if ! ssh $sshargs $ip "true" ; then
		ec lightRed "Error: Ssh connection to $ip failed."
		ec yellow "May need to change 'PermitRootLogin no' to 'PermitRootLogin without-password' in sshd_config on remote server."
		ec lightCyan "Add pubkey from ~/.ssh/pullsync.pub below to remote server, and press enter to retry"
		cat ~/.ssh/pullsync.pub
		read
		#fail here
		if ! ssh $sshargs $ip "true"; then
		  ec lightRed "Error: Ssh connection to $ip failed, please check connection before retrying!" |tee -a $dir/error.log
		  exitcleanup
		  # quit
		  exit 3
		fi
	fi
	ec lightGreen "Ssh connection to $ip succeded!"
	# command to remove the 'stdin: is not a tty' error that is annoying. append a bit to the top of /root/.bashrc on the source server. don't add more entries if it exists. '[ -z $PS1 ] && return'
	stdin_cmd="if ! grep -q '\[ -z "'$PS1'" \] && return' /root/.bashrc; then sed -i '1s/^/[ -z "'$PS1'" ] \&\& return\n/' /root/.bashrc ;fi"	
	ssh $sshargs $ip "$stdin_cmd"
	sleep 5
	#disable firewall app on hostgator servers, it denies rapid remote connections 
	ssh $sshargs $ip "if which firewall; then firewall stop; fi"
	ssh $sshargs $ip "mkdir -p $remote_tempdir/"

}

getuserlist() { # get user list for different sync types

	# a list of users
	if [ "$synctype" == "list" ];then 
		# list is stored locally
		if [ -f "$userlistfile" ];then
			userlist=`cat $userlistfile`
			for user in $userlist; do
					rsync -R $rsyncargs -e "ssh $sshargs" $ip:/var/cpanel/users/$user $dir/
			done
			getdomainlist
		else
			ec lightRed "Did not find $userlistfile!"
			exitcleanup
			exit 4
		fi
	# a list of domains
	elif  [ "$synctype" == "domainlist" ] ; then 
		if [ -f "$domainlistfile" ]; then
			#lowercase the domainlist
			sed -i -e 's/\(.*\)/\L\1/'  $domainlistfile
			cp -rp $domainlistfile $dir/
			#get users from a domainlist, $dir/etc/userdomains needs to exist already
			userlist=$(for domain in `cat $domainlistfile`; do 
		  		grep ^$domain $dir/etc/userdomains |cut -d\  -f2 
			done |sort |uniq )
			for user in $userlist; do
					rsync -R $rsyncargs -e "ssh $sshargs" $ip:/var/cpanel/users/$user $dir/
			done
			#generate domain list in $dir ( each domain in an acount may not have been given )
			getdomainlist
		else
			ec lightRed "Did not find /root/domainlist.txt!"
			exitcleanup
			exit 5
		fi
	#all users
	elif [ "$synctype" == "all" ] ; then 
		rsync -R $rsyncargs -e "ssh $sshargs" $ip:/var/cpanel/users $dir/
		userlist=`/bin/ls -A $dir/var/cpanel/users/ | egrep -v "^HASH" | egrep -v "^${badusers}|HASH*$"`
		getdomainlist
	# single user
	elif [ "$synctype" == "single" ] ; then 
		rsync -R $rsyncargs -e "ssh $sshargs" $ip:/var/cpanel/users/$userlist $dir/
		ec yellow "What is the user you would like to migrate?"
		read userlist
		if ! [ -f "$dir/var/cpanel/users/$userlist" ];then 
			ec lightRed "User not found!"
			exitcleanup
			exit 6 
		fi
		getdomainlist
		if yesNo "Restore to dedicated ip?"; then
			single_dedip="yes"
		else
			single_dedip="no"
		fi

	#elif [ "$synctype" == "final" ] ; then
	else #final and other syncs
		if [ -f $olddir/userlist.txt ] && [ $oldusercount -gt 0 ]; then
			ec lightGreen "Previous sync from ip $oldip at $oldstarttime found in $olddir/userlist.txt."
			ec yellow "Count of old users: $oldusercount"
			ec yellow "First 6 old users: $someoldusers"
			if yesNo "Are these users correct?"; then
				userlist=`cat $olddir/userlist.txt`
				rsync -R $rsyncargs -e "ssh $sshargs" $ip:/var/cpanel/users/$user $dir/
			fi
		fi
		if [ -f /root/userlist.txt ] ;then 
			userlist_count=`cat /root/userlist.txt |wc -w`
		else
			userlist_count=0
		fi
		if [ $userlist_count -gt 0 ] && [ ! "$userlist" ]; then
			ec lightGreen "Userlist found in /root/userlist.txt."
			userlist_some=`cat /root/userlist.txt | tr '\n' ' '| cut -d' ' -f1-6`
			ec yellow "Counted $userlist_count users."
			ec yellow "First 6 users found: $userlist_some"
			if yesNo "Are these users correct?"; then
				userlist=`cat /root/userlist.txt`
				rsync -R $rsyncargs -e "ssh $sshargs" $ip:/var/cpanel/users/$user $dir/
			fi
		fi
		if [ ! "$userlist" ]; then
			# no previous sync found, ask for all users?
			if yesNo "No userlist found, final sync all users?";then 
				rsync -R $rsyncargs -e "ssh $sshargs" $ip:/var/cpanel/users $dir/
				userlist=`/bin/ls -A $dir/var/cpanel/users/ | egrep -v "^${badusers}$" `
			else
				ec lightRed "Error: No userlist was defined, quitting."
				exitcleanup
				exit 1
			fi
		fi
		getdomainlist
	fi 
	echo $userlist > "$dir/userlist.txt"
	echo $userlist > /root/userlist.txt
	#check for conflicts 
	ec yellow "Checking for account conflicts..." 
	for user in $userlist ; do\
		#write erronious users to a file
		if [ -f "/var/cpanel/users/$user" ] && [[ "$synctype" =~ "single" || "$synctype" =~ "list" || "$synctype" =~ "domainlist" || "$synctype" =~ "all" ]]; then # if the user exists for an initial sync, fail out.
			ec lightRed  "Error: $user already exists on this server" | tee -a $dir/error.log
			echo $user >> $dir/conflicts.txt
			error_encountered=1
		elif [ ! -f "/var/cpanel/users/$user" ] && [ "$synctype" == "final" ]; then #if the user does not exist for a final sync, exit
			ec lightRed "Error: $user was selected for a final sync, but does not exist on this server!"  |tee -a $dir/error.log
			echo $user >> $dir/conflicts.txt
			error_encountered=1
		elif [ ! -f "/var/cpanel/users/$user" ] && [[ "$synctype" =~ "homedir" || "$synctype" =~ "mysql" || "$synctype" =~ "pgsql" ]]; then
			ec lightRed "Error: User $user does not exist on this server! " |tee -a $dir/error.log
			echo $user >> $dir/conflicts.txt
			error_encountered=1
		fi
	done
	if [ "$error_encountered" ]; then
		ec red "User conflicts found, put conflicting users in $dir/conflicts.txt. Resolve conflicts and re-run sync!" |tee -a $dir/error.log
		exitcleanup
		exit 7
	fi

}

getdomainlist() { #called as needed by getuserlist
	# get a domain list (for 'userlist', 'final', 'all')	

	domainlist=$(for user in $userlist; do
		grep ^DNS.*= $dir/var/cpanel/users/$user | cut -d= -f2
	done)
	echo $domainlist > $dir/domainlist.txt
}

dedipcheck() { # check for available/needed dedicated ip amount
	ec yellow "Checking for dedicated IPs..."
	source_ip_usage=`ip_usage $dir/`
	ip_count=`cat /etc/ips| wc -w` 
	ip_usage=`ip_usage /` # calling ip_usage function on /
	ips_free=$(( $ip_count-$ip_usage ))
	ec yellow "
	Dedicated ips in use for selected users on remote server: $source_ip_usage 
	Dedicated Ips in use on this Server:$ip_usage
	Total dedicated IPs on this server: $ip_count
	There are $ips_free available IPs on this server." 
	if [[ $source_ip_usage -le $ips_free ]];then
	  ec lightGreen "There seems to be enough IPs on this server for the migration."
	else
	  ec lightRed "This server does not seem to have enough dedicated IPs." 
	fi
	if yesNo "Restore accounts to dedicated Ips?
no  = Restore accounts to the Main Shared Ip." ;then
	  ec lightGreen "Restoring accounts to dedicated IPs."
	  ded_ip_check=1
	else
	  ec lightGreen "Restoring accounts to the main shared Ip."
	  ded_ip_check=0
	fi
}

ip_usage() {
	ipcheckpath=$1
	main_ip=`cat ${ipcheckpath}etc/wwwacct.conf|grep ADDR|cut -d ' ' -f2`
	dedicated_ips=""
	if [ "$ipcheckpath" = "/" ];then
		ipcheck_userlist=`/bin/ls -A /var/cpanel/users/` # checking for free ips on this server
	else
		ipcheck_userlist=$userlist #checking for ips in use on remote server (from users selected to migrate)
	fi
	for user in $ipcheck_userlist ; do
		dedicated_ips="$dedicated_ips `grep ^IP= ${ipcheckpath}var/cpanel/users/$user |grep -v $main_ip | cut -d= -f2`"
	done 
	dedicated_ip_count=`echo $dedicated_ips |tr ' ' '\n' |sort |uniq |wc -w`
	echo $dedicated_ip_count
}

lower_ttls() { # should have a domainlist at this point, from getuserlist()
	ec yellow "Lowering TTLs for selected users..."
	# back up /var/named on remote server!
	ssh $sshargs $ip "rsync -aqH /var/named $remote_tempdir/"
	# we have /var/named from source server, run our seds locally to make things easier, then copy them back to original server.
	if [ -f $dir/domainlist.txt ]; then
		domainlist=`cat $dir/domainlist.txt`
		mkdir -p $dir/var/named
		for domain in $domainlist; do
			y=$(ssh ${sshargs} ${ip} "ls /var/named/$domain.db")
			if [ "$y" != "" ]; then
				rsync $rsyncargs -e "ssh $sshargs" $ip:/var/named/$domain.db $dir/var/named/
			fi
			if [ -f $dir/var/named/$domain.db ]; then
				sed -i -e 's/^\$TTL.*/\$TTL 300/g' $dir/var/named/$domain.db
				sed -i -e 's/[0-9]{10}/'`date +%Y%m%d%H`'/g' $dir/var/named/$domain.db
				#jwarrens A record reducer:
				sed -i -e 's/^\([\w.\-]+[^\S\n]+\)[0-9]+\([^\S\n]+IN[^\S\n]+A[^\S\n]+[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+.*$\)/\1\Q300\E\2/g' $dir/var/named/$domain.db
				rsync $rsyncargs -e "ssh $sshargs" $dir/var/named/$domain.db $ip:/var/named/
			else
				ec red "Warning: Domain $domain not found while lowering TTLs, checked for $dir/var/named/$domain.db!" |tee -a $dir/error.log
			fi
		done
	else
		ec lightRed "Error: Domainlist not found $dir/domainlist.txt!" |tee -a $dir/error.log
	fi
	# reload rndc on remote server to lower ttls
	ssh $sshargs $ip "rndc reload ; [ `which nsdc 2>/dev/null` ] && nsdc rebuild && nsdc reload"
}

# ask if version matching will be needed. maybe check for version on remote server first

# check versions of local/remote software
getversions() {
	ec yellow "Running version detection"
	# store functions, couldn't find a better way to do this... 
	phpcmd='php -v |head -n1 | awk '\''{print $2}'\'' '
	mysqlcmd='mysqladmin ver |grep '\''^Server version'\'' |awk '\''{print $3}'\'' |cut -d. -f1-2 '
	httpcmd='/usr/local/apache/bin/httpd -v |grep version | awk '\''{print $3}'\'' |cut -d/ -f2'
	phphandlercmd='/usr/local/cpanel/bin/rebuild_phpconf --current |grep PHP5 |cut -d" " -f3'
	modsec_cmd='rpm -qa "*modsec*" '
	os_cmd='cat /etc/redhat-release'
	echo "Versions on local server `hostname`, $cpanel_main_ip:" |tee -a $dir/versionsLocal.txt
	# run the commands, load into variables
	localhttp=`eval $httpcmd`
	localmysql=`eval $mysqlcmd`
	localphp=` eval $phpcmd`
	localphphandler=` eval $phphandlercmd`
	localcpanel=`cat /usr/local/cpanel/version`
	localmodsec=`eval $modsec_cmd`
	local_os=`eval $os_cmd`
	#display:
	echo "	Local Http      : $localhttp
	Local Php       : $localphp
	Local Phphandler: $localphphandler
	Local Mysql     : $localmysql
	Local Cpanel    : $localcpanel
	Local Modsec    : $localmodsec
	Local OS        : $local_os
	" | tee -a $dir/versionsLocal.txt

	#for a remote server:
	remotehostname=`ssh $sshargs $ip "hostname"`
	echo "Versions on $remotehostname $ip:" |tee -a $dir/versionsRemote.txt
	remotehttp=`ssh $sshargs $ip "eval $httpcmd"`
	remotemysql=`ssh $sshargs $ip "eval $mysqlcmd"`
	remotephp=`ssh $sshargs $ip "eval $phpcmd"`
	remotephphandler=`ssh $sshargs $ip "eval $phphandlercmd"`
	remotecpanel=`cat $dir/usr/local/cpanel/version`
	remotemodsec=`ssh $sshargs $ip "eval $modsec_cmd"`
	remote_os=`ssh $sshargs $ip "eval $os_cmd"`
	echo "	Remote Http      : $remotehttp
	Remote Php       : $remotephp
	Remote Phphandler: $remotephphandler
	Remote Mysql     : $remotemysql
	Remote Cpanel    : $remotecpanel
	Remote Modsec    : $remotemodsec
	Remote OS        : $remote_os
	" | tee -a $dir/versionsRemote.txt
	ec yellow "Please press enter to continue."
	read

	ec yellow "Checking for 3rd party apps..." 
	# Check for stuff we can install
	ffmpeg=`ssh $sshargs $ip "which ffmpeg"`
	imagick=`ssh $sshargs $ip "which convert"`
	memcache=`ssh $sshargs $ip "ps aux | grep -e 'memcache' | grep -v grep | tail -n1 "`
	java=`ssh $sshargs $ip "which java 2>1 /dev/null"`
	if ssh $sshargs $ip "/etc/init.d/postgresql status" ; then
		postgres="found"
	fi
	#other stuff , probably a better way to do this
	xcache=`ssh $sshargs $ip "ps aux | grep -e 'xcache' | grep -v grep | tail -n1"`
	eaccel=`ssh $sshargs $ip "ps aux | grep -e 'eaccelerator' | grep -v grep |tail -n1"`
	nginx=`ssh $sshargs $ip "ps aux | grep  -e 'nginx' |grep -v grep| tail -n1"`
	lsws=`ssh $sshargs $ip "ps aux | grep  -e 'lsws' | grep -v grep | tail -n1"`	
	if [ "${xcachefound}${eaccelfound}${nginxfound}${lswsfound}" ]; then
		ec yellow '3rd party stuff found on the old server!'  
		[ "$xcachefound" ] && echo "Xcache: $xcachefound" 
		[ "$eaccelfound" ] && echo "Eaccelerator: $eaccelfound" 
		[ "$nginxfound" ] && echo "Nginx: $nginxfound" 
		[ "$lswsfound" ] && echo "Litespeed: $lswsfound"
		ec yellow 'It is up to you to install these. Press enter to continue.'
		read
	fi

	# Dns check
	if [ "$domainlist" ]; then #skip if no domainlist (only versionmatching)
		ec yellow "Checking Current dns..." 
		if [ -f $olddir/dns.txt ]; then
			echo "Found $olddir/dns.txt" 
			cp $olddir/dns.txt $dir/
			cat $dir/dns.txt | sort -n +3 -2 | more
		else
		  	for domain in $domainlist; do 
		  		echo $domain\ `dig @8.8.8.8 NS +short $domain |sed 's/\.$//g'`\ `dig @8.8.8.8 +short $domain` ;
		  	done | grep -v \ \ | column -t > $dir/dns.txt
		  cat $dir/dns.txt | sort -n +3 -2 | more
		fi
		ec yellow "Press enter to continue."
		read
	fi

	# nameserver check 
	if [ ! "$synctype" = "single" ] ;then 
		ec yellow "Source server nameserver settings:"
		source_nameservers=`grep ^NS[\ 0-9] $dir/etc/wwwacct.conf`
		echo "$source_nameservers"
		ec yellow "Local nameserver settings:"
		local_nameservers=`grep ^NS[\ 0-9] /etc/wwwacct.conf`
		echo "$local_nameservers"
		if [ "$source_nameservers" = "$local_nameservers" ]; then 
			if yesNo "Set old nameservers to this server?"; then
				sed -i -e '/^NS[\ 0-9]/d' /etc/wwwacct.conf
				grep ^NS[\ 0-9]  $dir/etc/wwwacct.conf >> /etc/wwwacct.conf
			fi
		else
			ec yellow "nameservers match"
		fi
	fi

	# SSL cert checking.
	ec yellow "Checking for SSL Certificates in apache conf..." 
	if grep -q SSLCertificateFile $dir/usr/local/apache/conf/httpd.conf ; then
		ec yellow "SSL Certificates detected." 
		for domain in $domainlist; do 		
			# sed -n "/VirtualHost.*\:443/,/\/Virtualhost/ { /ServerName.*rebcky.com/,/\/VirtualHost/  { s/.*SSLCertificateFile \(.*.crt\)/\1/p } }" /home/temp/pullsync/usr/local/apache/conf/httpd.conf
			for crt in `grep SSLCertificateFile.*/$domain.crt $dir/usr/local/apache/conf/httpd.conf |awk '{print $2}'`; do
				echo $dir/$crt; openssl x509 -noout -in $crt -issuer  -subject  -dates 
				ec yellow "Press enter to continue."
				read
		 	done
		 done
	else
		echo "No SSL Certificates found in httpd.conf." 
	fi

	# check for dnsclustering
	ec yellow "Checking for DNS clustering..." 
	if [ -f $dir/var/cpanel/useclusteringdns ]; then
		ec yellow 'Remote DNS Clustering found! Press enter to continue.' 
	 	read 
	fi
	if [ -f /var/cpanel/useclusteringdns ]; then
		 ec lightRed "DNS cluster on the local server is detected, you shouldn't continue since restoring accounts has the potential to automatically update DNS for them in the cluster. Probably will be better to remove or disable clustering before continuing." 
		echo 'Press enter to continue.' 
	 	read 
	else
	 	ec yellow "No Local DNS clustering found."
	fi

	# space check
	ec yellow "Comparing free space on /home to used space of old server."
	ssh $sshargs $ip "df /home/ | tail -n1" > $dir/df.txt # Filesystem            Size  Used Avail Use% Mounted on
	remote_used_space=`cat $dir/df.txt | awk '{print $3} '` #convert to gb? since we could potentially be shown TB or other.
	local_free_space=`df /home |tail -n1 | awk '{print $4}'`
	ec white "Remote used space: $(( $remote_used_space / 1024 / 1024 )) Gb "
	ec white "Local free space : $(( $local_free_space / 1024 / 1024 )) Gb "
	if [[ $remote_used_space -gt $local_free_space ]] ; then 
		ec lightRed 'There does not appear to be enough free space on this server when comparing the home partitions! '
		ec yellow "Press enter to continue." 
		read
	fi

	# cpbackup check
	if [ ! "$synctype" = "single" ]; then
		backup_acct=`grep ^BACKUPACCTS /etc/cpbackup.conf | awk '{print $2}' `
		backup_enable=`grep ^BACKUPENABLE /etc/cpbackup.conf | awk '{print $2}'`
		if [ $backup_enable = "yes" ] && [ $backup_acct = "yes" ]; then
			ec yellow "Cpanel backups are enabled."
		else
			ec yellow "Cpanel backups are disabled." 
			if yesNo "Do you want to enable cpanel backups?"; then
			    sed -i.syncbak -e 's/^\(BACKUPACCTS\).*/\1 yes/g' -e 's/^\(BACKUPENABLE\).*/\1 yes/g' /etc/cpbackup.conf
			fi
		fi
	fi

	# cloudlinux
	if echo $remote_os | grep -q -i cloud ; then
		ec lightRed "Cloud linux detected on remote server. Press enter to continue."
		read
	fi

	#mysql open_files_limit
	if [ ! "$synctype" = "single" ] ;then 
		if ! grep -q ^open_files_limit /etc/my.cnf ;then
			echo "adding open_files_limit = 50000 to my.cnf"
			sed -i 's/\(\[mysqld\]\)/\1\nopen_files_limit = 50000/' /etc/my.cnf
			service mysql restart
		else
			echo "found open_files_limit in my.cnf,. skipping"
		fi
	fi

}

installs() {
	ec yellow "Downloading lwbake and plbake..."
	wget -q -O /scripts/lwbake http://layer3.liquidweb.com/scripts/lwbake
	chmod 700 /scripts/lwbake
	wget -q -O /scripts/plbake http://layer3.liquidweb.com/scripts/plBake/plBake
	chmod 700 /scripts/plbake


	#upcp
	if [ $upcp ]; then
		ec yellow "Running Upcp..."
		"/scripts/upcp"
	fi
	#java
	if [ "$java" ];then
		ec yellow "Installing Java..."
		screen -S java -d -m /scripts/plbake java
	fi
	#postgres
	if [ "$postgres" ]; then
		if ! /etc/init.d/postgresql status ; then
		 	ec yellow "Installing Postgresql..."
			#use expect to install since it asks for input
			cp -rp /var/lib/pgsql{,.bak.$starttime}
		 	expect -c "spawn /scripts/installpostgres
			expect \"Are you sure you wish to proceed? \"
			send \"yes\r\"
			expect eof"
			#rsync $rsyncargs -e "ssh $sshargs" $ip:/var/lib/pgsql/data/pg_hba.conf /var/lib/pgsql/data/
			/etc/init.d/postgresql stop
			mv /var/lib/pgsql{,.bak}
			/etc/init.d/postgresql initdb
			sed 's/\(local.*all.*all.*\)ident/\1trust/' /var/lib/pgsql/data/pg_hba.conf
			/scripts/restartsrv_postgres
		else
			ec yellow "Detected postgres is installed already"
		fi
	fi

	#mysql
	if [ "$mysqlup" ]; then
		ec yellow "Reinstalling mysql..."
		sed -i.bak /mysql-version/d /var/cpanel/cpanel.config
		echo mysql-version=$newmysqlver >> /var/cpanel/cpanel.config
		cp -rp /etc/my.cnf{,.bak.$starttime}
		if [ $newmysqlver > 5 ]; then
			sed -i -e /safe-show-database/d -e /skip-locking/d /etc/my.cnf
		fi
		cp -rp /var/lib/mysql{,.bak.$starttime}
		if [ $localcpanel > 11.36.0 ]; then
			/usr/local/cpanel/scripts/check_cpanel_rpms --targets=MySQL50,MySQL51,MySQL55,MySQL56 --fix
		else
			/scripts/mysqlup --force
		fi
		ec yellow "Verifying mysql is started..."
		if service mysql status ;then
			echo "Mysql update completed, EA will need to be ran."
			mysqlupcheck=1
		else
			ec lightRed "Mysql failed to start, ensure it starts before restoring accounts!"
			ec yellow "Press enter to continue..."
			read
		fi
	fi
	#ea, run if mysql was updated
	if [ "$ea" ] || [ "$mysqlupcheck" ]; then
		ec yellow "Running EA..."
		#we should have ea config already from php version
		#want to enable the symlink protection regardless. "SymlinkProtection": 1
		if grep -q '"SymlinkProtection":' /var/cpanel/easy/apache/profile/_main.yaml ;then
			sed -i 's/\("SymlinkProtection":\).*/\1 1/g' /var/cpanel/easy/apache/profile/_main.yaml
		else
			#insert symlink protection after optmods line. 
			sed -i '/"optmods":/a \ \ \ \ "SymlinkProtection":\ 1' /var/cpanel/easy/apache/profile/_main.yaml
		fi

		/scripts/easyapache --build
	 	unset mysqlupcheck
	fi
	phpextras
	# ffmpeg
	if [ "$ffmpeg" ] ; then
		ec yellow "Installing ffmpeg..." 
		# fork it off into a screen since it takes a while
 		screen -S ffmpeg -d -m /scripts/lwbake ffmpeg-php 
	fi
	#imagick
	if [ "$imagick" ] ; then
		echo "Installing imagemagick..." 
		/scripts/lwbake imagemagick
		/scripts/lwbake imagick
		/scripts/lwbake magickwand
	fi
	#memcache
	if [ "$memcache" ]; then
		ec yellow "Installing memcache..." 
		wget -O /scripts/confmemcached.pl http://layer3.liquidweb.com/scripts/confMemcached/confmemcached.pl
		chmod +x /scripts/confmemcached.pl
		/scripts/confmemcached.pl --memcached-full
		service httpd restart
	fi

	# pear
	ec yellow "Matching PEAR packages..."
	ssh $sshargs $ip "pear list" | egrep [0-9]{1}.[0-9]{1} | awk '{print $1}' > $dir/pearlist.txt
	cat $dir/pearlist.txt |xargs pear install $pear

	# ruby gems
	if ssh $sshargs $ip "which gem"; then
		ec yellow "Matching ruby gems..."
		if which gem; then
			ssh $sshargs $ip "gem list" | tail -n+4 | awk '{print $1}' > $dir/gemlist.txt
			cat $dir/gemlist.txt | xargs gem install
		fi
	fi

}

# package/copy accounts/sync/final sync
package_accounts() { #for initialsyncs
	ec yellow "Packaging cpanel accounts externally and restoring on local server..." 
	> $hostsfile
	> $hostsfile_alt
	old_main_ip=`grep ADDR $dir/etc/wwwacct.conf | awk '{print $2}'`
	mkdir -p $dir/tmp/
	user_count=1
	user_total=`echo $userlist |wc -w`
	for user in $userlist; do
		restorepkg_args=""
		progress="$user_count/$user_total | $user:"
		old_user_ip=`grep ^IP= $dir/var/cpanel/users/$user|cut -d '=' -f2`
		ec lightBlue "${progress} Packaging $user" | tee -a $dir/pkgacct.log
		ssh $sshargs $ip "/scripts/pkgacct --skiphomedir $user $remote_tempdir " >> $dir/pkgacct.log
		cpmovefile=`ssh $sshargs $ip "find $remote_tempdir/ -maxdepth 1 -name cpmove-$user.tar.gz -mtime -1 |head -n1"`
		# verify a package was found
		if [ $cpmovefile ]; then
			ec lightPurple "$progress Rsyncing cpmove $cpmovefile"
			rsync $rsyncargs -e "ssh $sshargs" $ip:$cpmovefile $dir/tmp/
			if ([[ $old_user_ip != $old_main_ip ]] && [ "$ded_ip_check" = "1" ]) || [ "$single_dedip" = "yes" ]; then
				restorepkg_args="--ip=y"
			fi
			ec lightCyan "$progress Restoring $cpmovefile" | tee -a $dir/restorepkg.log
			/scripts/restorepkg $restorepkg_args $dir/tmp/cpmove-$user.tar.gz #2>&1 >> $dir/restorepkg.log
			mv $dir/tmp/cpmove-$user.tar.gz $dir/
			rsync_homedir
			hosts_file $user
		else
			# cpmove file was not found
			ec lightRed "Error: Did not find backup file for user $user!" |tee -a $dir/error.log
			echo $user >> $dir/did_not_restore.txt
		fi
		user_count=$(( $user_count+1 ))
	done
}
noncp_mysql_dbsync() { #get non-cPanel dbs
	if yesNo "Check for databases created outside of cpanel?"; then
        ec yellow "Downloading noncpaneldbs.py"
        wget -q --no-check-certificate https://git.sysres.liquidweb.com/acarlsonlynch/noncpaneldbs-py/raw/master/noncpaneldbs.py -O ${dir}/noncpaneldbs.py
        chmod 700 ${dir}/noncpaneldbs.py
        ec yellow "Uploading noncpaneldbs.py to remote server"
        rsync $rsyncargs -e "ssh $sshargs" ${dir}/noncpaneldbs.py ${ip}:${remote_tempdir}/
        ec yellow "Checking for databases created outside cPanel..."
        ssh $sshargs $ip "${remote_tempdir}/noncpaneldbs.py -c"
        myTest=$(ssh $sshargs $ip "echo $?")
        if [[ "$myTest" != 1 ]]; then
                if yesNo "Would you like to transfer and retore those databases as well? (if you say yes and the databases exist on the destination you will have the option to skip them)"; then
                        ssh $sshargs $ip "${remote_tempdir}/noncpaneldbs.py --dbdump-path=${remote_tempdir}/noncpdbdumps/ -v -f" | tee -a $dir/noncpaneldbs.log
                        rsync $rsyncargs -e "ssh $sshargs" ${ip}:${remote_tempdir}/noncpdbdumps $dir/
                        for db in `\ls ${dir}/noncpdbdumps/ | grep -v grants.sql | cut -d"." -f1`; do
                                ec yellow "Restoring ${db}"
                                x=$(mysql -Ns -e "SHOW DATABASES" | grep '^'${db}'$')
                                if [ "$x" = $db ]; then
                                        ec red "${db} Already exists on destination."
                                        if yesNo "Would you like to restore ${db} anyway?"; then
                                                mysql $db < $dir/noncpdbdumps/${db}.sql | tee -a $dir/noncpaneldbs.log
                                        fi
                                else
                                        if [ "$synctype" == "final" ]; then
                                                ec red "${db} not found on destination. Skipping. If you want to import by hand the dump is at ${dir}/noncpdbdumps/${db}.sql"
                                        else
                                                mysql -Ns -e "CREATE DATABASE ${db};"
                                                mysql $db < $dir/noncpdbdumps/${db}.sql | tee -a $dir/noncpaneldbs.log
                                        fi
                                fi
                        done
                        if yesNo "Would you like to import the users and grants from ${dir}/noncpdbdumps/grants.sql ?"; then
                                mysql < $dir/noncpdbdumps/grants.sql
                        fi
                fi
        fi
    fi
}

rsync_homedir() { # ran in a user in $userlist loop, for initial/final syncs.  package_accounts() 
	if [ -f "$dir/etc/passwd" ]; then
		userhome_remote=`grep ^$user: $dir/etc/passwd | tail -n1 |cut -d: -f6`
		userhome_local=`grep ^$user: /etc/passwd | tail -n1 |cut -d: -f6`
		# check if cpanel user exists
		if [ -f $dir/var/cpanel/users/$user ] && [ -f /var/cpanel/users/$user ] && [ -d $userhome_local ]; then
			ec lightGreen "$progress Rsyncing homedir from ${ip}:${userhome_remote} to $userhome_local."
			rsync $rsyncargs $rsync_update $rsync_excludes -e "ssh $sshargs" $ip:$userhome_remote/ $userhome_local/
		else
			ec red "Warning: Cpanel user $user not found! Not rsycing homedir." |tee -a $dir/error.log
			ec yellow "Running \`tail $dir/restorepkg.log\`, check for errors!"
			tail $dir/restorepkg.log
		fi
	else
		ec lightRed "Error: Password file from remote server not found at $dir/etc/passwd, can't sync homedir for $user! "
	fi
}

perlYaml() {
	if ! cpan -l | grep YAML::Syck ;then
		ec yellow "Installing YAML perl module..."
		cpan -i YAML::Syck #use YAML::Syck instead, should be installed already
		if cpan -l | grep YAML::Syck ; then 
			ec yellow "Yaml Perl module installed!"
		else
			ec red "Did not find YAML::Syck in installed perl modules, please try to reinstall with `cpan -i YAML::Syck` so we can resync databases."
			ec lightBlue "Press enter to continue."
			read
		fi
	else
		ec yellow "YAML Perl module found... continuing"
	fi
	wget -q --no-check-certificate https://git.sysres.liquidweb.com/sysres/pullsync/raw/master/dbyaml.pl -O /scripts/dbyaml.pl
	#check that script downloaded
	if ! [ -s /scripts/dbyaml.pl ]; then
		ec red "Error: Did not download dbyaml script, please run the following command and press enter to continue."
		echo 'wget -q --no-check-certificate https://git.sysres.liquidweb.com/sysres/pullsync/raw/master/dbyaml.pl -O /scripts/dbyaml.pl'
	fi
	chmod 700 /scripts/dbyaml.pl
}

mysql_dbsync(){ #for final syncs
	mkdir -p $dir/dbdumps
	perlYaml
	ec yellow "Dumping databases..."
	if [ "$userlist" ]; then
		dblist_restore="" # use for storing all db names to restore later.
		for user in $userlist; do
			echo "Dumping dbs for $user..."
			ssh $sshargs $ip "mkdir -p $remote_tempdir/dbdumps"
			# get list of dbs for user
			if [ -f $dir/var/cpanel/databases/$user.yaml ]; then
				# get from yaml file if it exists with this goofy sed. will grab dbs that are not obviously owned by user.  
				#dblist=`sed -e '/MYSQL:/,/dbusers:/!d' $dir/var/cpanel/databases/$user.yaml |tail -n +3 |head -n -1 |cut -d: -f1 |tr -d ' '`
				dblist=`/scripts/dbyaml.pl $dir/var/cpanel/databases/$user.yaml MYSQL`
			else
				# var/cpanel/databases, may not exist in really old vps, fall back to old way.
				dblist=`ssh $sshargs $ip "mysql -e 'show databases'| grep ^$user\_ "`
			fi

			echo "Found dbs: $dblist"
			dblist_restore="$dblist_restore $dblist"
			mysqldumpver=`ssh $sshargs $ip 'mysqldump --version |cut -d" " -f6 |cut -d, -f1'`
			for db in $dblist; do 
				if [[ $mysqldumpver > 5.0.42 ]]; then
					mysqldumpopts="--opt --routines --force --log-error=$remote_tempdir/dbdumps/dump.log"
				else
					mysqldumpopts="--opt -Q"
				fi
				if ! ssh $sshargs $ip "mysqladmin status > /dev/null" ; then # check if mysql is running using a more universal method
					ec lightRed "Mysql does not seem to be running on remote server, please fix and press enter to continue!"
					echo "Checked with `mysqladmin status` "
					read
				fi
				echo "Dumping $db on remote server..."
				ssh $sshargs $ip "mysqldump $mysqldumpopts $db > $remote_tempdir/dbdumps/$db.sql"
				echo "Rsyncing over $db"
				rsync $rsyncargs -e "ssh $sshargs" $ip:$remote_tempdir/dbdumps/$db.sql $dir/dbdumps/
				#check for existing db
				if ! mysql -e 'show databases;' |egrep "^${db}$" ; then
					ec red "Mysql db $db does not exist on this server! Creating and dbmapping to user"
					mysqladmin create $db
					/usr/local/cpanel/bin/dbmaptool $user --type mysql --dbs "$db"
				fi
			done
		done
		mkdir -p $dir/pre_dbdumps
		for db in $dblist_restore; do
			echo "Backing up $db to $dir/pre_dbdumps..."
			mysqldump --opt --routines $db > $dir/pre_dbdumps/$db.sql
			echo "Restoring $db..."
			mysql $db < $dir/dbdumps/$db.sql
		done
	else
		ec red "Userlist not found for mysql sync!?"
	fi
}

pgsql_dbsync() {
	perlYaml
	#test if posgres exists first, and on remote server, and are running
	if ssh $sshargs $ip "/etc/init.d/postgresql status" ; then
		ec yellow "Postgres found running on remote server..."
		if /etc/init.d/postgresql status ; then
			ec yellow "Postgres running on local server, syncing dbs"
			if [ "$userlist" ]; then
				for user in $userlist; do
					#run in userloop, during final sync.
					echo "Checking for postgres databases for $user..."
					if [ -f "$dir/var/cpanel/databases/$user.yaml" ]; then
						pgdbs=`/scripts/dbyaml.pl $dir/var/cpanel/databases/$user.yaml PGSQL`
						pgdbcount=`echo $pgdbs |wc -w`
						if [[ $pgdbcount -gt 0 ]]; then
							for db in $pgdbs; do
								echo "Importing pgsql db $db..."
								mkdir -p $dir/pgdumps
								mkdir -p $dir/pre_pgdumps/
								ssh $sshargs $ip "mkdir -p $remote_tempdir; cd $remote_tempdir; pg_dump --clean -U postgres $db > $db.psql"
								rsync $rsyncargs -e "ssh $sshargs" $ip:$remote_tempdir/$db.psql $dir/pgdumps/
								pg_dump --clean -U postgres $db > $dir/pre_pgdumps/$db.psql
								psql --quiet -U postgres -f $dir/pgdumps/$db.psql -d $db
							done
						else
							echo "No Postgres dbs found for $user."
						fi
					else
						echo "No yaml file found for $user"
					fi
				done
			fi
		else
			ec red "Postgres not found on local sever!"
		fi
	else
		echo "Postgres not found on remote server."
	fi
}

hosts_file() {
	user=$1
	ec yellow "Generating hosts file entries for $user"
	if [ -f /var/cpanel/users/$user ]; then
		user_IP=`grep ^IP /var/cpanel/users/$user |cut -d= -f2`
		user_domains=`grep ^DNS /var/cpanel/users/$user |cut -d= -f2 `
		#per user way
		echo -n "$user_IP " | tee -a $hostsfile
		echo $user_domains | while read DOMAIN ; do
			echo -n "$DOMAIN www.$DOMAIN "
	  	done | tee -a $hostsfile
	  	echo "" | tee -a $hostsfile
		#one line per domain
		for domain in $user_domains; do
			echo "$user_IP $domain www.$domain" >> $hostsfile_alt
		done
	else
	  ec lightRed "Cpanel user file for $user not found, not generating hosts file entries!" |tee -a $dir/error.log
	fi
}
mysqlversion() {
	ec yellow "Remote Mysql 	   : $remotemysql"
	ec yellow "Current local Mysql : $localmysql"
	#check major.minor version of mysql
	if [ $localmysql == $remotemysql ];then
		ec green "Mysql versions match!"
	else
		ec red "Mysql versions do not match."
	fi
	if yesNo "Change local Mysql version?"; then
		mysqlverloop=0
		while [ $mysqlverloop == 0 ]; do 
		    ec lightBlue "Available mysql versions:"
		    ec white " 5.1"
			ec white " 5.5"
			ec white " 5.6"
		    echo -e "Please input desired mysql version, or x to cancel: " # older than 5.1 isn't supported in 11.40+
		    read newmysqlver
		    case $newmysqlver in 
		    	5.1|5.5|5.6)
					ec green "Mysql will be changed to $newmysqlver"
					mysqlup=1
					mysqlverloop=1;;
				x)
					ec yellow "Mysql version will not be changed."
					mysqlverloop=1;;
				*) 
					ec lightRed "Incorrect input, try again." ;;
			esac
		done
	fi


}
phpversion () {
	if [ "$remotephp" ] && [ "$localphp" ]; then
		# store versions in an array #{ea_php_versions[0]}
		ea_php_versions=(`/scripts/easyapache --latest-versions |grep PHP -A1 |tail -n1 |sed 's/,//g'`)
		count=0
		# generate menu
		phpversion_loop=0
		while [ $phpversion_loop == 0 ]; do 
			ec yellow "Remote php        : $remotephp"
			ec yellow "Current local php : $localphp"
			ec lightBlue "Select your desired php version from the following list:"
			while [ $count -lt ${#ea_php_versions[@]} ] ; do
				phpver=${ea_php_versions[$count]}
				count=$(( $count + 1 )) # add here, so we offset the array by +1, so we get options starting at 1
				ec white "$count) $phpver"
			done
			# offer php 5.2?
			# ec white "5.2) 5.2.17 (Custom Cpanel Module)"
			ec white "x) no php change (unless you are changing mysql version)"
			echo -n "Choose: "
			read phpversion_choice
			# test if choice was valid, goofy bash regex here. 
			if [[ $phpversion_choice =~ [1-${#ea_php_versions[@]}] ]] || [ "$phpversion_choice" = "x" ] ;then # || [ $phpversion_choice = "5.2" ];then
				phpversion_loop=1
			else
				ec red "Invalid choice."
				count=0
			fi
		done
		if [ ! "$phpversion_choice" = "x" ]; then
			# subtract 1 from the choice to get the proper array reference
			phpversion_choice=$(( $phpversion_choice-1 ))
			ec lightGreen "Selected ${ea_php_versions[$phpversion_choice]}" 
			major=$(echo ${ea_php_versions[$phpversion_choice]} | cut -d. -f1)
			minor=$(echo ${ea_php_versions[$phpversion_choice]} | cut -d. -f2)
			patch=$(echo ${ea_php_versions[$phpversion_choice]} | cut -d. -f3)
			newline="Cpanel::Easy::PHP${major}::${minor}_${patch}:"
			echo "choice: $phpversion_choice"
			echo "major: $major minor: $minor patch: $patch"
			echo "Selected PHP version=${newline}" 
			# back up existing _main.yaml
			cp -rp /var/cpanel/easy/apache/profile/_main.yaml $dir/
			#get config from remote server:
			rsync $rsyncargs -e "ssh $sshargs" $ip:/var/cpanel/easy/apache/ /var/cpanel/easy/apache/
			# This will make all current versions 0's.
			sed -i -e 's/\(Cpanel::Easy::PHP[0-9]::[0-9]\+_[0-9]\+\:\ \)/\10/g' /var/cpanel/easy/apache/profile/_main.yaml
			# add the desired version to the _main.yaml
			if grep -q ${newline} /var/cpanel/easy/apache/profile/_main.yaml; then
				sed -i "s/${newline} 0/${newline} 1/" /var/cpanel/easy/apache/profile/_main.yaml
			else
				echo "${newline} 1" >> /var/cpanel/easy/apache/profile/_main.yaml
			fi 
			#set this to run ea later
			ea=1 
		else
			ec lightGreen "Skipped php version change."
		fi
	else
		ec lightRed "Local or remote php version not detected! Skipping version change. Press Enter to continue."
		read
	fi
}
postgres_install_check() {
	# check to install posgres
	if [ "$postgres" ]; then
		if [ -d /var/lib/pgsql ]; then
			ec yellow "Postgres found on this server already!"
			unset postgres
		else
			if yesNo "Postgres detected on old server, install postgres locally?";then 
				ec lightGreen "Postgres selected for installation."
			else
				ec lightGreen "Postgres will not be installed."
				unset postgres
			fi
		fi
	fi
}

phpextras () { # run after EA
	# phphandler
	ec yellow "Matching php handler..." 
	# we pretty much only care about the php5 handler.  php 4 is no more as far as we are concerned. never seen suexec disabled eitehr.
	/usr/local/cpanel/bin/rebuild_phpconf 5 none $remotephphandler 1 > /dev/null
	phphandler_check=`/usr/local/cpanel/bin/rebuild_phpconf --current |grep PHP5\ SAPI: |cut -d" " -f3`
	if [ ! "$remotephphandler" = "$phphandler_check" ]; then
		ec lightRed "Warning: Phphandler not set to $remotephphandler, please double check!" | tee -a $dir/error.log
	fi
	# Memory limit
	remotephp_memory_limit=`sed -n 's/^memory_limit.*=\ \?\([0-9]\+[A-Z]\?\)/\1/p' $dir/usr/local/lib/php.ini`
	# check for a valid value
	if echo $remotephp_memory_limit |egrep -q '[0-9]+' ;then 
		ec yellow "Setting php memory_limit to $remotephp_memory_limit"
		sed -i "s/^\(memory_limit\ =\ \)[0-9]\+[A-Z]\?/\1$remotephp_memory_limit/" /usr/local/lib/php.ini
	else
		ec red "WARNING: Remotephp memory limit of $remotephp_memory_limit seems to be invalid."
	fi
	# max execution time
	remotephp_max_execution_time=`sed -n 's/^max_execution_time.*=\ \?\([0-9]\+[A-Z]\?\)/\1/p' $dir/usr/local/lib/php.ini`
	if echo $remotephp_max_execution_time |egrep -q '[0-9]+' ;then 
		ec yellow "Setting php max_execution_time to $remotephp_max_execution_time"
		sed -i "s/^\(max_execution_time\ =\ \)[0-9]\+[A-Z]\?/\1$remotephp_max_execution_time/" /usr/local/lib/php.ini
	else
		ec red "WARNING: Remotephp max execution time of $remotephp_max_execution_time seems to be invalid." 
	fi
}

upcp_check() { #
	echo "Checking Cpanel versions..." 
	#upcp if local version is higher than remote
	if  [[ $localcpanel < $remotecpanel ]]; then
		echo "This server has $localcpanel" 
		echo "Remote server has $remotecpanel" 
		if yesNo "Run Upcp on this server?" ; then
			echo "Upcp will be ran when the sync begins." 
			upcp=1
		fi
	else
	    echo "Found a higher version of cpanel on local server, continuing."
	fi
}

modsec_rules_check(){
	# we check for modsec rpm versions back in getversions
	if [ "$localmodsec" != "$remotemodsec" ]; then
		ec yellow "Remote modsec version $remotemodsec different from local version $localmodsec. Please press enter to continue."
		read 
	else
		# copy over if modsec2 (apache 1 no longer supported by ea) if whitelist file is not empty on this server.
		if [[ "$localmodsec" =~ "lp-modsec2-rules" ]];then
			if [ ! -s "/usr/local/apache/conf/modsec2/whitelist.conf" ]; then #whitelist.conf is not a non-zero size
				cat $dir/usr/local/apache/conf/modsec2/whitelist.conf >> /usr/local/apache/conf/modsec2/whitelist.conf
			else
				ec yellow "Existing content found in /usr/local/apache/conf/modsec2/whitelist.conf, not importing."		
			fi
		fi
	fi
}

mailman_copy() {
	# will come over with initial sync, just needed in final sync.
	[ ! "$userlist" ] && return;
	for user in $userlist; do 
		# found list data in /var/cpanel/datastore/$user/mailman-list-usage, just reference the data for the user already restored. may not exist on old cp versions. 
		if [ -f "/var/cpanel/datastore/$user/mailman-list-usage" ]; then
			mailinglists=`cat /var/cpanel/datastore/$user/mailman-list-usage |cut -d: -f1`
			for list in mailinglists; do 
				# list data is in /usr/local/cpanel/3rdparty/mailman/lists/$list
				rsync $rsyncargs -e "ssh $sshargs" $ip:/usr/local/cpanel/3rdparty/mailman/lists/$list /usr/local/cpanel/3rdparty/mailman/lists/
				# archive data is in /usr/local/cpanel/3rdparty/mailman/archives/private/$list{,.mbox}
				rsync $rsyncargs -e "ssh $sshargs" $ip:"/usr/local/cpanel/3rdparty/mailman/archives/private/$list{,.mbox}" /usr/local/cpanel/3rdparty/mailman/archives/private/
			done
		fi
	done
}

hostsfile_gen() {
	#run as part of initial sync, and as own function, requires userlist, domainlist, cpanel_main_ip

	#hosts
	> /usr/local/apache/htdocs/hosts_file_entries.html
	if [ "$domainlist" ]; then
		ec yellow "Hosts file entries:"
		for domain in $domainlist
			do cat /etc/userdatadomains | grep $domain | sed -e 's/:/ /g' -e 's/==/ /g' | while read sdomain suser owner type maindomain docroot dip sport; do 
				echo $dip $sdomain "www."$sdomain >> /usr/local/apache/htdocs/hosts_file_entries.html; 
			done 
		done
	else
		ec red "Domainlist variable is not set, not generating host file entries."
	fi

	#hostscheck 
	if [ "$userlist" ]; then
		ec yellow "Adding lwHostsCheck.php to migrated users"
		#wget -q http://migration.sysres.liquidweb.com/hostsCheck.txt  -O $dir/lwHostsCheck.php
		wget -q --no-check-certificate https://git.sysres.liquidweb.com/sysres/pullsync/raw/master/hostsCheck.txt -O $dir/lwHostsCheck.php
		for user in $userlist; do 
			userhome_local=`grep ^$user: /etc/passwd | tail -n1 |cut -d: -f6`
			docroots=`grep DocumentRoot /usr/local/apache/conf/httpd.conf |grep $userhome_local| awk '{print $2}'`
			for docroot in $docroots; do 
				cp -rp $dir/lwHostsCheck.php $docroot/
				chown $user. $docroot/lwHostsCheck.php
			done
		done
	else
		ec red "Warning: Userlist variable not detected when creating lw test file!"
	fi

	#test urls
	> /usr/local/apache/htdocs/migration_test_urls.html
	if [ "$domainlist" ]; then
		ec yellow "Generating migration test urls..."
		for domain in $domainlist; do
			echo "http://$domain/lwHostsCheck.php" >> /usr/local/apache/htdocs/migration_test_urls.html
		done
		test_urls=`cat /usr/local/apache/htdocs/migration_test_urls.html |haste`
		#save hastbin url in $dir
		echo $test_urls > $dir/test_urls
	else
		ec red "Warning: Could not genearte test urls, no domainlist."
	fi

	#upload hostsfile_alt to hastebin:
	hostsfile_url=`cat $hostsfile_alt | haste`
	echo $hostsfile_url > $dir/hostsfile_url

	#generate reply
	ec yellow "generating response to customer..."
	wget -q --no-check-certificate https://git.sysres.liquidweb.com/sysres/pullsync/raw/master/pullsync_reply.txt -O $dir/pullsync_reply.txt
	
	#edit reply
	#hostsfile url
	sed -i -e "s|http://\${ip}/hostsfile.txt|$hostsfile_url|" $dir/pullsync_reply.txt 
	#migration_test_urls.html
	sed -i -e "s|http://\${ip}/migration_test_urls.html|$test_urls|" $dir/pullsync_reply.txt 

	#send to paste server
	reply_url=`cat $dir/pullsync_reply.txt | haste`
	echo $reply_url > $dir/reply_url
	ec yellow "Reply generated at $reply_url"
}



# logging function
logit() { 
	tee -a $log; 
}

exitcleanup() {
    #remove local and remote noncpaneldbs.py script
    if [ "$dir" ]; then
            if [ -f "${dir}/noncpaneldbs.py" ]; then
                    rm -f ${dir}/noncpaneldbs.py
            fi
    fi
    if [ "$ip" ]; then
            ssh $sshargs $ip "if [ "$remote_tempdir" ]; then if [ -f "${remote_tempdir}/noncpaneldbs.py" ]; then rm -f ${remote_tempdir}/noncpaneldbs.py; fi; fi"
    fi
	#remove pullsync key from remote authorized keys on remote server
	if [ "$ip" ]; then
		ssh $sshargs $ip "sed -i /pullsync/d ~/.ssh/authorized_keys ; if which firewall; then firewall start; fi"
	fi
	#remove local pullsync sshkeys
	rm -rf ~/.ssh/pullsync*
	#clear lock file (carefully)
	if [ "$dir" ]; then
		if [ -f "$pidfile" ]; then
			rm -f "$pidfile"
		fi
	fi
}

control_c() {
  #if user hits control-c 
  echo
  echo "Control-C pushed, exiting..." | tee -a $dir/error.log
  exitcleanup
  exit 200
}

trap control_c SIGINT
# start the script after functions are defined.

main | logit

exitcleanup

echo
ec white "Started $starttime"
ec white "Ended `date +%F.%T`"
ec lightGreen "Done!"
