#!/bin/bash

#Set the No/Yes Values for easier code reading
No=0
Yes=1
 
#-------- Begin Configs ------#
#Normal Operation - take command line argument for run mode Ex: audit-all
OPERMODE=$1
#Example of hard coding argument for remote testing or added security 
#OPERMODE=fix-notify

#We hard code the following options for safety, in the future we might allow changing via commnad line
TURNOFFBACKUPS=$No         #Should we turn off backups? 
PRESCRIBECOMMANDSONLY=$Yes #Do we only create a list of command to remediate the checks and run them later?  (No=run now,Yes=only create list)
#--------- End Configs --------#

#-------- Begin Initialize Default Values ------#
MAYNEEDTOBERERUN=$No
INATERMINAL=$No
RootEUID=0
#-------- End Initialize Default Values ------#

#-------- Begin Set Exit Codes ------#
Success=0
RootInNonTerminal=1
PermissionsNeeded=2
UsagePrint=3
TerminalNeededForInteractive=4
CommandsNeeded=10
UndeterminedOS=49
UnsupportedOS=50
FilevaluecheckError=51
#-------- End Set Exit Codes ------#

#-------- Begin Set Text - these should all be 12 characters ------#
WarningText="!!!Warning  "
ModificationText="+++Changing "
IncorrectText="---Incorrect"
CorrectText="OK          "
SkippedText="Skipped     "
ErrorText="ERROR       "
#-------- End Set Text ------#

if [[ -t $Yes ]]; then #Check for a terminal
	INATERMINAL=$Yes
fi #End Terminal Check

echo_text_function () {
	TextToEcho=$1
	TYPEOFNOTIFICATION=$2
	
	case "$TYPEOFNOTIFICATION" in #Rather than checking the notification setting for each echo, we centralize it here (default to echoing)
	ON)
		if [[ "$ONNOTIFICATIONS" -eq "$Yes" ]]; then #This is an ON notification, should we announce it?
			echo "$TextToEcho"
		fi #ONNOTIFICATIONS check
	;;
	OFF)
		if [[ "$OFFNOTIFICATIONS" -eq "$Yes" ]]; then #This is an OFF notification, should we announce it?
			echo "$TextToEcho"
		fi #OFFNOTIFICATIONS check
	;;
	CHANGE)
		if [[ "$NOTIFYCHANGES" -eq "$Yes" ]]; then #This is a CHANGE notification, should we announce it?
			echo "$TextToEcho"
		fi #NOTIFYCHANGES check
	;;
	*) #We'd like to avoid falling into this block
		echo "$TextToEcho"
	esac #End - case "$TYPEOFNOTIFICATION"
}

#Command Check - "echo" is the only command we assume exists because we use it for the Command check announcement, it would be nice to run this through the echo_text_function at some point
commands_needed_array=(echo chmod chown grep sed service stat rpm yum awk tail sysctl mktemp tar sudo mv date)

for command in "${commands_needed_array[@]}"; do
	hash "$command" 2>/dev/null || { echo "$ErrorText - This script requires $command but it's not available."; exit $CommandsNeeded;}
done #End command in ${commands_needed_array[@]}

if [[ "$EUID" -eq "$RootEUID" ]]; then #Permissions and Path check - you should be running this script with a user that that has full sudo privs (non-root) but I'll tolerate running as root in a terminal
    if [[ "$INATERMINAL" -eq "$Yes" ]]; then  #Check for a terminal
		echo_text_function "Ok I'll let you run this as root in a terminal"
	else #INATERMINAL else
		echo_text_function "You really shouldn't be running as root in a non-terminal. Exiting"
		exit $RootInNonTerminal
	fi #End INATERMINAL check
else #EUID else
    #Check that the user has correct sudo privs - TODO: I should trim the white space
    #This could be done much better, for now I just want to encourage people to use sudo for its logging capabilites.
    #I'll start to keep a list of what commands we need to sudo without a passworda
    #Ideal /etc/sudoers line:
    #^\$USER ALL = NOPASSWD:/bin/ls,/bin/tar,/bin/cat,/bin/grep,/usr/bin/stat,/bin/echo,/bin/sed,/bin/mv,/sbin/service,/sbin/chkconfig,/sbin/sysctl
	if sudo grep -q "^$USER ALL = NOPASSWD: ALL$" /etc/sudoers; then
		echo_text_function "You are running as a non-root user with the correct sudo privs."
	else #Status code else
		echo_text_function "You don't have the required permissions to run this check"
		exit $PermissionsNeeded
	fi #End Status code check
fi #End EUID Check

if [[ -f /etc/redhat-release ]]; then #Determine version of RedHat/Centos and if it is supported - this should be cleaned up 
	if grep -qE "Red Hat|CentOS" /etc/redhat-release; then 
		if grep -q "5." /etc/redhat-release; then
			OSVER="5"
		fi 
		if grep -q "6." /etc/redhat-release; then
			OSVER="6"
		fi 
	fi 
	if [[ "$OSVER" = "" ]]; then #Check if we determined an OS Version 
		echo_text_function "$ErrorText Could not determine OS Version"
		exit $UndeterminedOS
	fi #End OS Version determination check 
else #else for main OS check
	echo_text_function "$ErrorText You are using an unsupported OS. RedHat/Centos required"
	exit $UnsupportedOS
fi #End OS Check 

echo_text_function "OSVER is $OSVER - Supported"
	
#Set default values for configs and give explanations
ONNOTIFICATIONS=$No        #Should we notify things that are configured properly 
OFFNOTIFICATIONS=$No       #Should we notify things that aren't configured properly
NOTIFYCHANGES=$No          #Should we notify of changes 
MAKECHANGES=$No            #Should we make changes 
INTERACTIVECHANGES=$No     #Should we the user to make select what changes to make 

case "$OPERMODE" in
audit-all)
	ONNOTIFICATIONS=$Yes   #In this case we want notifications of things that are on/implemented
	OFFNOTIFICATIONS=$Yes  #In this case we want notifications of things that are off/not implemented
	NOTIFYCHANGES=$No      #Nothing should change in an audit
	MAKECHANGES=$No        #Nothing should change in an audit 
	INTERACTIVECHANGES=$No #This is not interactice mode
	TURNOFFBACKUPS=$Yes    #No need for backups here, nothing should change
;;

audit-on)
	ONNOTIFICATIONS=$Yes   #In this case we want notifications of things that are on/implemented
	OFFNOTIFICATIONS=$No   #In this case we dont want notifications of things that are off/not implemented
	NOTIFYCHANGES=$No      #Nothing should change in an audit
	MAKECHANGES=$No        #Nothing should change in an audit
	INTERACTIVECHANGES=$No #This is not interactice mode
	TURNOFFBACKUPS=$Yes    #No need for backups here, nothing should change
;;

audit-off)
	ONNOTIFICATIONS=$No    #In this case we don't want notifications of things that are on/implemented
	OFFNOTIFICATIONS=$Yes  #In this case we want notifications of things that are off/not implemented
	NOTIFYCHANGES=$No      #Nothing should change in an audit
	MAKECHANGES=$No        #Nothing should change in an audit
	INTERACTIVECHANGES=$No #This is not interactice mode
	TURNOFFBACKUPS=$Yes    #No need for backups here, nothing should change
;;

fix-quiet)
	ONNOTIFICATIONS=$No    #In this case we don't want notifications of things that are on/implemented
	OFFNOTIFICATIONS=$No   #In this case we dont want notifications of things that are off/not implemented
	NOTIFYCHANGES=$No      #Don't need to nofify in quiet mode 
	MAKECHANGES=$Yes       #Yes we are making changes 
	INTERACTIVECHANGES=$No #This is not interactice mode 
	#TURNOFFBACKUPS stays set to its  hard coded default
;;

fix-notify)
	ONNOTIFICATIONS=$No    #In this case we don't want notifications of things that are on/implemented
	OFFNOTIFICATIONS=$No   #In this case we dont want notifications of things that are off/not implemented
	NOTIFYCHANGES=$Yes     #We need to send notification of what changes are needed
	MAKECHANGES=$Yes       #Yes we are making changes 
	INTERACTIVECHANGES=$No #This is not interactice mode
	#TURNOFFBACKUPS stays set to its  hard coded default
;;

interactive)
	if [[ "$INATERMINAL" -eq "$No" ]]; then #Check if in a terminal 
		echo_text_function "$ErrorText - You need to be in a terminal to make interactive changes"
		exit $TerminalNeededForInteractive
	fi #End INATERMINAL Check
	ONNOTIFICATIONS=$Yes    #In this case we do want notifications of things that are on/implemented
	OFFNOTIFICATIONS=$Yes   #In this case we do want notifications of things that are off/not implemented
	NOTIFYCHANGES=$Yes      #We need to send notification of what changes are needed
	MAKECHANGES=$Yes        #Yes we are making changes 
	INTERACTIVECHANGES=$Yes #This is not interactice mode
	#TURNOFFBACKUPS stays set to its  hard coded default
;;

*)
	echo "Usage: $0 audit-all | audit-on | audit-off | fix-quiet | fix-notify | interactive"
	echo
	echo "audit-all   - make no changes, notify status of all"
	echo "audit-on    - make no changes, notify status of correct settings"
	echo "audit-off   - make no changes, notify status of incorrect settings"
	echo "fix-quiet   - make changes, no notifications"
	echo "fix-notify  - make changes, with notifications"
	echo "interactive - step through each check, give status of all and prompt to fix (if needed)"
	echo
	echo "Example:"
	echo "[user@server LinuxChiro]$ $0 audit-all"
	echo 
	exit $UsagePrint
esac

echo

if [[ "$MAKECHANGES" -eq "$Yes" ]]; then #Check if we should make changes 

	#Create Directory for Commands that should be run
	PRESCRIBEFOLDER=$(mktemp -d)
	
	#Create file to store commands that should be run
	PRESCRIBECOMMANDFILE="commandstorun.lis"
	
	#Create Directory for Undo File
	UNDOFOLDER=$(mktemp -d)
	
	#Create file to store commands to undo changes
	UNDOCOMMANDFILE="undocommands.lis"
	
	if [[ "$TURNOFFBACKUPS" -eq "$No" ]]; then #Check if we should turn off Backups
		#Add the BACKUPFOLDER to the PRESCRIBECOMMANDFILE
		echo "BACKUPFOLDER=\$(mktemp -d)" > "$PRESCRIBEFOLDER/$PRESCRIBECOMMANDFILE"
	fi #TURNOFFBACKUPS check 
fi #MAKECHANGES Check

#Define Functions 
execute_command_function () { #Start of execute_command_function
	CommandToExecute=$1
	CommandToUndo=$2
	CommandToCleanUpBackups=$3
	
	#Add the Command to Execute to the "Prescibe Commands, at the end we decide if we should run these or not
	echo "$CommandToExecute" >> "$PRESCRIBEFOLDER/$PRESCRIBECOMMANDFILE"
	
	if [[ -n "$CommandToUndo" ]]; then #Add the command to undo change as long as it is populated 
		echo "$CommandToUndo" >> "$UNDOFOLDER/$UNDOCOMMANDFILE"
	fi #End check of CommandToUndo variable 
	
	if [[ "$TURNOFFBACKUPS" -eq "$No" && -n "$CommandToCleanUpBackups" ]]; then #if backups are on we need to clean up any files produces
		echo "$CommandToCleanUpBackups" >> "$PRESCRIBEFOLDER/$PRESCRIBECOMMANDFILE"
	fi #end of check for backup files to clean up 
} #End of execute_command_function 

interactive_check_function () { #Function to determine if we should prompt for each change 
	QuestionToDisplay=$1
	
	if [[ "$INTERACTIVECHANGES" -eq "$Yes" ]]; then #INTERACTIVE CHANGES Check 
		while true; do
			read -rp "$QuestionToDisplay" yn 
			case $yn in
				[Yy]* ) MAKETHISCHANGE=$Yes; break;;
				[Nn]* ) MAKETHISCHANGE=$No; break;;
				"" ) MAKETHISCHANGE=$No; break;;
				* ) echo 'Please answer "y" or "n".';;
			esac
		done
	else #INTERACTIVE CHANGES Check
		MAKETHISCHANGE=$Yes
	fi #INTERACTIVE CHANGES Check
} #End of interactive_check_function

FILEPERMCHANGECOMMAND="chmod"
FILEOWNSHIPCHANGECOMMAND="chown"

#Correct File and folder permissions and ownership
#format - operation,filename,correct value,reason
file_and_perm_array=(
"$FILEPERMCHANGECOMMAND,/etc/inittab,600,disable_gui_login"
"$FILEPERMCHANGECOMMAND,/etc/security/console.perms,600,disable_user_mounted_removable_file_systems"
"$FILEPERMCHANGECOMMAND,/var/log/dmesg,640,prevent_access_to_dmesg"
"$FILEPERMCHANGECOMMAND,/etc/sysctl.conf,600,secure_sysctl"
"$FILEPERMCHANGECOMMAND,/root,700,root_home_dir"
"$FILEPERMCHANGECOMMAND,/root/.tcshrc,400,sec_for_root"
"$FILEPERMCHANGECOMMAND,/root/.bashrc,400,sec_for_root"
"$FILEPERMCHANGECOMMAND,/root/.cshrc,400,sec_for_root"
"$FILEPERMCHANGECOMMAND,/etc/csh.cshrc,444,sec_for_root"
"$FILEPERMCHANGECOMMAND,/etc/bashrc,444,sec_for_root"
"$FILEPERMCHANGECOMMAND,/var/log/wtmp,600,sec_logs"
"$FILEPERMCHANGECOMMAND,/var/log/lastlog,600,sec_logs"
"$FILEPERMCHANGECOMMAND,/var/log/rpmpkgs,640,sec_logs"
"$FILEPERMCHANGECOMMAND,/etc/securetty,400,sec_console_login"
"$FILEPERMCHANGECOMMAND,/var/lib/nfs,750,secure_nfs_folder"
"$FILEPERMCHANGECOMMAND,/etc/cups/cupsd.conf,600,sec_cups"
"$FILEPERMCHANGECOMMAND,/etc/crontab,400,secure_crontab"
"$FILEPERMCHANGECOMMAND,/etc/cron.allow,400,secure_crontab"
"$FILEPERMCHANGECOMMAND,/etc/at.allow,400,secure_crontab"
"$FILEPERMCHANGECOMMAND,/etc/mail/sendmail.cf,444,secure_sendmail_conf"
"$FILEPERMCHANGECOMMAND,/var/log/sa,600,secure_sar_files"
"$FILEPERMCHANGECOMMAND,/var/spool/cron,600,secure_cron"
"$FILEPERMCHANGECOMMAND,/etc/syslog.conf,640,secure_syslog_conf"
"$FILEPERMCHANGECOMMAND,/etc/security/access.conf,640,secure_access_conf"
"$FILEPERMCHANGECOMMAND,/var/spool/cron/root,600,secure_root_crontab"
"$FILEPERMCHANGECOMMAND,/etc/gshadow,0,secure_gshadow"
"$FILEPERMCHANGECOMMAND,/etc/shadow,0,secure_shadow"
"$FILEPERMCHANGECOMMAND,/etc/passwd,644,secure_etc_passwd"
"$FILEPERMCHANGECOMMAND,/etc/group,644,secure_etc_group"
"$FILEPERMCHANGECOMMAND,/boot/grub/grub.conf,600,secure_grub_conf"
"$FILEPERMCHANGECOMMAND,/lib,755,secure_lib"
"$FILEPERMCHANGECOMMAND,/lib64,755,secure_lib64"
"$FILEPERMCHANGECOMMAND,/usr/lib,755,secure__usr_lib"
"$FILEPERMCHANGECOMMAND,/usr/lib64,755,secure__usr_lib64"
"$FILEPERMCHANGECOMMAND,/var/log/audit,750,secure_audit_dir"
"$FILEPERMCHANGECOMMAND,/var/log/audit/audit.log,600,secure_audit_fule"
"$FILEOWNSHIPCHANGECOMMAND,/var/spool/cron/root,root:root,secure_root_crontab"
"$FILEOWNSHIPCHANGECOMMAND,/var/log/btmp,root:root,secure_logs"
"$FILEOWNSHIPCHANGECOMMAND,/etc/cups/cupsd.conf,lp:sys,secure_cups_conf"
"$FILEOWNSHIPCHANGECOMMAND,/etc/pam.d/atd,root:root,secure_pam_conf"
"$FILEOWNSHIPCHANGECOMMAND,/etc/mail/sendmail.cf,root:bin,secure_sendmail_conf"
"$FILEOWNSHIPCHANGECOMMAND,/var/log/wtmp,root:root,secure_wtmp"
"$FILEOWNSHIPCHANGECOMMAND,/etc/gshadow,root:root,secure_gshadow"
"$FILEOWNSHIPCHANGECOMMAND,/etc/shadow,root:root,secure_shadow"
"$FILEOWNSHIPCHANGECOMMAND,/etc/passwd,root:root,secure_passwd"
"$FILEOWNSHIPCHANGECOMMAND,/var/log/audit/audit.log,root:root,secure_audit_file"
"$FILEOWNSHIPCHANGECOMMAND,/etc/group,root:root,secure_group_file"
"$FILEOWNSHIPCHANGECOMMAND,/lib,root:root,secure_lib"
"$FILEOWNSHIPCHANGECOMMAND,/lib64,root:root,secure_lib64"
"$FILEOWNSHIPCHANGECOMMAND,/usr/lib,root:root,secure_usr_lib"
"$FILEOWNSHIPCHANGECOMMAND,/usr/lib64,root:root,secure_usr_lib64"
"$FILEOWNSHIPCHANGECOMMAND,/boot/grub/grub.conf,root:root,secure_grub_conf"
)

for i in "${file_and_perm_array[@]}"; do
	operation=$(echo "$i" | awk -F, '{print $1;}')
	file=$(echo "$i" | awk -F, '{print $2;}')
	correctsetting=$(echo "$i" | awk -F, '{print $3;}')
	reason=$(echo "$i" | awk -F, '{print $4;}')
	
	if sudo stat "$file" > /dev/null 2>&1; then #Check the file or directory exists
		if [[ "$operation" = "$FILEPERMCHANGECOMMAND" ]]; then #operation check
			filevaluecheck=$(sudo stat -c %a "$file")
		elif [[ "$operation" = "$FILEOWNSHIPCHANGECOMMAND" ]]; then #operation check
			filevaluecheck=$(sudo stat -c %U:%G "$file")
		else #operation check catch all 
		        echo_text_function "Error processing filevaluecheck it was set to $filevaluecheck"; exit $FilevaluecheckError
		fi #operation check
		
		if [[ "$filevaluecheck" != "$correctsetting" ]]; then
			echo_text_function "$IncorrectText $file is set to $filevaluecheck should be $correctsetting" "OFF"
			#Make Chages
			if [[ "$MAKECHANGES" -eq "$Yes" ]]; then
				interactive_check_function "Would you like to $operation $file to $correctsetting [y/N]"
				if [[ "$MAKETHISCHANGE" -eq "$Yes" ]]; then
					execute_command_function "sudo $operation $correctsetting $file" "sudo $operation $filevaluecheck $file"
					#Check to notify of changes
					echo_text_function "$ModificationText Setting $file to $correctsetting to $reason" "CHANGE"
				else #MAKETHISCHANGE else 
					echo_text_function "$SkippedText $file left set to $filevaluecheck" "SKIPPED"
				fi #MAKETHISCHANGE check
			fi #MAKECHANGES check
		else #correctsetting check
			echo_text_function "$CorrectText $file is correctly set to $correctsetting" "ON"
		fi #correctsetting check
	else #file existance check
		echo_text_function "$WarningText $file does not exist" "OFF"
	fi #file existance check
done


sysctlfile="/etc/sysctl.conf"
ssh_client_config="/etc/ssh/ssh_config"
sshd_config="/etc/ssh/sshd_config"
etc_resolv_conf="/etc/resolv.conf"
sshd_service="sshd"
logins_defs="/etc/login.defs"
sysconfig_init="/etc/sysconfig/init"
httpd_conf="/etc/httpd/conf/httpd.conf"
ssl_conf="/etc/httpd/conf.d/ssl.conf"
php_conf="/etc/php.ini"
rpmpkgslog_conf="/etc/logrotate.d/rpm"
network_conf="/etc/sysconfig/network"

#Configure some things
#format:
#filename,option,value,SeparatorOfOptionAndValueInConf,command_to_set_active_value,flag_for_command_to_set_active_value,service_to_reload,line_to_add_after,reason_for_change
Conf_LOOP=(
"$sysctlfile,net.ipv4.tcp_max_syn_backlog,4096,=,sysctl,-w,none,none,sysctl_tuning"
"$sysctlfile,net.ipv4.conf.all.rp_filter,1,=,sysctl,-w,none,none,sysctl_tuning"
"$sysctlfile,net.ipv4.conf.all.accept_source_route,0,=,sysctl,-w,none,none,sysctl_tuning"
"$sysctlfile,net.ipv4.conf.all.accept_redirects,0,=,sysctl,-w,none,none,sysctl_tuning"
"$sysctlfile,net.ipv4.conf.all.secure_redirects,0,=,sysctl,-w,none,none,sysctl_tuning"
"$sysctlfile,net.ipv4.conf.default.accept_redirects,0,=,sysctl,-w,none,none,sysctl_tuning"
"$sysctlfile,net.ipv4.conf.default.secure_redirects,0,=,sysctl,-w,none,none,sysctl_tuning"
"$sysctlfile,net.ipv4.conf.all.send_redirects,0,=,sysctl,-w,none,none,sysctl_tuning"
"$sysctlfile,net.ipv4.conf.default.send_redirects,0,=,sysctl,-w,none,none,sysctl_tuning"
"$sysctlfile,net.ipv4.tcp_syncookies,1,=,sysctl,-w,none,none,sysctl_tuning"
"$sysctlfile,net.ipv4.icmp_echo_ignore_broadcasts,1,=,sysctl,-w,none,none,sysctl_tuning"
"$sysctlfile,net.ipv4.icmp_ignore_bogus_error_responses,1,=,sysctl,-w,none,none,sysctl_tuning"
"$sysctlfile,net.ipv4.ip_forward,0,=,sysctl,-w,none,none,sysctl_tuning"
"$sysctlfile,net.ipv4.conf.all.log_martians,1,=,sysctl,-w,none,none,sysctl_tuning"
"$sysctlfile,net.ipv4.conf.default.rp_filter,1,=,sysctl,-w,none,none,sysctl_tuning"
"$sysctlfile,vm.swappiness,0,=,sysctl,-w,none,none,sysctl_tuning"
"$sysctlfile,kernel.randomize_va_space,2,=,sysctl,-w,none,none,sysctl_tuning"
"$sysctlfile,kernel.exec-shield,1,=,sysctl,-w,none,none,sysctl_tuning"
"$ssh_client_config,HashKnownHosts,yes, ,none,none,none,none,ssh_client_tuning"
"$ssh_client_config,RhostsAuthentication,no, ,none,none,none,none,ssh_client_tuning"
"$ssh_client_config,HostbasedAuthentication,no, ,none,none,none,none,ssh_client_tuning"
"$ssh_client_config,Protocol,2, ,none,none,none,none,ssh_client_tuning"
"$sshd_config,PrintLastLog,yes, ,none,none,$sshd_service,none,sshd_tuning"
"$sshd_config,Protocol,2, ,none,none,$sshd_service,none,sshd_tuning"
"$sshd_config,PermitRootLogin,no, ,none,none,$sshd_service,none,sshd_tuning"
"$sshd_config,LoginGraceTime,30, ,none,none,$sshd_service,none,sshd_tuning"
"$sshd_config,MaxAuthTries,2, ,none,none,$sshd_service,none,sshd_tuning"
"$sshd_config,PermitEmptyPasswords,no, ,none,none,$sshd_service,none,sshd_tuning"
"$sshd_config,HostbasedAuthentication,no, ,none,none,$sshd_service,none,sshd_tuning"
"$sshd_config,IgnoreRhosts,yes, ,none,none,$sshd_service,none,sshd_tuning"
"$sshd_config,MaxStartups,3, ,none,none,$sshd_service,^Subsystem,sshd_tuning"
"$sshd_config,AllowTcpForwarding,no, ,none,none,$sshd_service,^MaxAuthTries,sshd_tuning"
"$sshd_config,ClientAliveInterval,3600, ,none,none,$sshd_service,none,sshd_tuning"
"$sshd_config,ClientAliveCountMax,0, ,none,none,$sshd_service,none,sshd_tuning"
"$sshd_config,PermitUserEnvironment,no, ,none,none,$sshd_service,none,sshd_tuning"
"$sshd_config,Banner,/etc/issue, ,none,none,$sshd_service,^PermitUserEnvironment,sshd_tuning"
"$etc_resolv_conf,search,scranton.edu, ,none,none,none,none,set_default_dns_search"
"$logins_defs,PASS_MIN_LEN,14,\t,none,none,none,none,logins_defs_securing"
"$logins_defs,PASS_MIN_DAYS,1,\t,none,none,none,none,logins_defs_securing"
"$logins_defs,PASS_MAX_DAYS,60,\t,none,none,none,none,logins_defs_securing"
"$logins_defs,PASS_WARN_AGE,7,\t,none,none,none,none,logins_defs_securing"
"$logins_defs,ENCRYPT_METHOD,SHA512, ,none,none,none,none,logins_defs_securing"
"$sysconfig_init,PROMPT,no,=,none,none,none,none,sysconfig_securing"
"$httpd_conf,ServerSignature,Off, ,none,none,httpd,none,httpd_securing"
"$httpd_conf,ServerTokens,Prod, ,none,none,httpd,none,httpd_securing"
"$httpd_conf,TraceEnable,Off, ,none,none,httpd,none,httpd_securing"
"$httpd_conf,Header always append,SAMEORIGIN, X-Frame-Options ,none,none,httpd,none,click_jacking_protection"
"$ssl_conf,Header always add,\"max-age=15768000\", Strict-Transport-Security ,none,none,httpd,^SSLHonorCipherOrder,HSTS_enforcement"
"$ssl_conf,SSLProtocol,all -SSLv2 -SSLv3, ,none,none,httpd,none,ssl_secure_protocols"
"$ssl_conf,SSLCipherSuite,HIGH:!aNULL:!MD5:!EXP, ,none,none,httpd,^SSLProtocol,ssl_secure_ciphers"
"$ssl_conf,SSLHonorCipherOrder,on, ,none,none,httpd,^SSLCipherSuite,ssl_obey_server_ciphers"
"$php_conf,expose_php,off, = ,none,none,none,none,php_securing"
"$rpmpkgslog_conf,create 0640,root root,\t,none,none,syslog,weekly,correcting_default_file_perms"
"$network_conf,NOZEROCONF,yes,=,none,none,network,none,disabling_zeroconf"
)

#TODO - check for duplicate entries of the same option (especially with different values)
for i in "${Conf_LOOP[@]}"; do
	filename=$(echo "$i" | awk -F, '{print $1;}')
	option=$(echo "$i" | awk -F, '{print $2;}')
	value=$(echo "$i" | awk -F, '{print $3;}')
	separator=$(echo "$i" | awk -F, '{print $4;}')
	command_to_set_active_value=$(echo "$i" | awk -F, '{print $5;}')
	flag_to_set_active_value=$(echo "$i" | awk -F, '{print $6;}')
	servive_to_reload=$(echo "$i" | awk -F, '{print $7;}')
	textoflinetoaddafter=$(echo "$i" | awk -F, '{print $8;}')
	reason=$(echo "$i" | awk -F, '{print $9;}')
	
	if sudo stat "$filename" > /dev/null 2>&1; then #File Existance check
		#We pipe to tail -n1 because there is a current limitation that we can only check one instance of the option, so we check the last. 
		#"Usually" the last option is the one that is put into use. 
		#How do we deal with leading and trailing white spaces and tabs??????!!!?	
		currentsetting=$(sudo grep "^$option" "$filename" | tail -n1 | awk -F"$separator" '{$1=""; print $0}'| sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//')

		#Get the line number of the current setting.
		linenumofcurrentsetting=$(sudo grep -n "^$option" "$filename" | tail -n1 | grep -o '^[0-9]*')

		#check for additional occurrences
		if [[ "$(sudo grep -c "^$option" "$filename")" -gt "1" ]]; then
			echo_text_function "$WarningText There are multiple occurrences of $option in $filename - Only checking the last one" "WARNING"
		fi #Multiple occurrences check

		#Check to see if the option/value pair follow a specified line(if applicable) 
		LineToAddAfter=""
		#echo "Option = $option and textoflinetoaddafter=$textoflinetoaddafter"
		if [[ "$textoflinetoaddafter" != "none" ]]; then #Check to if there is a required line to add the value after 
			if sudo grep -q "$textoflinetoaddafter" "$filename"; then #Check if the required line exists 
				LineToAddAfter=$(sudo grep -n "$textoflinetoaddafter" "$filename" | tail -n1 | grep -o '^[0-9]*')
				#When we want to add the funtionality to add a value BEFORE a specified line, we can skip the following increment
				LineToAddAfter=$((LineToAddAfter+1))
				echo "============================== LineToAddAfter=$LineToAddAfter"
			fi	#Check if the required line exists
		fi #Check to if there is a required line to add the value after 
		
		if [[ "$currentsetting" != "$value" ]]; then #Check if current setting equals the desired value 
			if [[ -z "$currentsetting" ]]; then
				echo_text_function "$IncorrectText $option in $filename is not set, it should be $value" "OFF"
			else #currentsetting else 
				echo_text_function "$IncorrectText $option in $filename is set to $currentsetting, it should be $value" "OFF"
				#We may want to add some checking/notification of the placement here as well 
			fi #currentsetting end if 

			if [[ "$MAKECHANGES" -eq "$Yes" ]]; then #Make Changes        
				if [[ "$LineToAddAfter" -lt "2" ]]; then #Check to see if there was a required placement line and if it existed 
					MAKETHISCHANGE=$No
					echo_text_function "$WarningText We can not add $option to $filename becuase the required line of $textoflinetoaddafter does not exist" "WARNING"
					#We should set a flag to indicate that the script may need to rerun - the required line might be added with a later check
					MAYNEEDTOBERERUN=$Yes
				else #Check to see if there was a required placement line and if it existed
					interactive_check_function "Would you like to set $option to $value in $filename? [y/N]"
                fi #Check to see if there was a required placement line and if it existed

				if [[ "$MAKETHISCHANGE" -eq "$Yes" ]]; then #Check to see if we should make this specific change 
					if [[ "$TURNOFFBACKUPS" -eq "$No" ]]; then #Are Backsups turned off 
						#Generate a backup hash unique to each check
						BACKUPEXTENTION="$(date +"%m-%d-%Y-%H:%M:%S:%N")${option//[[:blank:]]/}"
					else #Are Backsups turned off 
						BACKUPEXTENTION=""
					fi ##Are Backsups turned off 
					
					if [[ "$currentsetting" != "" ]]; then #Check if the current setting is blank
						#Correct the existing value for the option
						execute_command_function "sudo sed -i$BACKUPEXTENTION '/^$option/s/$separator$currentsetting/$separator$value/gi' $filename" "sudo sed -i '/^$option/s/$separator$value/$separator$currentsetting/gi' $filename" "sudo mv $filename$BACKUPEXTENTION \$BACKUPFOLDER"
						echo_text_function "$ModificationText Changing existing entry - $option$separator$value in $filename" "CHANGED"
					else #Check if the current setting is blank
						if [[ "$LineToAddAfter" = "" ]]; then #Check if there is a line to add the option after 
							#Append the Option and Value to the conf file with the correct separator
							execute_command_function "sudo sed -i$BACKUPEXTENTION '\$a$option$separator$value' $filename" "sudo sed -i '/^$option$separator$value/d' $filename" "sudo mv $filename$BACKUPEXTENTION \$BACKUPFOLDER"
							echo_text_function "$ModificationText Adding new entry - $option$separator$value to $filename at the end of the file" "CHANGED"
						else #Check if there is a line to add the option after 
							#Insert the Option and Value to the conf file with the correct separator at the correct location
							execute_command_function "sudo sed -i$BACKUPEXTENTION '"$LineToAddAfter"i $option$separator$value' $filename" "sudo sed -i '/^$option$separator$value/d' $filename" "sudo mv $filename$BACKUPEXTENTION \$BACKUPFOLDER"
							echo_text_function "$ModificationText Adding new entry - $option$separator$value to $filename at line number $LineToAddAfter" "CHANGED"
						fi  #Check if there is a line to add the option after 
					fi #Check if the current setting is blank
					
					if [[ "$command_to_set_active_value" != "none" ]]; then #Check for a command to set active value
						execute_command_function "sudo $command_to_set_active_value $flag_to_set_active_value $option$separator$value > /dev/null" "sudo $command_to_set_active_value $flag_to_set_active_value $option$separator$currentsetting > /dev/null" ""
						echo_text_function "$ModificationText Making the new $option value active by running $command_to_set_active_value $flag_to_set_active_value $option$separator$value" "CHANGED"
					fi #Check for a command to set active value
					
					if [[ "$servive_to_reload" != "none" ]]; then #check if there is a service to reload 
						execute_command_function "sudo service $servive_to_reload reload > /dev/null" "sudo service $servive_to_reload reload > /dev/null" ""
						echo_text_function "$ModificationText Reloading the $servive_to_reload service" "CHANGED"
					fi #check if there is a service to reload 
				else #Check to see if we should make this specific change
					if [[ "$currentsetting" != "" ]]; then #Check if the current setting is blank 
						echo_text_function "$SkippedText $option left set to $currentsetting in $filename" "SKIPPED"
					else #Check if the current setting is blank
						echo_text_function "$SkippedText $option left unset in $filename" "SKIPPED"
					fi #Check if the current setting is blank
				fi #Check to see if we should make this specific change
			fi #MAKECHANGES check
		else #Check if current setting equals the desired value 
			if [[ "$textoflinetoaddafter" = "none" ]]; then	#Check if there is a required line to add after 
				#There is no required line to check for
				echo_text_function "$CorrectText $option has correct value of $value in $filename" "ON"
			else #Check if there is a required line to add after 
				if [[ "$LineToAddAfter" -eq "" ]]; then #Check if the required line to add after exists 
					#The required line that this option should follow does not exist
			        echo_text_function "$WarningText $option has correct value of $value in $filename but the required previous line of $textoflinetoaddafter is not present" "WARNING"	
				else #Check if the required line to add after exists 
					if [[ "$LineToAddAfter" -eq "$linenumofcurrentsetting" ]]; then #Check if existing line correctly follows the required line
				        echo_text_function "$CorrectText $option has correct value of $value in $filename and follows the corret line of $textoflinetoaddafter" "ON"
					else #Check if existing line correctly follows the required line
				        echo_text_function "$WarningText $option has correct value of $value in $filename but does not follow the correct line of $textoflinetoaddafter" "WARNING"
					fi #Check if existing line correctly follows the required line
				fi #Check if the required line to add after exists 
			fi #Check if there is a required line to add after 
		fi #currentsetting check
	else #File Existance check 
		echo_text_function "$WarningText $filename does not exist" "WARNING"
	fi #File Existance check 
done

#Service Check
#Format
#servicename,should it be on or off (uninstalled will also suffice),reason (for now the default reason is "security", I should make then more descriptive)
services_to_check=(
"abrtd,off,security"
"acpid,off,security"
"atd,off,security"
"autofs,off,V-38437"
"avahi-daemon,off,security"
"avahi-dnsconfd,off,security"
"bluetooth,off,security"
"cpuspeed,off,security"
"cups anacron,off,security"
"firstboot,off,security"
"gpm,off,security"
"haldeamon,off,security"
"hiddi,off,security"
"ip6tables,off,security"
"kudzu,off,security"
"mcstrans,off,security"
"mdmonitor,off,security"
"messagebus,off,security"
"netconsole,off,security"
"ntpdate,off,security"
"ntpd,off,security"
"oddjobd,off,security"
"pcscd,off,security"
"qpidd,off,security"
"rawdevices,off,security"
"rdisc,off,security"
"readahead_early,off,security"
"readahead_later,off,security"
"restorecond,off,security"
"rexecd,off,security"
"rhnsd,on,configuration"
"rlogind,off,security"
"rshd,off,security"
"smartd,off,security"
"telnet,off,security"
"tftp,off,security"
"vsftpd,off,security"
"ypbind,off,security"
"yum-updatesd,off,security"
"crond,on,security"
"iptables,on,security"
"webmin,off,security"
)

for i in "${services_to_check[@]}"; do
	servicename=$(echo "$i" | awk -F, '{print $1;}')
	correct_setting=$(echo "$i" | awk -F, '{print $2;}')
	reason=$(echo "$i" | awk -F, '{print $3;}')
	
	if sudo /sbin/chkconfig --list "$servicename" > /dev/null 2>&1; then #does the service exist check
		#If the service exists then we need to get its current start-up setting- Note we are only checking run level 3
		actual_setting=$(sudo /sbin/chkconfig --list "$servicename" | grep "3:" | awk '{print $5;}' | awk -F: '{print $2;}')
		if [[ "$correct_setting" = "$actual_setting" ]]; then # correct setting check
				echo_text_function "$CorrectText $servicename has the correct startup value of $actual_setting" "ON"
		else #correct setting check
			if sudo service "$servicename" status > /dev/null 2>&1; then #Is_Service_Running check
					Is_Service_Running=$Yes
			else #Is_Service_Running check
					Is_Service_Running=$No
			fi #Is_Service_Running check
			
			echo_text_function "$IncorrectText $servicename Should be set to $correct_setting at boot" "OFF"
			#Make Changes
			if [[ "$MAKECHANGES" -eq "$Yes" ]]; then #Check if we should make changes 
				interactive_check_function "Would you like to change $servicename's startup setting to $correct_setting [y/N]"
				if [[ "$MAKETHISCHANGE" -eq "$Yes" ]]; then #Check if we should make this specific change 
					echo_text_function "$ModificationText Changing $servicename's boot setting to $correct_setting" "CHANGE"
					execute_command_function "sudo /sbin/chkconfig $servicename $correct_setting" "sudo /sbin/chkconfig $servicename $actual_setting" ""

					#Stop the service if it was running and needs to be stopped
					#We can assume that if it was running it needs to be stopped because of the part of the "correct setting check" if block we are in 
					if [[ "$Is_Service_Running" = "$Yes" ]]; then #was service running check
						echo_text_function "$ModificationText Stopping $servicename because it was running" "CHANGE"
						execute_command_function "sudo service $servicename stop > /dev/null" "sudo service $servicename start > /dev/null" ""
					fi #was service running check

				else #Check if we should make this specific change
					echo_text_function "$SkippedText $servicename startup left set to $actual_setting" ""
				fi #Check if we should make this specific change
			fi #Check if we should make changes 
		fi #correct setting check

	else #does the service exist check
		if [[ "$correct_setting" = "on" ]]; then #check if the service should exist 
			echo_text_function "$IncorrectText $servicename is not installed and it needs to be running, future versions of this script might offer to install it for you" "OFF"
		else #check if the service should exist
			echo_text_function "$CorrectText $servicename is not installed and that is fine because it should not be running" "ON"	
		fi #check if the service should exist
	fi #does the service exist check
done


if [[ "$MAKECHANGES" -eq "$Yes" ]]; then #Last MAKECHANGES
	echo
        if sudo grep -q "sudo" "$PRESCRIBEFOLDER"/"$PRESCRIBECOMMANDFILE"; then #Check to see if there are any commands to run - Probably a better way to do this
		#Backups
		if [[ "$TURNOFFBACKUPS" -eq "$No" ]]; then #If we made backups, we need to deal with them	
			echo "echo BACKUPFOLDER used is \$BACKUPFOLDER" >> "$PRESCRIBEFOLDER/$PRESCRIBECOMMANDFILE"
		fi #TURNOFFBACKUPS check 
		
		if [[ "$PRESCRIBECOMMANDSONLY" -eq "$No" ]]; then #Check to see if we should actually run the commands based on PRESCRIBECOMMANDSONLY
			echo_text_function "Based on the PRESCRIBECOMMANDSONLY variable, we will run the following commands in $PRESCRIBEFOLDER/$PRESCRIBECOMMANDFILE"
			sudo cat "$PRESCRIBEFOLDER/$PRESCRIBECOMMANDFILE"
			# shellcheck source=/dev/null
			source "$PRESCRIBEFOLDER"/"$PRESCRIBECOMMANDFILE"
		else #Check to see if we should actually run the commands based on PRESCRIBECOMMANDSONLY
			echo_text_function "Based on the PRESCRIBECOMMANDSONLY variable, we will NOT run the following commands in $PRESCRIBEFOLDER/$PRESCRIBECOMMANDFILE"
			sudo cat "$PRESCRIBEFOLDER/$PRESCRIBECOMMANDFILE"
			echo
		fi #End check to see if we should actually run the commands based on PRESCRIBECOMMANDSONLY

		#Clean up Command list 
		sudo tar -zcf "$PRESCRIBEFOLDER".tar.gz "$PRESCRIBEFOLDER" > /dev/null 2>&1
		echo_text_function "Compressed the Prescribed commands to $PRESCRIBEFOLDER.tar.gz"
	else #Checking for any commands to run
		echo_text_function "The script didn't find anything to change"
		MAYNEEDTOBERERUN=$No	
	fi #End check of any commands to run
	
	#Undos
	if [[ -e "$UNDOFOLDER"/"$UNDOCOMMANDFILE" ]]; then 
		echo_text_function "Here are the commands to undo the changes if you made them:"
		sudo cat "$UNDOFOLDER/$UNDOCOMMANDFILE"
		sudo tar -zcf "$UNDOFOLDER".tar.gz "$UNDOFOLDER" > /dev/null 2>&1
		echo_text_function "Commands to undo changes are available in $UNDOFOLDER.tar.gz"
        fi #existence of  undo file check

	#Very rudimentary check and notififcation that we may need to run the script again 
        if [[ "$MAYNEEDTOBERERUN" -eq "$Yes" ]]; then
		 echo_text_function "We might need to run this script again because required lines may have been added"
	fi #MAYNEEDTOBERERUN Check
fi #Last MAKECHANGES
echo
exit $Success
