#!/bin/bash

#Normal Operation
OPERMODE=$1
#Example of hard coding argument for remote testing
#OPERMODE=audit-all

#Set the No/Yes Values for easier code reading
No=0
Yes=1

#Set Default value
INATERMINAL=0
#Check for a terminal
if [[ -t $Yes ]]; then
	INATERMINAL=$Yes
fi #End Terminal Check

#Set Exit Codes
Success=0
RootInNonTerminal=1
PermissionsNeeded=2
UsagePrint=3
TerminalNeededForInteractive=4
CommandsNeeded=10
UndeterminedOS=49
UnsupportedOS=50
FilevaluecheckError=51

#Set Text
WarningText="!!!Warning"
ModificationText="+++Changing"
IncorrectText="---Incorrect"
CorrectText="OK"
SkippedText="Skipped"
ErrorText="ERROR"

echo_text_function () {
	TextToEcho=$1
	
	echo "$TextToEcho"
}

#Command Check - "echo" is the only command we assume exists because we use it for the Command check announcement, it would be nice to run this through the echo_text_function at some point
#format
#command
commands_needed_array=(
echo
chmod
chown
grep
sed
service
stat
rpm
yum
awk
tail
sysctl
mktemp
tar
sudo
mv
date
)

for command in ${commands_needed_array[@]}
do
	hash $command 2>/dev/null || { echo "$ErrorText - This script requires $command but it's not available."; exit $CommandsNeeded;}
done

#Permissions and Path check - you should be running this script with a user
#that that has full sudo privs (non-root) but I'll tolerate running as root in a terminal
RootEUID=0
if [[ $EUID -eq $RootEUID ]]; then
   #Check for a terminal
    if [[ $INATERMINAL -eq $Yes ]]; then
		echo "Ok I'll let you run this as root in a terminal"
	else #INATERMINAL else
		echo "You really shouldn't be running as root in a non-terminal. Exiting"
		exit $RootInNonTerminal
	fi #End INATERMINAL check
else #EUID else
    #Check that the user has correct sudo privs - TODO: I should trim the white space
    #This could be done much better, for now I just want to encourage people to use sudo for its logging capabilites.
	sudo grep "^\$USER ALL = NOPASSWD: ALL$" /etc/sudoers > /dev/null
	if [[ $? -ne 0 ]]; then
		echo "You are running as a non-root user with the correct sudo privs."
	else #Status code else
		echo "You don't have the required permissions to run this check"
		exit $PermissionsNeeded
	fi #End Status code check
fi #End EUID Check


#Determine version of RedHat/Centos and if it is supported - TODO, get a better way to do this
if [[ -f /etc/redhat-release ]]; then
	grep -E "Red Hat|Centos" /etc/redhat-release > /dev/null
	if [[ $? -eq 0 ]]; then 
		grep "5." /etc/redhat-release > /dev/null
		if [[ $? -eq 0 ]]; then
			OSVER="5"
		fi 
		grep "6." /etc/redhat-release > /dev/null
		if [[ $? -eq 0 ]]; then
			OSVER="6"
		fi 
	fi 
	if [[ $OSVER = "" ]]; then 
		echo "$ErrorText Could not determine OS Version"
		exit $UndeterminedOS
	fi 
else 
	echo "$ErrorText You are using an unsupported OS. RedHat/Centos required"
	exit $UnsupportedOS
fi 
echo "OSVER is $OSVER - Supported"
	
#Set default values for configs and give explanations
ONNOTIFICATIONS=$No        #Should we notify things that are configured properly 
OFFNOTIFICATIONS=$No       #Should we notify things that aren't configured properly
NOTIFYCHANGES=$No          #Should we notify of changes 
MAKECHANGES=$No            #Should we make changes 
INTERACTIVECHANGES=$No     #Should we the user to make select what changes to make 

#We hard code the following options for safety, in the future we might allow changing via commnad line
TURNOFFBACKUPS=$No         #Should we turn off backups? 
PRESCRIBECOMMANDSONLY=$Yes #Do we only create a list of command to remediate the checks and run then later?  (No=run now,Yes=only create list)

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
	if [[ $INATERMINAL -eq $No ]]; then
		echo "$ErrorText - You need to be in a terminal to make interactive changes"
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
	echo "Usage: $0 audit|audit-on|audit-off|fix-quiet|fix-notify|interactive"
	echo
	echo "audit-all   - make no changes, notify status of all checks"
	echo "audit-on    - make no changes, notify status of only implemented checks"
	echo "audit-off   - make no changes, notify status of only non-implemented checks"
	echo "fix-quiet   - make changes, no notifications"
	echo "fix-notify  - make changes, with notifications of changes made"
	echo "interactive - step through each check, give status of all and prompt to fix (if needed)"
	echo
	exit $UsagePrint
esac

echo

if [[ $MAKECHANGES -eq $Yes ]]; then
	if [[ $TURNOFFBACKUPS -eq $No ]]; then
		#Create Directory for backups
		BACKUPFOLDER=$(mktemp -d)
		#Create file to store commands to undo changes
		UNDOCOMMANDFILE="undocommands.lis"
		#Prime the file 
		echo "#!/bin/bash" > $BACKUPFOLDER/$UNDOCOMMANDFILE
	fi #TURNOFFBACKUPS check 

	#Create Directory for Commands that should be run
	PRESCRIBEFOLDER=$(mktemp -d)
	#Create file to store commands that should be run
	PRESCRIBECOMMANDFILE="commandstorun.lis"
	#Prime the file 
	echo "#!/bin/bash" > $PRESCRIBEFOLDER/$PRESCRIBECOMMANDFILE
fi #MAKECHANGES Check

#Create a file to white list certain checks on hosts.
#Still in the works but we'll remove the white listed changes from the prescribed commands. 
##WHITELISTFILE="whitelist.lis"

#Define Functions 
execute_command_function () {
	CommandToExecute=$1
	CommandToUndo=$2
	
	#Add the Command to Execute to the "Prescibe Commands, at the end we decide if we should run these or not
	echo "$CommandToExecute" >> $PRESCRIBEFOLDER/$PRESCRIBECOMMANDFILE
	
	#Add the command to undo change
	if [[ $TURNOFFBACKUPS -eq $No ]]; then
		echo "$CommandToUndo" >> $BACKUPFOLDER/$UNDOCOMMANDFILE
	fi 
} 

interactive_check_function () {

	QuestionToDisplay=$1
	
	if [[ $INTERACTIVECHANGES -eq $Yes ]]; then
		while true; do
			read -p "$QuestionToDisplay" yn 
			case $yn in
				[Yy]* ) MAKETHISCHANGE=$Yes; break;;
				[Nn]* ) MAKETHISCHANGE=$No; break;;
				* ) echo "Please answer yes or no.";;
			esac
		done
	else
		MAKETHISCHANGE=$Yes
	fi #INTERACTIVE CHANGES Check
}


FILEPERMCHANGECOMMAND="chmod"
FILEOWNSHIPCHANGECOMMAND="chown"

#Correct File and folder permissions and ownership
#format
#operation,filename,correct value,reason
file_and_perm_array=(
"$FILEPERMCHANGECOMMAND,/etc/inittab,600,disable_gui_login"
"$FILEPERMCHANGECOMMAND,/etc/security/console.perms,600,disable_user_mounted_removable_file_systems"
"$FILEPERMCHANGECOMMAND,/var/log/dmesg,640,prevent_access_to_dmesg"
"$FILEPERMCHANGECOMMAND,/etc/sysctl.conf,600,secure_sysctl"
"$FILEPERMCHANGECOMMAND,/var/spool/cron/root,700,sec_for_root"
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
"$FILEPERMCHANGECOMMAND,/etc/gshadow,0000,secure_gshadow"
"$FILEPERMCHANGECOMMAND,/etc/shadow,0000,secure_shadow"
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
"$FILEOWNSHIPCHANGECOMMAND,/usr/lib,root:root,secure_usr_lib64"
"$FILEOWNSHIPCHANGECOMMAND,/boot/grub/grub.conf,root:root,secure_grub_conf"
)

for i in "${file_and_perm_array[@]}"
do
	operation=$(echo $i | awk -F, '{print $1;}')
	file=$(echo $i | awk -F, '{print $2;}')
	correctsetting=$(echo $i | awk -F, '{print $3;}')
	reason=$(echo $i | awk -F, '{print $4;}')
	#Check the file or directory exists
	if [[ -f $file ]] || [[ -d $file ]]; then
		if [[ $operation = "$FILEPERMCHANGECOMMAND" ]]; then #operation check
			filevaluecheck=$(sudo stat -c %a $file)
		elif [[ $operation = "$FILEOWNSHIPCHANGECOMMAND" ]]; then #operation check
			filevaluecheck=$(sudo stat -c %U:%G $file)
		else #operation check catch all 
		        echo_text_function "Error processing filevaluecheck it was set to $filevaluecheck"; exit $FilevaluecheckError
		fi #operation check
		
		if [[ "$filevaluecheck" != "$correctsetting" ]]; then
			if [[ $OFFNOTIFICATIONS -eq $Yes ]]; then
				echo_text_function "$IncorrectText $file is set to $filevaluecheck should be $correctsetting"
			fi #OFFNOTIFICATIONS check
			#Make Chages
			if [[ $MAKECHANGES -eq $Yes ]]; then
				interactive_check_function "Would you like to $operation $file to $correctsetting [y/n]"
				if [[ $MAKETHISCHANGE -eq $Yes ]]; then
					execute_command_function "sudo $operation $correctsetting $file" "sudo $operation $filevaluecheck $file"
					#Check to notify of changes
					echo_text_function "$ModificationText $operationed $file to $correctsetting to $reason"
				else #MAKETHISCHANGE else 
					echo_text_function "$SkippedText $file left set to $filevaluecheck"
				fi #MAKETHISCHANGE check
			fi #MAKECHANGES check
		else #correctsetting check
			if [[ $ONNOTIFICATIONS -eq $Yes ]]; then
				echo_text_function "$CorrectText $file is correctly set to $correctsetting"
			fi #ONNOTIFICATIONS check
		fi #correctsetting check
	else 
		if [[ $OFFNOTIFICATIONS -eq $Yes ]]; then
			echo_text_function "$WarningText $file does not exist"
		fi #OFFNOTIFICATIONS check
	fi #file existance check
done


sysctlfile="/etc/sysctl.conf"
ssh_client_config="/etc/ssh/ssh_config"
sshd_config="/etc/ssh/sshd_config"
etc_resolv_conf="/etc/resolv.conf"
sshd_service="sshd"
logins_defs="/etc/login.defs"
sysconfig_init="/etc/sysconfig/init"
system_auth="/etc/pam.d/system-auth"

#Configure some things
#format:
#filename,option,value,SeparatorOfOptionAndValueInConf,command_to_set_active_value,flag_for_command_to_set_active_value,service_to_reload,reason_for_change
Conf_LOOP=(
"$sysctlfile,net.ipv4.tcp_max_syn_backlog,4096,=,sysctl,-w,none,sysctl_tuning"
"$sysctlfile,net.ipv4.conf.all.rp_filter,1,=,sysctl,-w,none,sysctl_tuning"
"$sysctlfile,net.ipv4.conf.all.accept_source_route,0,=,sysctl,-w,none,sysctl_tuning"
"$sysctlfile,net.ipv4.conf.all.accept_redirects,0,=,sysctl,-w,none,sysctl_tuning"
"$sysctlfile,net.ipv4.conf.all.secure_redirects,0,=,sysctl,-w,none,sysctl_tuning"
"$sysctlfile,net.ipv4.conf.default.accept_redirects,0,=,sysctl,-w,none,sysctl_tuning"
"$sysctlfile,net.ipv4.conf.default.secure_redirects,0,=,sysctl,-w,none,sysctl_tuning"
"$sysctlfile,net.ipv4.conf.all.send_redirects,0,=,sysctl,-w,none,sysctl_tuning"
"$sysctlfile,net.ipv4.conf.default.send_redirects,0,=,sysctl,-w,none,sysctl_tuning"
"$sysctlfile,net.ipv4.tcp_syncookies,1,=,sysctl,-w,none,sysctl_tuning"
"$sysctlfile,net.ipv4.icmp_echo_ignore_broadcasts,1,=,sysctl,-w,none,sysctl_tuning"
"$sysctlfile,net.ipv4.icmp_ignore_bogus_error_responses,1,=,sysctl,-w,none,sysctl_tuning"
"$sysctlfile,net.ipv4.ip_forward,0,=,sysctl,-w,none,sysctl_tuning"
"$sysctlfile,net.ipv4.conf.all.log_martians,1,=,sysctl,-w,none,sysctl_tuning"
"$sysctlfile,net.ipv4.conf.default.rp_filter,1,=,sysctl,-w,none,sysctl_tuning"
"$sysctlfile,vm.swappiness,0,=,sysctl,-w,none,sysctl_tuning"
"$sysctlfile,kernel.randomize_va_space,2,=,sysctl,-w,none,sysctl_tuning"
"$sysctlfile,kernel.exec-shield,1,=,sysctl,-w,none,sysctl_tuning"
"$ssh_client_config,HashKnownHosts,yes, ,none,none,none,ssh_client_tuning"
"$ssh_client_config,RhostsAuthentication,no, ,none,none,none,ssh_client_tuning"
"$ssh_client_config,HostbasedAuthentication,no, ,none,none,none,ssh_client_tuning"
"$ssh_client_config,Protocol,2, ,none,none,none,ssh_client_tuning"
"$sshd_config,PrintLastLog,yes, ,none,none,$sshd_service,sshd_tuning"
"$sshd_config,Protocol,2, ,none,none,$sshd_service,sshd_tuning"
"$sshd_config,PermitRootLogin,no, ,none,none,$sshd_service,sshd_tuning"
"$sshd_config,LoginGraceTime,30, ,none,none,$sshd_service,sshd_tuning"
"$sshd_config,MaxAuthTries,2, ,none,none,$sshd_service,sshd_tuning"
"$sshd_config,PermitEmptyPasswords,no, ,none,none,$sshd_service,sshd_tuning"
"$sshd_config,HostbasedAuthentication,no, ,none,none,$sshd_service,sshd_tuning"
"$sshd_config,IgnoreRhosts,yes, ,none,none,$sshd_service,sshd_tuning"
"$sshd_config,MaxStartups,3, ,none,none,$sshd_service,sshd_tuning"
"$sshd_config,AllowTcpForwarding,no, ,none,none,$sshd_service,sshd_tuning"
"$sshd_config,ClientAliveInterval,3600, ,none,none,$sshd_service,sshd_tuning"
"$sshd_config,ClientAliveCountMax,0, ,none,none,$sshd_service,sshd_tuning"
"$sshd_config,PermitUserEnvironment,no, ,none,none,$sshd_service,sshd_tuning"
"$sshd_config,Banner,/etc/issue, ,none,none,$sshd_service,sshd_tuning"
"$etc_resolv_conf,search,scranton.edu, ,none,none,none,set_default_dns_search"
"$logins_defs,PASS_MIN_LEN,14, ,none,none,none,logins_defs_securing"
"$logins_defs,PASS_MIN_DAYS,1, ,none,none,none,logins_defs_securing"
"$logins_defs,PASS_MAX_DAYS,60, ,none,none,none,logins_defs_securing"
"$logins_defs,PASS_WARN_AGE,7, ,none,none,none,logins_defs_securing"
"$logins_defs,ENCRYPT_METHOD,SHA512, ,none,none,none,logins_defs_securing"
"$sysconfig_init,PROMPT,no,=,none,none,none,sysconfig_securing"
)

#TODO - check for duplicate entries of the same option (especially with different values)
for i in "${Conf_LOOP[@]}"
do
	filename=$(echo $i | awk -F, '{print $1;}')
	option=$(echo $i | awk -F, '{print $2;}')
	value=$(echo $i | awk -F, '{print $3;}')
	separator=$(echo $i | awk -F, '{print $4;}')
	command_to_set_active_value=$(echo $i | awk -F, '{print $5;}')
	flag_to_set_active_value=$(echo $i | awk -F, '{print $6;}')
	servive_to_reload=$(echo $i | awk -F, '{print $7;}')
	reason=$(echo $i | awk -F, '{print $8;}')
	
	if [[ -f $filename ]]; then
		
		currentsetting=$(sudo grep "^$option" $filename | tail -n1 | awk -F"$separator" '{print $2;}' | tr -d ' ')

		#check for additional occurrences
		if [[ $(sudo grep -c "^$option" $filename) -gt 1 ]]; then
			echo_text_function "$WarningText There are multiple occurrences of $option in $filename - Only checking the last one"
		fi #Multiple occurrences check
		
		if [[ "$currentsetting" != "$value" ]]; then
			if [[ -z "$currentsetting" ]]; then
				if [[ $OFFNOTIFICATIONS -eq $Yes ]]; then
					echo_text_function "$IncorrectText $option in $filename is not set, it should be $value"
				fi #OFFNOTIFICATIONS check
			else #currentsetting else 
				if [[ $OFFNOTIFICATIONS -eq $Yes ]]; then
					echo_text_function "$IncorrectText $option in $filename is set to $currentsetting, it should be $value"
				fi #OFFNOTIFICATIONS check 
			fi #currentsetting end if 
			#Make Changes
			if [[ $MAKECHANGES -eq $Yes ]]; then
			
				interactive_check_function "Would you like to set $option to $value in $filename? [y/n]"
				
				if [[ $MAKETHISCHANGE -eq $Yes ]]; then
					if [[ $TURNOFFBACKUPS -eq $No ]]; then
						#Generate a backup hash
						BACKUPEXTENTION="$(date +"%m-%d-%Y-%k:%M:%S:%N")$option"
					else 
						BACKUPEXTENTION=""
					fi 
					
					#Modify the current setting or add it
					if [[ "$currentsetting" != "" ]]; then
						#Correct the existing value for the option
						sudo sed -i$BACKUPEXTENTION "/^$option/s/$separator$currentsetting/$separator$value/gi" $filename
						echo_text_function "$ModificationText Changing existing entry - $option$separator$value in $filename"
					else #current setting blank check else
						#Append the Option and Value to the conf file with the correct separator
						sudo sed -i$BACKUPEXTENTION "\$a$option$separator$value" $filename
						echo_text_function "$ModificationText Adding new entry - $option$separator$value to $filename"
						
					fi #End current setting check
					if [[ $TURNOFFBACKUPS -eq $No ]]; then
						#Get the backup
						sudo mv $filename$BACKUPEXTENTION $BACKUPFOLDER
					fi
					
					if [[ $command_to_set_active_value != "none" ]]; then #If there is a need and way to set an active value, do it here
						#Set active value
						sudo $command_to_set_active_value $flag_to_set_active_value $option$separator$value > /dev/null
						if [[ $TURNOFFBACKUPS -eq $No ]]; then
							#Add the command to undo change
							echo "sudo $command_to_set_active_value $flag_to_set_active_value $option$separator$currentsetting" >> $BACKUPFOLDER/$UNDOCOMMANDFILE
						fi 
						echo_text_function "$ModificationText Making the new $option value active by running $command_to_set_active_value $flag_to_set_active_value $option$separator$value"
					fi #active value command check
					
					if [[ "$servive_to_reload" != "none" ]]; then
						#reload the appropriate service 
						sudo service $servive_to_reload reload > /dev/null
						echo_text_function "$ModificationText Reloaded the $servive_to_reload service" 
						if [[ $TURNOFFBACKUPS -eq $No ]]; then
							#Add the command to undo change
							echo "sudo service $servive_to_reload reload" >> $BACKUPFOLDER/$UNDOCOMMANDFILE
						fi
					fi #servive_to_reload
				else #MAKETHISCHANGE
					echo_text_function "$SkippedText $option left set to $value in $filename"
				fi #MAKETHISCHANGE check
			fi #MAKECHANGES check
		else #currentsetting else
			if [[ $ONNOTIFICATIONS -eq $Yes ]]; then
				echo_text_function "$CorrectText $option has correct value of $value in $filename"
			fi #ONNOTIFICATIONS check
		fi #currentsetting check
	else 
		if [[ $OFFNOTIFICATIONS -eq $Yes ]]; then
			echo_text_function "$WarningText $filename does not exist"
		fi #OFFNOTIFICATIONS check
	fi #File Existance check 
done


if [[ $MAKECHANGES -eq $Yes ]]; then
	echo
	
	#Check to see if we are actually suppose to run the commands 
	if [[ $PRESCRIBECOMMANDSONLY -eq $No ]]; then
		echo_text_function "Based on the PRESCRIBECOMMANDSONLY variable, we will run the following commands in $PRESCRIBEFOLDER/$PRESCRIBECOMMANDFILE"
		sudo cat $PRESCRIBEFOLDER/$PRESCRIBECOMMANDFILE
		sudo bash $PRESCRIBEFOLDER/$PRESCRIBECOMMANDFILE
	else
		echo_text_function "Based on the PRESCRIBECOMMANDSONLY variable, we will NOT run the following commands in $PRESCRIBEFOLDER/$PRESCRIBECOMMANDFILE"
		sudo cat $PRESCRIBEFOLDER/$PRESCRIBECOMMANDFILE
		echo
	fi #PRESCRIBECOMMANDSONLY check 

	#Clean up Command list 
	sudo tar -zcf $PRESCRIBEFOLDER.tar.gz $PRESCRIBEFOLDER > /dev/null 2>&1
	echo
	echo_text_function "Compressed the Prescribed commands to $PRESCRIBEFOLDER.tar.gz"
	echo
	
	#Backups
	if [[ $TURNOFFBACKUPS -eq $No ]]; then
		#We made backups so we need to deal with them
		echo_text_function "Here are the commands to undo the changes if you made them:"
		sudo cat $BACKUPFOLDER/$UNDOCOMMANDFILE
		echo
		#Compress the files
		sudo tar -zcf $BACKUPFOLDER.tar.gz $BACKUPFOLDER > /dev/null 2>&1
		echo_text_function "Backups of files that were changed and commands to undo changes are available in $BACKUPFOLDER.tar.gz"
	fi #TURNOFFBACKUPS check 
	
fi #MAKECHANGES check 

echo
exit $Success