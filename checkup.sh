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

#Set Ownership and Permissions on files/folders
file_and_perm_array=(
'{ "Operation": "chmod", "Filename": "/etc/inittab",                "Correct_Value": "600",       "Reason": "disable_gui_login" }'
'{ "Operation": "chmod", "Filename": "/etc/security/console.perms", "Correct_Value": "600",       "Reason": "disable_user_mounted_removable_file_systems" }'
'{ "Operation": "chmod", "Filename": "/var/log/dmesg",              "Correct_Value": "640",       "Reason": "prevent_access_to_dmesg" }'
'{ "Operation": "chmod", "Filename": "/etc/sysctl.conf",            "Correct_Value": "600",       "Reason": "secure_sysctl_conf" }'
'{ "Operation": "chmod", "Filename": "/root",                       "Correct_Value": "700",       "Reason": "secure_root_home_dir" }'
'{ "Operation": "chmod", "Filename": "/root/.tcshrc",               "Correct_Value": "400",       "Reason": "sec_for_root" }'
'{ "Operation": "chmod", "Filename": "/root/.bashrc",               "Correct_Value": "400",       "Reason": "secure_bashrc" }'
'{ "Operation": "chmod", "Filename": "/root/.cshrc",                "Correct_Value": "400",       "Reason": "secure_cshrc" }'
'{ "Operation": "chmod", "Filename": "/etc/csh.cshrc",              "Correct_Value": "444",       "Reason": "secure_csh.cshrc" }'
'{ "Operation": "chmod", "Filename": "/etc/bashrc",                 "Correct_Value": "444",       "Reason": "secure_bashrc" }'
'{ "Operation": "chmod", "Filename": "/var/log/wtmp",               "Correct_Value": "600",       "Reason": ",sec_logs" }'
'{ "Operation": "chmod", "Filename": "/var/log/lastlog",            "Correct_Value": "600",       "Reason": "sec_logs" }'
'{ "Operation": "chmod", "Filename": "/var/log/rpmpkgs",            "Correct_Value": "640",       "Reason": "sec_logs" }'
'{ "Operation": "chmod", "Filename": "/etc/securetty",              "Correct_Value": "400",       "Reason": "sec_console_login" }'
'{ "Operation": "chmod", "Filename": "/var/lib/nfs",                "Correct_Value": "750",       "Reason": "secure_nfs_folder" }'
'{ "Operation": "chmod", "Filename": "/etc/cups/cupsd.conf",        "Correct_Value": "600",       "Reason": "sec_cups" }'
'{ "Operation": "chmod", "Filename": "/etc/crontab",                "Correct_Value": "400",       "Reason": "secure_crontab" }'
'{ "Operation": "chmod", "Filename": "/etc/cron.allow",             "Correct_Value": "400",       "Reason": "secure_crontab" }'
'{ "Operation": "chmod", "Filename": "/etc/at.allow",               "Correct_Value": "400",       "Reason": "secure_at" }'
'{ "Operation": "chmod", "Filename": "/etc/mail/sendmail.cf",       "Correct_Value": "444",       "Reason": "secure_sendmail_conf" }'
'{ "Operation": "chmod", "Filename": "/var/log/sa",                 "Correct_Value": "600",       "Reason": "secure_sar_files" }'
'{ "Operation": "chmod", "Filename": "/var/spool/cron",             "Correct_Value": "600",       "Reason": "secure_cron" }'
'{ "Operation": "chmod", "Filename": "/etc/syslog.conf",            "Correct_Value": "640",       "Reason": "secure_syslog_conf" }'
'{ "Operation": "chmod", "Filename": "/etc/security/access.conf",   "Correct_Value": "640",       "Reason": "secure_access_conf" }'
'{ "Operation": "chmod", "Filename": "/var/spool/cron/root",        "Correct_Value": "600",       "Reason": "secure_root_crontab" }'
'{ "Operation": "chmod", "Filename": "/etc/gshadow",                "Correct_Value": "0",         "Reason": "secure_gshadow" }'
'{ "Operation": "chmod", "Filename": "/etc/shadow",                 "Correct_Value": "0",         "Reason": "secure_shadow" }'
'{ "Operation": "chmod", "Filename": "/etc/passwd",                 "Correct_Value": "644",       "Reason": "secure_etc_passwd" }'
'{ "Operation": "chmod", "Filename": "/etc/group",                  "Correct_Value": "644",       "Reason": "secure_etc_group" }'
'{ "Operation": "chmod", "Filename": "/boot/grub/grub.conf",        "Correct_Value": "600",       "Reason": "secure_grub_conf" }'
'{ "Operation": "chmod", "Filename": "/lib",                        "Correct_Value": "755",       "Reason": "secure_lib" }'
'{ "Operation": "chmod", "Filename": "/lib64",                      "Correct_Value": "755",       "Reason": "secure_lib64" }'
'{ "Operation": "chmod", "Filename": "/usr/lib",                    "Correct_Value": "755",       "Reason": "secure__usr_lib" }'
'{ "Operation": "chmod", "Filename": "/usr/lib64",                  "Correct_Value": "755",       "Reason": "secure__usr_lib64" }'
'{ "Operation": "chmod", "Filename": "/var/log/audit",              "Correct_Value": "750",       "Reason": "secure_audit_dir" }'
'{ "Operation": "chmod", "Filename": "/var/log/audit/audit.log",    "Correct_Value": "600",       "Reason": "secure_audit_log" }'
'{ "Operation": "chown", "Filename": "var/spool/cron/root",         "Correct_Value": "root:root", "Reason": "secure_root_crontab" }'
'{ "Operation": "chown", "Filename": "/var/log/btmp",               "Correct_Value": "root:root", "Reason": "secure_logs" }'
'{ "Operation": "chown", "Filename": "/etc/cups/cupsd.conf",        "Correct_Value": "lp:sys", "   Reason": "secure_cups_conf" }'
'{ "Operation": "chown", "Filename": "/etc/pam.d/atd",              "Correct_Value": "root:root", "Reason": "secure_pam_conf" }'
'{ "Operation": "chown", "Filename": "/etc/mail/sendmail.cf",       "Correct_Value": "root:bin",  "Reason": "secure_sendmail_conf" }'
'{ "Operation": "chown", "Filename": "/var/log/wtmp",               "Correct_Value": "root:root", "Reason": "secure_wtmp" }'
'{ "Operation": "chown", "Filename": "/etc/gshadow",                "Correct_Value": "root:root", "Reason": "secure_gshadow" }'
'{ "Operation": "chown", "Filename": "/etc/shadow",                 "Correct_Value": "root:root", "Reason": "secure_shadow" }'
'{ "Operation": "chown", "Filename": "/etc/passwd",                 "Correct_Value": "root:root", "Reason": "secure_passwd" }'
'{ "Operation": "chown", "Filename": "/var/log/audit/audit.log",    "Correct_Value": "root:root", "Reason": "secure_audit_log" }'
'{ "Operation": "chown", "Filename": "/etc/group",                  "Correct_Value": "root:root", "Reason": "secure_group_file" }'
'{ "Operation": "chown", "Filename": "/lib",                        "Correct_Value": "root:root", "Reason": "secure_lib" }'
'{ "Operation": "chown", "Filename": "/lib64",                      "Correct_Value": "root:root", "Reason": "secure_lib64" }'
'{ "Operation": "chown", "Filename": "/usr/lib",                    "Correct_Value": "root:root", "Reason": "secure_usr_lib" }'
'{ "Operation": "chown", "Filename": "/usr/lib64",                  "Correct_Value": "root:root", "Reason": "secure_usr_lib64" }'
'{ "Operation": "chown", "Filename": "/boot/grub/grub.conf",        "Correct_Value": "root:root", "Reason": "secure_grub_conf" }'
)

for i in "${file_and_perm_array[@]}"; do
        operation=$(echo "$i" | grep -Po '(?<="Operation": ")[^"]*')
        file=$(echo "$i" | grep -Po '(?<="Filename": ")[^"]*')
        correctsetting=$(echo "$i" | grep -Po '(?<="Correct_Value": ")[^"]*')
        reason=$(echo "$i" | grep -Po '(?<="Reason": ")[^"]*')

	if sudo stat "$file" > /dev/null 2>&1; then #Check the file or directory exists
		if [[ "$operation" = "chmod" ]]; then #operation check
			filevaluecheck=$(sudo stat -c %a "$file")
		elif [[ "$operation" = "chown" ]]; then #operation check
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

#Configure Options and Values in files
Conf_LOOP=(
'{ "Filename": "/etc/sysctl.conf",     "Option": "net.ipv4.tcp_max_syn_backlog",                "Value": "4096",   "Separator": "=",   "Command_To_Set_Active_Value":   "sysctl",  "Flag_To_Set_Active_Value": "-w",  "Service_To_Reload": "none",  "Line_To_Add_After": "none",  "Reason": "sysctl_tuning" }'
'{ "Filename": "/etc/sysctl.conf",     "Option": "net.ipv4.conf.all.rp_filter",                 "Value": "1",      "Separator": "=",   "Command_To_Set_Active_Value":   "sysctl",  "Flag_To_Set_Active_Value": "-w",   "Service_To_Reload": "none",  "Line_To_Add_After": "none",  "Reason": "sysctl_tuning" }'
'{ "Filename": "/etc/sysctl.conf",     "Option": "net.ipv4.conf.all.accept_source_route",       "Value": "0",      "Separator": "=",   "Command_To_Set_Active_Value":   "sysctl",  "Flag_To_Set_Active_Value": "-w",   "Service_To_Reload": "none",  "Line_To_Add_After": "none",  "Reason": "sysctl_tuning" }'
'{ "Filename": "/etc/sysctl.conf",     "Option": "net.ipv4.conf.all.accept_redirects",          "Value": "0",      "Separator": "=",   "Command_To_Set_Active_Value":   "sysctl",  "Flag_To_Set_Active_Value": "-w",   "Service_To_Reload": "none",  "Line_To_Add_After": "none",  "Reason": "sysctl_tuning" }'
'{ "Filename": "/etc/sysctl.conf",     "Option": "net.ipv4.conf.all.secure_redirects",          "Value": "0",      "Separator": "=",   "Command_To_Set_Active_Value":   "sysctl",  "Flag_To_Set_Active_Value": "-w",   "Service_To_Reload": "none",  "Line_To_Add_After": "none",  "Reason": "sysctl_tuning" }'
'{ "Filename": "/etc/sysctl.conf",     "Option": "net.ipv4.conf.default.accept_redirects",      "Value": "0",      "Separator": "=",   "Command_To_Set_Active_Value":   "sysctl",  "Flag_To_Set_Active_Value": "-w",   "Service_To_Reload": "none",  "Line_To_Add_After": "none",  "Reason": "sysctl_tuning" }'
'{ "Filename": "/etc/sysctl.conf",     "Option": "net.ipv4.conf.default.secure_redirects",      "Value": "0",      "Separator": "=",   "Command_To_Set_Active_Value":   "sysctl",  "Flag_To_Set_Active_Value": "-w",   "Service_To_Reload": "none",  "Line_To_Add_After": "none",  "Reason": "sysctl_tuning" }'
'{ "Filename": "/etc/sysctl.conf",     "Option": "net.ipv4.conf.all.send_redirects",            "Value": "0",      "Separator": "=",   "Command_To_Set_Active_Value":   "sysctl",  "Flag_To_Set_Active_Value": "-w",   "Service_To_Reload": "none",  "Line_To_Add_After": "none",  "Reason": "sysctl_tuning" }'
'{ "Filename": "/etc/sysctl.conf",     "Option": "net.ipv4.conf.default.send_redirects",        "Value": "0",      "Separator": "=",   "Command_To_Set_Active_Value":   "sysctl",  "Flag_To_Set_Active_Value": "-w",   "Service_To_Reload": "none",  "Line_To_Add_After": "none",  "Reason": "sysctl_tuning" }'
'{ "Filename": "/etc/sysctl.conf",     "Option": "net.ipv4.tcp_syncookies",                     "Value": "1",      "Separator": "=",   "Command_To_Set_Active_Value":   "sysctl",  "Flag_To_Set_Active_Value": "-w",   "Service_To_Reload": "none",  "Line_To_Add_After": "none",  "Reason": "sysctl_tuning" }'
'{ "Filename": "/etc/sysctl.conf",     "Option": "net.ipv4.icmp_echo_ignore_broadcasts",        "Value": "1",      "Separator": "=",   "Command_To_Set_Active_Value":   "sysctl",  "Flag_To_Set_Active_Value": "-w",   "Service_To_Reload": "none",  "Line_To_Add_After": "none",  "Reason": "sysctl_tuning" }'
'{ "Filename": "/etc/sysctl.conf",     "Option": "net.ipv4.icmp_ignore_bogus_error_responses",  "Value": "1",      "Separator": "=",   "Command_To_Set_Active_Value":   "sysctl",  "Flag_To_Set_Active_Value": "-w",   "Service_To_Reload": "none",  "Line_To_Add_After": "none",  "Reason": "sysctl_tuning" }'
'{ "Filename": "/etc/sysctl.conf",     "Option": "net.ipv4.ip_forward",                         "Value": "0",      "Separator": "=",   "Command_To_Set_Active_Value":   "sysctl",  "Flag_To_Set_Active_Value": "-w",   "Service_To_Reload": "none",  "Line_To_Add_After": "none",  "Reason": "sysctl_tuning" }'
'{ "Filename": "/etc/sysctl.conf",     "Option": "net.ipv4.conf.all.log_martians",              "Value": "1",      "Separator": "=",   "Command_To_Set_Active_Value":   "sysctl",  "Flag_To_Set_Active_Value": "-w",   "Service_To_Reload": "none",  "Line_To_Add_After": "none",  "Reason": "sysctl_tuning" }'
'{ "Filename": "/etc/sysctl.conf",     "Option": "net.ipv4.conf.default.rp_filter",             "Value": "1",      "Separator": "=",   "Command_To_Set_Active_Value":   "sysctl",  "Flag_To_Set_Active_Value": "-w",   "Service_To_Reload": "none",  "Line_To_Add_After": "none",  "Reason": "sysctl_tuning" }'
'{ "Filename": "/etc/sysctl.conf",     "Option": "vm.swappiness",                               "Value": "1",      "Separator": "=",   "Command_To_Set_Active_Value":   "sysctl",  "Flag_To_Set_Active_Value": "-w",   "Service_To_Reload": "none",  "Line_To_Add_After": "none",  "Reason": "sysctl_tuning" }'
'{ "Filename": "/etc/sysctl.conf",     "Option": "kernel.randomize_va_space",                   "Value": "2",      "Separator": "=",   "Command_To_Set_Active_Value":   "sysctl",  "Flag_To_Set_Active_Value": "-w",   "Service_To_Reload": "none",  "Line_To_Add_After": "none",  "Reason": "sysctl_tuning" }'
'{ "Filename": "/etc/sysctl.conf",     "Option": "kernel.exec-shield",                          "Value": "1",      "Separator": "=",   "Command_To_Set_Active_Value":   "sysctl",  "Flag_To_Set_Active_Value": "-w",   "Service_To_Reload": "none",  "Line_To_Add_After": "none",  "Reason": "sysctl_tuning" }'
'{ "Filename": "/etc/ssh/ssh_config",  "Option": "HashKnownHosts",                              "Value": "yes",    "Separator": " ",   "Command_To_Set_Active_Value":   "none",    "Flag_To_Set_Active_Value": "none", "Service_To_Reload": "none",  "Line_To_Add_After": "none",  "Reason": "ssh_client_tuning" }'
'{ "Filename": "/etc/ssh/ssh_config",  "Option": "RhostsAuthentication",                        "Value": "no",     "Separator": " ",   "Command_To_Set_Active_Value":   "none",    "Flag_To_Set_Active_Value": "none", "Service_To_Reload": "none",  "Line_To_Add_After": "none",  "Reason": "ssh_client_tuning" }'
'{ "Filename": "/etc/ssh/ssh_config",  "Option": "HostbasedAuthentication",                     "Value": "no",     "Separator": " ",   "Command_To_Set_Active_Value":   "none",    "Flag_To_Set_Active_Value": "none", "Service_To_Reload": "none",  "Line_To_Add_After": "none",  "Reason": "ssh_client_tuning" }'
'{ "Filename": "/etc/ssh/ssh_config",  "Option": "Protocol",                                    "Value": "2",      "Separator": " ",   "Command_To_Set_Active_Value":   "none",    "Flag_To_Set_Active_Value": "none", "Service_To_Reload": "none",  "Line_To_Add_After": "none",  "Reason": "ssh_client_tuning" }'
'{ "Filename": "/etc/ssh/sshd_config",  "Option": "Protocol",                                   "Value": "2",      "Separator": " ",   "Command_To_Set_Active_Value":   "none",    "Flag_To_Set_Active_Value": "none", "Service_To_Reload": "sshd",  "Line_To_Add_After": "none",  "Reason": "sshd_tuning" }'
'{ "Filename": "/etc/ssh/sshd_config",  "Option": "PrintLastLog",                               "Value": "yes"     "Separator": " ",   "Command_To_Set_Active_Value":   "none",    "Flag_To_Set_Active_Value": "none", "Service_To_Reload": "sshd",  "Line_To_Add_After": "none",  "Reason": "sshd_tuning" }'
'{ "Filename": "/etc/ssh/sshd_config",  "Option": "PermitRootLogin",                            "Value": "no",     "Separator": " ",   "Command_To_Set_Active_Value":   "none",    "Flag_To_Set_Active_Value": "none", "Service_To_Reload": "sshd",  "Line_To_Add_After": "none",  "Reason": "sshd_tuning" }'
'{ "Filename": "/etc/ssh/sshd_config",  "Option": "LoginGraceTime",                             "Value": "30",     "Separator": " ",   "Command_To_Set_Active_Value":   "none",    "Flag_To_Set_Active_Value": "none", "Service_To_Reload": "sshd",  "Line_To_Add_After": "none",  "Reason": "sshd_tuning" }'
'{ "Filename": "/etc/ssh/sshd_config",  "Option": "MaxAuthTries",                               "Value": "2",      "Separator": " ",   "Command_To_Set_Active_Value":   "none",    "Flag_To_Set_Active_Value": "none", "Service_To_Reload": "sshd",  "Line_To_Add_After": "none",  "Reason": "sshd_tuning" }'
'{ "Filename": "/etc/ssh/sshd_config",  "Option": "PermitEmptyPasswords",                       "Value": "no",     "Separator": " ",   "Command_To_Set_Active_Value":   "none",    "Flag_To_Set_Active_Value": "none", "Service_To_Reload": "sshd",  "Line_To_Add_After": "none",  "Reason": "sshd_tuning" }'
'{ "Filename": "/etc/ssh/sshd_config",  "Option": "HostbasedAuthentication",                    "Value": "no",     "Separator": " ",   "Command_To_Set_Active_Value":   "none",    "Flag_To_Set_Active_Value": "none", "Service_To_Reload": "sshd",  "Line_To_Add_After": "none",  "Reason": "sshd_tuning" }'
'{ "Filename": "/etc/ssh/sshd_config",  "Option": "IgnoreRhosts",                               "Value": "yes",    "Separator": " ",   "Command_To_Set_Active_Value":   "none",    "Flag_To_Set_Active_Value": "none", "Service_To_Reload": "sshd",  "Line_To_Add_After": "none",  "Reason": "sshd_tuning" }'
'{ "Filename": "/etc/ssh/sshd_config",  "Option": "MaxStartups",                                "Value": "3",      "Separator": " ",   "Command_To_Set_Active_Value":   "none",    "Flag_To_Set_Active_Value": "none", "Service_To_Reload": "sshd",  "Line_To_Add_After": "none",  "Reason": "sshd_tuning" }'
'{ "Filename": "/etc/ssh/sshd_config",  "Option": "AllowTcpForwarding",                         "Value": "no",     "Separator": " ",   "Command_To_Set_Active_Value":   "none",    "Flag_To_Set_Active_Value": "none", "Service_To_Reload": "sshd",  "Line_To_Add_After": "none",  "Reason": "sshd_tuning" }'
'{ "Filename": "/etc/ssh/sshd_config",  "Option": "ClientAliveInterval",                        "Value": "3600",   "Separator": " ",   "Command_To_Set_Active_Value":   "none",    "Flag_To_Set_Active_Value": "none", "Service_To_Reload": "sshd",  "Line_To_Add_After": "none",  "Reason": "sshd_tuning" }'
'{ "Filename": "/etc/ssh/sshd_config",  "Option": "ClientAliveCountMax",                        "Value": "0",      "Separator": " ",   "Command_To_Set_Active_Value":   "none",    "Flag_To_Set_Active_Value": "none", "Service_To_Reload": "sshd",  "Line_To_Add_After": "none",  "Reason": "sshd_tuning" }'
'{ "Filename": "/etc/ssh/sshd_config",  "Option": "PermitUserEnvironment",                      "Value": "no",     "Separator": " ",   "Command_To_Set_Active_Value":   "none",    "Flag_To_Set_Active_Value": "none", "Service_To_Reload": "sshd",  "Line_To_Add_After": "none",  "Reason": "sshd_tuning" }'
'{ "Filename": "/etc/ssh/sshd_config",  "Option": "Banner",                                     "Value": "/etc/issue",      "Separator": " ",   "Command_To_Set_Active_Value":   "none",    "Flag_To_Set_Active_Value": "none", "Service_To_Reload": "sshd",  "Line_To_Add_After": "none",  "Reason": "sshd_tuning" }'
'{ "Filename": "/etc/ssh/sshd_config",  "Option": "Ciphers",                                    "Value": "aes128-ctr,aes192-ctr,aes256-ctr,arcfour256,arcfour128,arcfour",      "Separator": " ",   "Command_To_Set_Active_Value":   "none",    "Flag_To_Set_Active_Value": "none", "Service_To_Reload": "sshd",  "Line_To_Add_After": "none",  "Reason": "sshd_tuning" }'
'{ "Filename": "/etc/ssh/sshd_config",  "Option": "MACs",                                       "Value": "hmac-sha1,hmac-ripemd160",      "Separator": " ",   "Command_To_Set_Active_Value":   "none",    "Flag_To_Set_Active_Value": "none", "Service_To_Reload": "sshd",  "Line_To_Add_After": "none",  "Reason": "sshd_tuning" }'
'{ "Filename": "/etc/sysconfig/selinux",  "Option": "SELINUX",                                  "Value": "disabled",      "Separator": "=",   "Command_To_Set_Active_Value":   "none",    "Flag_To_Set_Active_Value": "none", "Service_To_Reload": "none",  "Line_To_Add_After": "none",  "Reason": "SELINUX" }'
'{ "Filename": "/etc/login.defs",  "Option": "PASS_MIN_LEN",                                    "Value": "14",      "Separator": "\t",   "Command_To_Set_Active_Value":   "none",    "Flag_To_Set_Active_Value": "none", "Service_To_Reload": "none",  "Line_To_Add_After": "none",  "Reason": "logins_defs_securing" }'
'{ "Filename": "/etc/login.defs",  "Option": "PASS_MIN_DAYS",                                   "Value": "1",       "Separator": "\t",   "Command_To_Set_Active_Value":   "none",    "Flag_To_Set_Active_Value": "none", "Service_To_Reload": "none",  "Line_To_Add_After": "none",  "Reason": "logins_defs_securing" }'
'{ "Filename": "/etc/login.defs",  "Option": "PASS_MAX_DAYS",                                   "Value": "60",      "Separator": "\t",   "Command_To_Set_Active_Value":   "none",    "Flag_To_Set_Active_Value": "none", "Service_To_Reload": "none",  "Line_To_Add_After": "none",  "Reason": "logins_defs_securing" }'
'{ "Filename": "/etc/login.defs",  "Option": "PASS_WARN_AGE",                                   "Value": "7",       "Separator": "\t",   "Command_To_Set_Active_Value":   "none",    "Flag_To_Set_Active_Value": "none", "Service_To_Reload": "none",  "Line_To_Add_After": "none",  "Reason": "logins_defs_securing" }'
'{ "Filename": "/etc/login.defs",  "Option": "ENCRYPT_METHOD",                                  "Value": "SHA512",  "Separator": "\t",   "Command_To_Set_Active_Value":   "none",    "Flag_To_Set_Active_Value": "none", "Service_To_Reload": "none",  "Line_To_Add_After": "none",  "Reason": "logins_defs_securing" }'
'{ "Filename": "/etc/httpd/conf/httpd.conf",  "Option": "ServerSignature",                      "Value": "Off",      "Separator": " ",   "Command_To_Set_Active_Value":   "none",    "Flag_To_Set_Active_Value": "none", "Service_To_Reload": "httpd",  "Line_To_Add_After": "none",  "Reason": "httpd_securing" }'
'{ "Filename": "/etc/httpd/conf/httpd.conf",  "Option": "ServerTokens",                         "Value": "Prod",      "Separator": " ",   "Command_To_Set_Active_Value":   "none",    "Flag_To_Set_Active_Value": "none", "Service_To_Reload": "httpd",  "Line_To_Add_After": "none",  "Reason": "httpd_securing" }'
'{ "Filename": "/etc/httpd/conf/httpd.conf",  "Option": "TraceEnable",                          "Value": "Off",      "Separator": " ",   "Command_To_Set_Active_Value":   "none",    "Flag_To_Set_Active_Value": "none", "Service_To_Reload": "httpd",  "Line_To_Add_After": "none",  "Reason": "httpd_securing" }'
'{ "Filename": "/etc/httpd/conf/httpd.conf",  "Option": "Header always append",                 "Value": "SAMEORIGIN",      "Separator": " X-Frame-Options ",   "Command_To_Set_Active_Value":   "none",    "Flag_To_Set_Active_Value": "none", "Service_To_Reload": "httpd",  "Line_To_Add_After": "none",  "Reason": "click_jacking_protection" }'
'{ "Filename": "/etc/httpd/conf.d/ssl.conf",  "Option": "SSLProtocol",                          "Value": "all -SSLv2 -SSLv3",      "Separator": " ",   "Command_To_Set_Active_Value":   "none",    "Flag_To_Set_Active_Value": "none", "Service_To_Reload": "httpd",  "Line_To_Add_After": "none",  "Reason": "ssl_secure_protocols" }'
'{ "Filename": "/etc/sysconfig/network",  "Option": "NOZEROCONF",                          "Value": "yes",      "Separator": "=",   "Command_To_Set_Active_Value":   "none",    "Flag_To_Set_Active_Value": "none", "Service_To_Reload": "network",  "Line_To_Add_After": "none",  "Reason": "disabling_zeroconf" }'
'{ "Filename": "/etc/php.ini",  "Option": "expose_php",                          "Value": "off",      "Separator": " = ",   "Command_To_Set_Active_Value":   "none",    "Flag_To_Set_Active_Value": "none", "Service_To_Reload": "none",  "Line_To_Add_After": "none",  "Reason": "php_securing" }'
'{ "Filename": "/etc/php.ini",  "Option": "enable_dl",                           "Value": "Off",      "Separator": " = ",   "Command_To_Set_Active_Value":   "none",    "Flag_To_Set_Active_Value": "none", "Service_To_Reload": "none",  "Line_To_Add_After": "none",  "Reason": "php_securing" }'
'{ "Filename": "/etc/php.ini",  "Option": "allow_url_fopen",                     "Value": "Off",      "Separator": " = ",   "Command_To_Set_Active_Value":   "none",    "Flag_To_Set_Active_Value": "none", "Service_To_Reload": "none",  "Line_To_Add_After": "none",  "Reason": "php_securing" }'
'{ "Filename": "/etc/php.ini",  "Option": "allow_url_include",                   "Value": "Off",      "Separator": " = ",   "Command_To_Set_Active_Value":   "none",    "Flag_To_Set_Active_Value": "none", "Service_To_Reload": "none",  "Line_To_Add_After": "none",  "Reason": "php_securing" }'
'{ "Filename": "/etc/sysconfig/init",  "Option": "PROMPT",                   "Value": "no",      "Separator": "=",   "Command_To_Set_Active_Value":   "none",    "Flag_To_Set_Active_Value": "none", "Service_To_Reload": "none",  "Line_To_Add_After": "none",  "Reason": "sysconfig_securing" }'
'{ "Filename": "/etc/logrotate.d/rpm",  "Option": "create 0640",                   "Value": "root root",      "Separator": "\t",   "Command_To_Set_Active_Value":   "none",    "Flag_To_Set_Active_Value": "none", "Service_To_Reload": "none",  "Line_To_Add_After": "none",  "Reason": "sysconfig_securing" }'
)

#TODO - check for duplicate entries of the same option (especially with different values)
for i in "${Conf_LOOP[@]}"; do

	filename=$(echo "$i" | grep -Po '(?<="Filename": ")[^"]*')
	option=$(echo "$i" | grep -Po '(?<="Option": ")[^"]*')
	value=$(echo "$i" | grep -Po '(?<="Value": ")[^"]*')
	separator=$(echo "$i" | grep -Po '(?<="Separator": ")[^"]*')
	command_to_set_active_value=$(echo "$i" | grep -Po '(?<="Command_To_Set_Active_Value": ")[^"]*')
	flag_to_set_active_value=$(echo "$i" | grep -Po '(?<="Flag_To_Set_Active_Value": ")[^"]*')
	servive_to_reload=$(echo "$i" | grep -Po '(?<="Service_To_Reload": ")[^"]*')
	textoflinetoaddafter=$(echo "$i" | grep -Po '(?<="Line_To_Add_After": ")[^"]*')
	reason=$(echo "$i" | grep -Po '(?<="Reason": ")[^"]*')
	
	if sudo stat "$filename" > /dev/null 2>&1; then #File Existance check
		#We pipe to tail -n1 because there is a current limitation that we can only check one instance of the option, so we check the last. 
		#"Usually" the last option is the one that is put into use. 
		#How do we deal with leading and trailing white spaces and tabs??????!!!?	
		currentsetting=$(sudo grep "^$option" "$filename" | tail -n1 | awk -F"$separator" '{$1=""; print $0}'| sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//')

		#Get the line number of the current setting.
		linenumofcurrentsetting=$(sudo grep -n "^$option" "$filename" | tail -n1 | grep -o '^[0-9]*')

		#check for additional occurrences and warn
		if [[ "$(sudo grep -c "^$option" "$filename")" -gt "1" ]]; then
			echo_text_function "$WarningText There are multiple occurrences of $option in $filename - Only checking the last one" "WARNING"
		fi #Multiple occurrences check

		#Check to see if the option/value pair follow a specified line(if applicable) 
		LineNumberToAddAfter=""
		REQUIREDLINENOTFOUND=$No
		#echo "Option = $option and textoflinetoaddafter=$textoflinetoaddafter"
		if [[ "$textoflinetoaddafter" != "none" ]]; then #Check to if there is a required line to add the value after 
			if sudo grep -q "$textoflinetoaddafter" "$filename"; then #Check if the required line exists 
				LineNumberToAddAfter=$(sudo grep -n "$textoflinetoaddafter" "$filename" | tail -n1 | grep -o '^[0-9]*')
				#When we want to add the funtionality to add a value BEFORE a specified line, we can skip the following increment
				LineNumberToAddAfter=$((LineNumberToAddAfter+1))
			else #Check to if there is a required line to add the value after
				#There was a required line and it was not found in the file	
				REQUIREDLINENOTFOUND=$Yes
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
				if [[ "$REQUIREDLINENOTFOUND" -eq "$Yes" ]]; then #Check to see if there was a required placement line and if it existed 
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
						if [[ "$LineNumberToAddAfter" = "" ]]; then #Check if there is a line to add the option after 
							#Append the Option and Value to the conf file with the correct separator
							execute_command_function "sudo sed -i$BACKUPEXTENTION '\$a$option$separator$value' $filename" "sudo sed -i '/^$option$separator$value/d' $filename" "sudo mv $filename$BACKUPEXTENTION \$BACKUPFOLDER"
							echo_text_function "$ModificationText Adding new entry - $option$separator$value to $filename at the end of the file" "CHANGED"
						else #Check if there is a line to add the option after 
							#Insert the Option and Value to the conf file with the correct separator at the correct location
							execute_command_function "sudo sed -i$BACKUPEXTENTION '"$LineNumberToAddAfter"i $option$separator$value' $filename" "sudo sed -i '/^$option$separator$value/d' $filename" "sudo mv $filename$BACKUPEXTENTION \$BACKUPFOLDER"
							echo_text_function "$ModificationText Adding new entry - $option$separator$value to $filename at line number $LineNumberToAddAfter" "CHANGED"
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
				if [[ "$LineNumberToAddAfter" -eq "" ]]; then #Check if the required line to add after exists 
					#The required line that this option should follow does not exist
			        echo_text_function "$WarningText $option has correct value of $value in $filename but the required previous line of $textoflinetoaddafter is not present" "WARNING"	
				else #Check if the required line to add after exists 
					if [[ "$LineNumberToAddAfter" -eq "$linenumofcurrentsetting" ]]; then #Check if existing line correctly follows the required line
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
services_to_check=(
'{ "servicename": "abrtd",           "preferredstatus": "off", "reason": "security"  }'
'{ "servicename": "acpid",           "preferredstatus": "off", "reason": "security"  }'
'{ "servicename": "atd",             "preferredstatus": "off", "reason": "security"  }'
'{ "servicename": "autofs",          "preferredstatus": "off", "reason": "V-38437"  }'
'{ "servicename": "avahi-daemon",    "preferredstatus": "off", "reason": "security"  }'
'{ "servicename": "avahi-dnsconfd",  "preferredstatus": "off", "reason": "security"  }'
'{ "servicename": "bluetooth",       "preferredstatus": "off", "reason": "security"  }'
'{ "servicename": "cpuspeed",        "preferredstatus": "off", "reason": "security"  }'
'{ "servicename": "cups",            "preferredstatus": "off", "reason": "security"  }'
'{ "servicename": "firstboot",       "preferredstatus": "off", "reason": "security"  }'
'{ "servicename": "gpm",             "preferredstatus": "off", "reason": "security"  }'
'{ "servicename": "haldeamon",       "preferredstatus": "off", "reason": "security"  }'
'{ "servicename": "hiddi",           "preferredstatus": "off", "reason": "security"  }'
'{ "servicename": "ip6tables",       "preferredstatus": "off", "reason": "security"  }'
'{ "servicename": "kudzu",           "preferredstatus": "off", "reason": "security"  }'
'{ "servicename": "mcstrans",        "preferredstatus": "off", "reason": "security"  }'
'{ "servicename": "mdmonitor",       "preferredstatus": "off", "reason": "security"  }'
'{ "servicename": "messagebus",      "preferredstatus": "off", "reason": "security"  }'
'{ "servicename": "netconsole",      "preferredstatus": "off", "reason": "security"  }'
'{ "servicename": "ntpdate",         "preferredstatus": "off", "reason": "security"  }'
'{ "servicename": "ntpd",            "preferredstatus": "off", "reason": "security"  }'
'{ "servicename": "oddjobd",         "preferredstatus": "off", "reason": "security"  }'
'{ "servicename": "pcscd",           "preferredstatus": "off", "reason": "security"  }'
'{ "servicename": "qpidd",           "preferredstatus": "off", "reason": "security"  }'
'{ "servicename": "rawdevices",      "preferredstatus": "off", "reason": "security"  }'
'{ "servicename": "rdisc",           "preferredstatus": "off", "reason": "security"  }'
'{ "servicename": "readahead_early", "preferredstatus": "off", "reason": "security"  }'
'{ "servicename": "readahead_later", "preferredstatus": "off", "reason": "security"  }'
'{ "servicename": "restorecond",     "preferredstatus": "off", "reason": "security"  }'
'{ "servicename": "rexecd",          "preferredstatus": "off", "reason": "security"  }'
'{ "servicename": "rhnsd",           "preferredstatus": "on",  "reason": "security"  }'
'{ "servicename": "rlogind",         "preferredstatus": "off", "reason": "security"  }'
'{ "servicename": "rshd",            "preferredstatus": "off", "reason": "security"  }'
'{ "servicename": "smartd",          "preferredstatus": "off", "reason": "security"  }'
'{ "servicename": "telnet",          "preferredstatus": "off", "reason": "security"  }'
'{ "servicename": "tftp",            "preferredstatus": "off", "reason": "security"  }'
'{ "servicename": "vsftpd",          "preferredstatus": "off", "reason": "security"  }'
'{ "servicename": "ypbind",          "preferredstatus": "off", "reason": "security"  }'
'{ "servicename": "yum-updatesd",    "preferredstatus": "off", "reason": "security"  }'
'{ "servicename": "crond",           "preferredstatus": "on",  "reason": "security"  }'
'{ "servicename": "iptables",        "preferredstatus": "on",  "reason": "security"  }'
'{ "servicename": "webmin",          "preferredstatus": "off", "reason": "security"  }'
)

for i in "${services_to_check[@]}"; do
        servicename=$(echo "$i" | grep -Po '(?<="servicename": ")[^"]*') 
        correct_setting=$(echo "$i" | grep -Po '(?<="preferredstatus": ")[^"]*') 
        reason=$(echo "$i" | grep -Po '(?<="reason": ")[^"]*') 

	
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
