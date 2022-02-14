#!/bin/bash
#
# Script to dirbuster when behind a slow or staging target
# Made by FM
#
# Examples:
# - ./dirscan.sh -w site.com -l /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt
######################################################################################
# Help function
Help() 
{
	# Display help
	echo "Syntax: script [-h|-w|-l|-t|-s|-o|-e]"
	echo
	echo "options:"
	echo "-h    Show this help."
	echo "-w    Set host website. Example: -w https://www.google.com/"
	echo "-l    Set fuzzing list. Example: -l /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt"
	echo "-t    Set sleep time in seconds. Example: -t 10"
	echo "-s    Set filter status codes. Example: -s 200,301,302"
	echo "-o    Set output filename. Example: -o results.txt"
	echo "-e    Set searchable extensions. Example: -e php,html,js"
	echo
}
######################################################################################
# Set mandatory variables
seconds=0

######################################################################################
# Get options
while getopts ":w:l:t:s:o:e:h" option; do
	case $option in
		w) # set host website
			host=$OPTARG;;
		l) # set fuzzing list
			file=$OPTARG;;
		t) # set sleep time
			seconds=$OPTARG;;
		s) # set filter status codes
			scodes=$OPTARG;;
		o) # set output filename
			output=$OPTARG;;
		e) # set searchable extensions
			extensions=$OPTARG;;
		h) # display help
			Help
			exit 1;;
		\?) # invalid option
			Help
			exit 1;;
	esac
done

######################################################################################
Request() 
{
	response="`curl -o /dev/null -s -w "%{http_code}\n" $site 2>&1`"
	if [[ $scodes == "" ]]; then
		echo "[+]" $response "|" $site
		if [[ ! $output == "" ]]; then
			echo "[+]" $response "|" $site >> $output
		fi
	else
		if [[ " ${codes[*]} " =~ " ${response} " ]]; then
			echo "[+]" $response "|" $site
			if [[ ! $output == "" ]]; then
				echo "[+]" $response "|" $site >> $output
			fi
		fi
	fi
	sleep $seconds
}

######################################################################################
# Website fuzzing scan
Scan() 
{
	lines=$(cat $file | egrep -v "(^#.*|^$)")
	if [[ ! $scodes == "" ]]; then
		echo "[*] Showing only status codes: " $scodes
		codes=(`echo $scodes | tr ',' ' '`)
	fi
	if [[ ! $extensions == "" ]]; then
		echo "[*] Looking for the following extensions: " $extensions
		ext=(`echo $extensions | tr ',' ' '`)
	fi
	if [[ ! $output == "" ]]; then
		echo "Redirecting output to" $output
		echo "Scanning host " $host > $output
		echo "---------------------------------------------------------------------------" >> $output
	fi
	for word in $lines
	do
		site=$host$word
		if [[ ! $extensions == "" ]]; then
			for ex in $ext
			do
				site=$site.$ex
				Request
			done
		else
			Request
		fi
	done
	echo "Scan finished!"
	if [[ ! $output == "" ]]; then
		echo "---------------------------------------------------------------------------" >> $output
		echo "Scan finished!" >> $output
	fi
}

######################################################################################
# Main
if [[ "$host" == "" || "$file" == "" ]]; then
	echo "options -w and -l are mandatory. " >&2
	exit 1
fi
Scan
exit 1