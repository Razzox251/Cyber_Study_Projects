#!/bin/bash
# Student name: Efi Kozinski
# Student Code: <S3>
# Class: TMAGEN77369
# Lecturer: Simon Bar

INSTALLATION () {
#Preforming an update so the applications could be installed safetly & installing the apps required for the scan
	sudo apt update
	sudo apt -y install ipcalc
	sudo apt -y install searchsploit
	sudo apt -y install exploitdb
	searchsploit -u
	sudo apt-get nmap
	git clone https://github.com/vulnersCom/nmap-vulners.git && sudo cp -r nmap-vulners/ /usr/share/nmap/scripts/
}



#This function is meant to get current ip and subnet of this net, map it, and look for live hosts

SCAN () {

        #
#the wanted output of this function is my ip and all the ips that are on my web

        echo "***Current IP: $CURIP"
        #
        mkdir netdiscover
        sudo netdiscover -P -r $CURSUBNET >> netdiscover/Net_Discover_res.txt
        #
        mkdir nmap
        nmap -sn $CURSUBNET | grep -o -E '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' >> nmap/nmap-sn_scan.txt
        LANIPS=nmap/nmap-sn_scan.txt
	echo "***Current Subnet: $CURSUBNET"

        echo "--------------- Hosts discovered by NMAP ping scan ---------------"
        cat $LANIPS

	echo "--------------- Hosts discovered by NETDISCOVERY ---------------"
	cat netdiscover/Net_Discover_res.txt
}

#This function enumerates ports and users
ENUM () {

        #Enumarating the current ip with nmap nse scripts and  attempting msfconsole auxiliary.

        echo "~~~~~~~~~~~~~~~~~~ Discovered open ports on ($CURIP) by nmap ~~~~~~~~~~~~~~~~~~"
        nmap -Pn $CURIP  -oX nmap/CURIP_open_ports.xml --open | sed -n '5,$p' >> nmap/CURIP_open_ports.txt
        cat nmap/nmap-sn_scan.txt

        LANIPS=nmap/nmap-sn_scan.txt

	#Subnet enumeration and user discovery using nmap
	echo "~~~~~~~~~~~~~~~~~~ Scanning your subnet for open ports on connected machines  ~~~~~~~~~~~~~~~~~~"
	nmap -iL $LANIP --exclude $CURIP --open | sed -n '5,$p' >> nmap/CURSUBNET_open_ports.txt
        cat nmap/CURSUBNET_open_ports.txt
	#SORT function is used to sort ports to which be reffered to by enumeration tool(s)

		echo "scanning and enumerating users on comman"

		SORT () {

		while read varip
		do

	        	echo "~~~~~~~~~~~~~~~~~~~~~~~~~~Enumerating ports and users $varip~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"

        		nmap -Pn  $varip --open  | sed -n '6,$p' | awk -F '/' '{ print $1 }' > open_ports.txt

        		while read openport
			do

				#afunction to echo each ip scan into it's own report and echo the discovered ports



				ECHO () {

					echo "$1"

					echo "$varip" >> disreport.txt
					echo "$1" >> disreport.txt

				}

                		case $openport in

                        		3306) ECHO "MYSQL DISCOVERED"  && nmap -Pn $varip --script mysql-enum.nse >> nmap/mysql-enum.txt;;
					139 | 445) ECHO "SMB DISCOVERED" && nmap -Pn --script smb-enum-users.nse >> nse-smb-users.txt;;
                        		80) ECHO "HTTP DISCOVERED" && nmap -Pn --script http-enum -oX nmap/$varip-http-enum.xml $varip >> $varip-http-enum.txt ;;
                        		53) ECHO "DNS DISCOVERED" && nmap -Pn --script dns-srv-enum -oX nmap/$varip-dns-srv-enum.xml $varip >> $varip-http-enum.txt;;
                        		25) ECHO "SMTP DISCOVERED"  && nmap -Pn --script smtp-enum-users $varip >> nmap/$varip-smtp-user-enum.txt ;;
                        		23) ECHO "TELNET DISCOVERED"  ;;
                        		22) ECHO "SSH DISCOVERED"  && msfconsole -q -x "use auxiliary/scanner/ssh/ssh_enumusers;set rhosts $varip;run;exit -y" ;;
                        		21) ECHO "FTP DISCOVERED" ;;
                        		*) ECHO "***open port $openport  cannot be enumerated***" ;;
                		esac
        		done < open_ports.txt


		done < nmap/nmap-sn_scan.txt
	}
	SORT

}



#VULN function is used  to check vulnerabilities on current ip and subnet ( or selcted )
VULN () {


#Checking vulnerabilities with nmap NSE vulners script and searchsploit


	echo "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ Checking Vulnerabilities using nmap NSE script Vulners on current ip ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
	nmap -sV --script=/usr/share/nmap/scripts/nmap-vulners/vulners.nse  $CURIP -oX nmap/nmapCURIP.xml >>  nmap/nsevulners_curip.txt


	#NMAPL function is used to search the list of detected ips for vulnerabilities
	NMAPL () {

	searchsploit --nmap nmap/nmapCURIP.xml >>CURIP_ searchsploit.txt
	count=0
	echo "Scaning detected machines for vulnerabilities"
	while read line
	do

        	echo "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ Vulner. scan No.$count of $line ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"

        	sudo nmap -sV -O --script=/usr/share/nmap/scripts/nmap-vulners/vulners.nse $line -oX nmap/$line-nmap-OV.xml >> nmap/$line.txt

		echo "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ Current IP searchsploit ($line) ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"


        	count=$(( $count + 1 ))
		searchsploit --colour  --nmap nmap/$line-nmap-OV.xml 
		echo "***Vulner. scan No.$count complete***"


	done < nmap/nmap-sn_scan.txt
	}

	NMAPL



}



#REPORT function as named, records and outputs into a Report.txt
REPORT () {

	echo "----------------------------Vulner REPORT----------------------------" >> Report.txt
	echo "~~~~~Info~~~~~" >> Report.txt
	echo "Current IP:$CURIP" >> Report.txt
	echo "Current Subnet:$CURSUBNET" >> Report.txt
	echo "Current Domain Name:$(domainname)" >> Report.txt
	echo "Current Host Name:$(hostname)" >> Report.txt
	echo "---------------------------- Open pcs ----------------------------" >> Report.txt
	echo "~~~~~Nmap hosts discovered~~~~~" >> Report.txt
	cat nmap/nmap-sn_scan.txt >> Report.txt
	echo "~~~~~Netdiscover results~~~~~" >> Report.txt
	cat netdiscover/Net_Discover_res.txt >> Report.txt

	temp=$(ls nmap/*.txt | grep  -E "([0-9]{1,3}[\.]){3}[0-9]{1,3}.txt") 
	for ctt in $temp
	do
		echo "~~~~~~~~~~~~~~~~~ $ctt Vulnerabilities  ~~~~~~~~~~~~~~~~~~~" >> Report.txt
		cat $ctt >> Report.txt

	done 
	echo "---------------------------- Services Discovered ----------------------------" >> Report.txt
	cat disreport.txt >> Report.txt

}




#Main function is used to declare all functions and let the user pick what input the script will read
MAIN () {

	figlet "Vulners"
	echo "Welcome! this program will check and test vulnerabiliries either on current IPv4 and subnet of the machine "
	echo "or to pick your given ip and subnet."


	read -p "please choose what to scan (c-current IP i-input IP):" ch

	if [[ $ch == c  ]]
	then
		mkdir VulnersScan
		cd VulnersScan
		mkdir temp
#		INSTALLATION
		mkdir ifconfigres
        	ifconfig -a -v | grep "inet" | head -1 >> ifconfigres/grepinfo.txt
        	CURIP=$(cat ifconfigres/grepinfo.txt | awk '{ print $2 }')

        	ipcalc $CURIP >> ipcalc.txt

		CURSUBNET=$(grep -i "network" ipcalc.txt | awk '{ print $2 }')

		SCAN
		ENUM
		VULN

	elif [[ $ch == i  ]]
	then

#Recieving ip and subnet from the user
        	read -p "Enter IP address (Ex. 192.168.1.100) :" CURIP
        	read -p "Enter Subnet (Ex. 192.168.1.1/24) :" CURSUBNET

		mkdir VulnersScan
                cd VulnersScan
		mkdir temp

		INSTALLATION
#Checking if the subnet matches the ip
		mkdir ifconfigres
                ifconfig -a -v | grep "inet" | head -1 >> ifconfigres/grepinfo.txt
                CURIP=$(cat ifconfigres/grepinfo.txt | awk '{ print $2 }')

                ipcalc $CURIP >> ipcalc.txt

                CURSUBNETcheck=$(grep -i "network" ipcalc.txt | awk '{ print $2 }')

		if [[ CURSUBNET == CURSUBNETcheck  ]]
		then

	        	SCAN
        		ENUM
        		VULN

		fi

	else
		echo "Invalid input"
	fi
REPORT
echo "***Vulners Complete!***"
}

MAIN

