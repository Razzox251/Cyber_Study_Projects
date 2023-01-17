#!/bin/bash

#INST function installs the needed programs

cpath=$(pwd)

INST (){
	
	
        mkdir Alerter
        cd Alerter
	mkdir log
        mkdir Installations
        cd Installations
        
        sudo apt-get -y install update &> /dev/null
        sudo apt-get -y install xdotool &> /dev/null
        sudo searchsploit -u &> /dev/null
        sudo apt-get -y install nmap &> /dev/null
        git clone https://github.com/vulnersCom/nmap-vulners.git
        
	git clone https://github.com/technicaldada/pentbox 
	cd pentbox
	tar -zxvf pentbox.tar.gz
	cd pentbox-1.8
	
	 

}


#Each of this functions (MAIN-SSH/FTP/SMB,HP-ALL) is executing a honeypot with pentbox tool on a port and tailing the log file as "Live Monitor".
#Each of the 4 functions has a VAR variable which will assist in logging the statistics

#Func. executing pentbox honeyppot on port 22
MAIN-SSH () {

	HP-SSH () {
		#Function to activate pentbox.
		XD-SSH () {
			cd $cpath/Alerter/Installations/pentbox/pentbox-1.8
			#-Using xdotool to enter the input into the pentbox console.
			xdotool key 2 KP_Enter 3 KP_Enter 2 KP_Enter 2 2 KP_Enter KP_Enter y KP_Enter && xdotool type $cpath/Alerter/log/SSH.log && xdotool key KP_Enter n KP_Enter && ./pentbox.rb 
        	}

		XD-SSH | grep -i "A" &
		sleep 3
        	clear
        	echo "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~Honeypot running on port 22(SSH)~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
        	sleep 2
        	
        	#the variable which will assist
        	VAR=22
        	
        }
        
        #-Sending the honeypot console to the background and tailing the log file created while it logs the activity.

        trap ' ' INT
	HP-SSH ; tail -F $cpath/Alerter/log/SSH.log | grep -a -i "ATTEMPT"

}

#Func. executing pentbox honeyppot on port 21
MAIN-FTP () {

	HP-FTP () {
		XD-FTP () {
			#-Using xdotool to enter the input into the pentbox console.
			cd $cpath/Alerter/Installations/pentbox/pentbox-1.8
			xdotool key 2 KP_Enter 3 KP_Enter 2 KP_Enter 2 1 KP_Enter KP_Enter y KP_Enter && xdotool type $cpath/Alerter/log/FTP.log && xdotool key KP_Enter n KP_Enter && ./pentbox.rb
		}
		
		XD-FTP | grep -i "A" &
        	sleep 3
        	clear
        	echo "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~Honeypot running on port 21(FTP)~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
        	sleep 2
       		VAR=21
       }
        
	#-Sending the honeypot console to the background and tailing the log file created while it logs the activity.
        trap ' ' INT
        HP-FTP ; tail -F $cpath/Alerter/log/FTP.log | grep -a -i "ATTEMPT"


}

#Func. executing pentbox honeyppot on ports 139 and 445 and tailing all logs.
MAIN-SMB () {

	HP-SMB139 () {
		
		XD139 () {
			cd $cpath/Alerter/Installations/pentbox/pentbox-1.8
			xdotool key 2 KP_Enter 3 KP_Enter 2 KP_Enter 1 3 9 KP_Enter KP_Enter y KP_Enter && xdotool type $cpath/Alerter/log/SMB139.log && xdotool key KP_Enter n KP_Enter && ./pentbox.rb 
		}
		XD139 |  grep -i "A" &
		sleep 6
		clear
	}
	
	HP-SMB445 () {
		
		XD445 () {
			cd $cpath/Alerter/Installations/pentbox/pentbox-1.8
			xdotool key 2 KP_Enter 3 KP_Enter 2 KP_Enter 4 4 5 KP_Enter KP_Enter y KP_Enter && xdotool type $cpath/Alerter/log/SMB445.log && xdotool key KP_Enter n KP_Enter && ./pentbox.rb
		}
		XD445 |  grep -i "A" &
		sleep 6
		clear
		echo "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~Honeypot running on ports 139 and 445(SMB)~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
        	sleep 2
	}
	
	VAR=SMB
	trap ' ' INT
	HP-SMB139 && HP-SMB445 ; tail -f $cpath/Alerter/log/*.log | grep -a -i "ATTEMPT"

}


#Func. executing pentbox honeyppot on all ports 21,22,139,445 and tailing all logs.
HP-ALL () {

	MAIN-SSHA () {

		HP-SSHA () {
			XD-SSHA () {
				cd $cpath/Alerter/Installations/pentbox/pentbox-1.8
				xdotool key 2 KP_Enter 3 KP_Enter 2 KP_Enter 2 2 KP_Enter KP_Enter y KP_Enter && xdotool type $cpath/Alerter/log/SSHA.log && xdotool key KP_Enter n KP_Enter && ./pentbox.rb 

			}

			XD-SSHA | grep -i "A" &
		        sleep 3
		        clear
		}
		HP-SSHA
	}

	MAIN-FTPA () {
		
		HP-FTPA () {
			XD-FTPA () {
				cd $cpath/Alerter/Installations/pentbox/pentbox-1.8
				xdotool key 2 KP_Enter 3 KP_Enter 2 KP_Enter 2 1 KP_Enter KP_Enter y KP_Enter && xdotool type $cpath/Alerter/log/FTPA.log && xdotool key KP_Enter n KP_Enter && ./pentbox.rb
			}
			XD-FTPA | grep -i "A" &
	        	sleep 3
	        	clear
		}
		HP-FTPA
	}

	MAIN-SMBA () {
	
				
		HP-SMB139A () {
			XD139A () {
				cd $cpath/Alerter/Installations/pentbox/pentbox-1.8
				xdotool key 2 KP_Enter 3 KP_Enter 2 KP_Enter 1 3 9 KP_Enter KP_Enter y KP_Enter && xdotool type $cpath/Alerter/log/SMB139A.log && xdotool key KP_Enter n KP_Enter && ./pentbox.rb 
			}

			XD139A |  grep -i "A" &
			sleep 3
			clear
		}
	
		HP-SMB445A () {
		
			XD445A () {
				cd $cpath/Alerter/Installations/pentbox/pentbox-1.8
				xdotool key 2 KP_Enter 3 KP_Enter 2 KP_Enter 4 4 5 KP_Enter KP_Enter y KP_Enter && xdotool type $cpath/Alerter/log/SMB445A.log && xdotool key KP_Enter n KP_Enter && ./pentbox.rb
			}
			XD445A |  grep -i "A" &
			sleep 3
			clear
			echo "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~Honeypot running all ports (21,22,139 and 445)~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
        		sleep 2
		}
	
		HP-SMB139A && HP-SMB445A

	}
	
	VAR=ALL
	trap ' ' INT
	MAIN-SSHA && MAIN-FTPA && MAIN-SMBA ; tail -F $cpath/Alerter/log/*.log | grep -a -i "ATTEMPT"

}


#SEARCH function meant to read the ips that were detected and scan each for vulnerabilities 
SEARCH () {
	
	cd $cpath/Alerter
	mkdir Search_Res
	
	touch $cpath/Alerter/log/tmp.log
	#Filtering the ip addresses from the log file/s
        grep -a -o -E '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' $(ls $cpath/Alerter/log/*.log) | awk -F ':' '{print $2}' | uniq | sort > Search_Res/ips.txt
        cat Search_Res/ips.txt
        echo "***** Scan Date [$(date)] *****" >> Search_Res/Report.txt

	#Statistics function sorts some scanned information into useful data to log
	STAT () {

		cd $cpath/Alerter
		echo "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~Statistics~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"  >> Search_Res/Report.txt
		echo "Number of Detected ips: $(cat Search_Res/ips.txt | wc -l)"  >> Search_Res/Report.txt
		echo "Detected ips: $(cat Search_Res/ips.txt)"  >> Search_Res/Report.txt
		
		case $VAR in
		
		# counting lines in each log for attempts
		22) echo "Number of attempts on SSH port 22: $(grep -a "ATTEMPT" log/SSH.log | wc -l)" >> Search_Res/Report.txt ;;
					
		21) echo "Number of attempts on FTP port 21: $(grep -a "ATTEMPT" log/FTP.log | wc -l)"  >> Search_Res/Report.txt ;;
				
		SMB) echo "Number of attempts on SMB port 139: $(grep -a "ATTEMPT" log/SMB139.log | wc -l)"  >> Search_Res/Report.txt
			echo "Number of attempts on SMB port 445: $(grep -a "ATTEMPT" log/SMB445.log | wc -l)"  >> Search_Res/Report.txt ;;
		
			
		ALL) echo "Number of attempts on SSH port 22: $(grep -a "ATTEMPT" log/SSHA.log | wc -l)" >> Search_Res/Report.txt
			echo "Number of attempts on FTP port 21: $(grep -a "ATTEMPT" log/FTPA.log | wc -l)"  >> Search_Res/Report.txt
			echo "Number of attempts on SMB port 139: $(grep -a "ATTEMPT" log/SMB139A.log | wc -l)"  >> Search_Res/Report.txt
			echo "Number of attempts on SMB port 445: $(grep -a "ATTEMPT" log/SMB445A.log | wc -l)"  >> Search_Res/Report.txt ;;
			
		esac
	}
	STAT
	
	echo "***** Current scan results *****" >> Search_Res/Report.txt && cat $cpath/Alerter/log/*.log  >> Search_Res/Report.txt
        cd Search_Res
	
	
        while read ip
        do         
                                         
                echo "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ Nmap scan on intruder ip ($ip) ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~" >> Report.txt
                
                #Executing Nmap with vulners.nse for detailed vulnerability scan.
                sudo nmap -Pn -O --script=$cpath/Alerter/Installations/nmap-vulners/vulners.nse $ip -oX nmapscan_$ip.xml >> Report.txt
                echo "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ Using searchsploit ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
                echo "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ Searchsploit vulnerability result from the Nmap scan ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~" >> Report.txt
                echo "" >> Report.txt
                echo "" >> Report.txt
		
		#Using Searchsploit on the nmap .xml output for possible exploits.
                searchsploit --nmap nmapscan_$ip.xml >> Report.txt
		echo "" >> Report.txt
		echo "" >> Report.txt
		echo "" >> Report.txt
                
                
                echo "Doing whois querry"
                echo "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ Whois Querry on intruder ip ($ip) ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~" >> Report.txt
                #Doing whois querry
                whois $ip >> Report.txt


                echo "" >> Report.txt
                echo "" >> Report.txt
                echo "" >> Report.txt
                echo "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ INTRUDER SCAN COMPLETE ($ip) ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~" >> Report.txt
                echo "" >> Report.txt
                echo "" >> Report.txt
                echo "" >> Report.txt

        done < ips.txt

	#Moving the Report.txt file to the main Alerter directory.
	mv $cpath/Alerter/Search_Res/Report.txt  $cpath/Alerter


}




#Function to read the choice from the user the execute the proper followed function
PICK () {
	
	
	figlet "ALERTER"
	sleep 1
	
	#Echoing the menu to the user
	echo "Hello, this bash script will turn an alerter on a port - 22,21,139+445, or all of them."
	echo "Please pick a service:"
        echo "1.  SSH(22)"
        echo "2.  FTP(21)"
        echo "3.  SMB(139,445)"
        echo "4.  Start on all services (22,21,139,445)"
 
 	echo "[***NOTE: while in monitor screen press crtl+c ONCE to exit and log the activity]"
 	read -p "[?] Enter your choice: " ch
	#Receiving the choice from the user and activating functions accordingly.
	#1.Installations
	#2.Waiting until the Installation finishes and executing the relevant function.
	#3.Executing the Search function to report and log the session ,And scan each intruder individually for vulnerabilities.
	case $ch in
	
		1) echo "Installing progrems" && INST &> /dev/null & wait && MAIN-SSH ; 
			echo "~~~~~~~~~~ Scanning Intruders ~~~~~~~~~~" && SEARCH &> /dev/null ;;
		2) echo "Installing progrems" && INST &> /dev/null & wait && MAIN-FTP ;
			echo "~~~~~~~~~~ Scanning Intruders ~~~~~~~~~~" && SEARCH &> /dev/null ;;
		3) echo "Installing progrems" && INST &> /dev/null & wait && MAIN-SMB ;
			echo "~~~~~~~~~~ Scanning Intruders ~~~~~~~~~~" && SEARCH &> /dev/null ;;
		4) echo "Installing progrems" && INST &> /dev/null & wait && HP-ALL ;
			echo "~~~~~~~~~~ Scanning Intruders ~~~~~~~~~~" && SEARCH &> /dev/null ;;
		*) echo "Invalid input!" ;;
	
		esac
	
	echo "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ Scan Complete ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
	echo "*****Report saved in $cpath/Alerter/Report.txt*****"
}

PICK

