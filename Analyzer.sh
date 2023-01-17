#!/bin/bash

# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

#Creating and navigating into the analyser file & adding the relevant directories for supporting the scan  results

MYPATH=$(pwd)

# Functions:

TYPE=$1
P=$2

function HDD()
{


	figlet "ANALYZER"

	mkdir $MYPATH/Analyzer
	cd Analyzer

#Creating an individual dir for hdd results
	mkdir hdd
	cd hdd

	echo "HDD file was selected"
	echo " ~~~ "
	echo "This scan may take more then a few minuts"
	echo " ~~~ "


	echo "Updating the system so the applications could be safely installed"
	echo " ~~~ "
#Updating the machine so the apps could be safely installed & run properly
	sudo apt-get update  >> installations.txt

#Installing relevant apps
	echo "Installing Applications "
	echo "***"
	echo "***"

        sudo apt-get install exiftool >> installations.txt
        sudo apt-get install binwalk >> installations.txt
        sudo apt-get install foremost >> installations.txt
	sudo apt-get install strings >> installations.txt
	sudo apt-get install bulk_extractor >> installations.txt
	echo "***"
	echo "***"
	echo "Installation complete"

	echo " ~~~ "

#Navigating and creating path for Bulk Extractor
        cd $MYPATH/Analyzer/hdd
        mkdir  Bulk_Extractor_Results
#Executing bulk_extractor on the given file and outputting the results in a designated diractory
	echo "Extracting files with bulk_extractor                                      "
	bulk_extractor -i $1  -o $MYPATH/Analyzer/hdd/Bulk_Extractor_Results >> $MYPATH/Analyzer/hdd/Bulk_Extractor_Results.txt
        cd $MYPATH/Analyzer/hdd/Bulk_Extractor_Results
#Using grep with regex to search out, emails, ips, and urls from the bulk_extractor result while outputting them into a .txt files
        echo " -grepping bulk_extractor  files"

	grep -E -o "\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,6}\b" $MYPATH/Analyzer/hdd/Bulk_Extractor_Results/email_histogram.txt >> bulk_emails.txt
        grep -E -o '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}'  $MYPATH/Analyzer/hdd/Bulk_Extractor_Results/domain_histogram.txt >> ipadr.txt
        grep -E -o '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' $MYPATH/Analyzer/hdd/Bulk_Extractor_Results/ip_histogram.txt >> ipadr.txt
        grep -E -o "(http|https)://[a-zA-Z0-9./?=_%:-]*"  $MYPATH/Analyzer/hdd/Bulk_Extractor_Results/url_histogram.txt >> URL.txt
	grep "www."  $MYPATH/Analyzer/hdd/Bulk_Extractor_Results/domain_histogram.txt | awk '{print $2}' >> URL.txt

	echo " ~~~ "
#Executing binwalk on the file and outputting its' results in a .txt file

	echo "Executing exiftool"

        cd $MYPATH/Analyzer/hdd
        mkdir exifres
        cd exifres
        exiftool $1 >> fileinfo.txt

	echo " ~~~ "

#Anylyzing the file with binwalk and outputting into a  .txt file
        cd $MYPATH/Analyzer/hdd
        mkdir Binwalk_Results
        cd Binwalk_Results
	echo "Executing binwalk"

        binwalk $1 >> binwalk_report.txt

	echo " ~~~ "

#Creating a diractory for strings results
        cd $MYPATH/Analyzer/hdd
        mkdir Strings_Results
        cd Strings_Results
#A function i made for filtering urls, ips & emails into 3 .txt files from strings result
        function MULTI()
	{

		grep -E -o "\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,6}\b" $STR  >> emails.txt
		grep -E -o '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' $STR  >> ip_adr.txt
		grep -E -o "(http|https)://[a-zA-Z0-9./?=_%:-]*" $STR >> url.txt

	}
#Executing strings and saving the output as a .txt file
	echo "Executing strings and extracting info"

	strings $1 >> Strings_Results.txt
	STR=Strings_Results.txt

	MULTI

	echo " ~~~ "

#Creating a diractory for foremost results
        cd $MYPATH/Analyzer/
	mkdir Foremost_Results
	cd Foremost_Results
	mkdir Extracted_Files
#Using foremost to extract files from the image
	echo "Extracting files with foremost"

        foremost $1 -o $MYPATH/Analyzer/Foremost_Results/Extracted_Files >> forprog.txt

	echo " Extracted files saved in $MYPATH/Analyzer/Foremost_Results/Extracted_Files/ directory "
	echo " ~~~ "

#Finding the file's hashes (MD5 & SHA1)
	echo "Extracting hashes"
	echo " ~~~ "

	cd $MYPATH/Analyzer/hdd
	mkdir Hashes
	cd Hashes
	md5sum $1 >> hashes.txt
	sha1sum $1 >>hashes.txt



}


function MEM()
{

figlet "ANALYZER"

	mkdir $MYPATH/Analyzer
	cd Analyzer
#Creating an individual path for mem results
	mkdir mem
	cd mem

	echo "MEM file was selected"
	echo " ~~~ "
	echo "This scan may take a minut"
	echo " ~~~ "
	echo "Updating the system so the applications could be safely installed"
	echo " ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ "
#Updating the machine so the apps could be safely installed & run properly
	sudo apt-get update >> installations.txt

#Installing relevant apps

	echo "Installing Applications "
        echo "***"
        echo "***"

	sudo apt-get install exiftool >> installations.txt
	sudo apt-get install binwalk >> installations.txt
	sudo apt-get install bulk_extractor >> installations.txt
	sudo apt-get install python3 >> installations.txt
        sudo git clone https://github.com/volatilityfoundation/volatility3.git >> installations.txt
        cd $MYPATH/Analyzer/mem/volatility3/
        sudo python3 $MYPATH/Analyzer/mem/volatility3/setup.py install >> installations.txt

	echo "***"
        echo "***"
        echo "Installations complete"
	echo " ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ "

#Executing Volatility3, recieving  MYPATH argument and outputting the results in a .txt file
        echo "Executing Volatility"
	echo " ~~~ "

	cd $MYPATH/Analyzer/mem
	mkdir Vol
	cd $MYPATH/Analyzer/mem/volatility3

	echo " -Extracting processes"
	sudo ./vol.py -f $1 windows.pslist >> $MYPATH/Analyzer/mem/Vol/Volpsl_results.txt
	echo " -Creating hive list"
	sudo ./vol.py -f $1 windows.registry.hivelist >> $MYPATH/Analyzer/mem/Vol/Volreghl_results.txt
	echo " -Creating process tree"
	sudo ./vol.py -f $1 windows.pstree  >> $MYPATH/Analyzer/mem/Vol/Volpst_results.txt
	echo " ~~~                        "

#Navigating and creating path for Bulk Extractor
        cd $MYPATH/Analyzer/mem
        mkdir  Bulk_Extractor_Results
#Executing bulk_extractor on the given file and outputting the results in a designated diractory
        echo "Extracting files with bulk_extractor                            "

	bulk_extractor -i $1  -o $MYPATH/Analyzer/mem/Bulk_Extractor_Results >> $MYPATH/Analyzer/mem/Bulk_Extractor_Results.txt

        cd $MYPATH/Analyzer/mem/Bulk_Extractor_Results
#Using grep with regex to search out, emails, ips, and urls from the bulk_extractor result while outputting them into a .txt files
        echo "  -grepping relevant info"
	echo " ~~~ "

	grep -E -o "\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,6}\b" $MYPATH/Analyzer/mem/Bulk_Extractor_Results/email_histogram.txt >> emails.txt
        grep -E -o '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}'  $MYPATH/Analyzer/mem/Bulk_Extractor_Results/domain_histogram.txt >> ipadr.txt
        grep -E -o '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' $MYPATH/Analyzer/mem/Bulk_Extractor_Results/ip_histogram.txt >> ipadr.txt
        grep -E -o "(http|https)://[a-zA-Z0-9./?=_%:-]*"  $MYPATH/Analyzer/mem/Bulk_Extractor_Results/url_histogram.txt >> URL.txt
	grep "www."  $MYPATH/Analyzer/mem/Bulk_Extractor_Results/domain_histogram.txt | awk '{print $2}' >> URL.txt


#Executing exif  on the file and outputting its' info  in a .txt file

        cd $MYPATH/Analyzer/mem
        mkdir exifres
        cd exifres
	echo "Executing exiftool"

        exiftool $1 >> fileinfo.txt

	echo " ~~~ "
#Creating strings diractory for results

        cd $MYPATH/Analyzer/mem
        mkdir Strings_Results
        cd Strings_Results
#A function for filtering urls, ips & emails into 3 .txt files from strings result
        function MULTI()
        {

                grep -E -o "\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,6}\b" $STR  >> emails.txt
                grep -E -o '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' $STR  >> ip_adr.txt
                grep -E -o "(http|https)://[a-zA-Z0-9./?=_%:-]*" $STR >> url.txt

        }
#Executing strings and saving the output as a .txt file
	echo "Executing strings and extracting info"

        strings $1 >> Strings_Results.txt
        STR=Strings_Results.txt

        MULTI
	echo " ~~~ "

#Creating a diractory for foremost results
        cd $MYPATH/Analyzer/
        mkdir Foremost_Results
        cd Foremost_Results
	mkdir Extracted_Files
#Using foremost to extract files from the image
	echo "Extracting files with foremost"

	foremost $1 -o $MYPATH/Analyzer/Foremost_Results/Extracted_Files >> forprog.txt


	echo " Extracted files saved in $MYPATH/Analyzer/Foremost_Results/Extracted_Files/ directory "
	echo " ~~~ "

#Finding the file's hashes (MD5 & SHA1)
        cd $MYPATH/Analyzer/mem
        mkdir Hashes
        cd Hashes
	echo "Extracting hashes"

        md5sum $1 >> hashes.txt
        sha1sum $1 >> hashes.txt
	echo " ~~~ "

}

# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
# Creating functions to log each of the MEM & HDD functions and creating the Report.txt file from all the .txt files gathered  in the scan
function LOGMEM()
{

	cd $MYPATH/Analyzer/
        echo "============SUMMERY============" >> Mem_Report.txt
        echo "----------File Info----------" >> Mem_Report.txt
	echo "Analyzer Scan Date: $(date)" >> Mem_Report.txt
	sed -n '2,$p'  $MYPATH/Analyzer/mem/exifres/fileinfo.txt >> Mem_Report.txt
        echo "----------Hashes(MD5/SHA1)-----------" >> Mem_Report.txt
        cat $MYPATH/Analyzer/mem/Hashes/hashes.txt >> Mem_Report.txt

	echo "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~" >> Mem_Report.txt
	echo "===========Foremost Extraction List===========" >> Mem_Report.txt
        sed -n '13,$p' $MYPATH/Analyzer/Foremost_Results/Extracted_Files/audit.txt >> Mem_Report.txt

	echo "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~" >> Mem_Report.txt
	echo "============Volatility===========" >> Mem_Report.txt
	echo "-----------Processes-------------" >> Mem_Report.txt
        cat  $MYPATH/Analyzer/mem/Vol/Volpsl_results.txt >> Mem_Report.txt
	echo "-----------Process Tree-----------" >> Mem_Report.txt
	cat $MYPATH/Analyzer/mem/Vol/Volpst_results.txt >> Mem_Report.txt
	echo "-----------Registry Hive List---------- " >> Mem_Report.txt
	cat $MYPATH/Analyzer/mem/Vol/Volreghl_results.txt >> Mem_Report.txt

	echo "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~" >> Mem_Report.txt
	echo "============Bulk_Extractor============" >> Mem_Report.txt
        echo "----------DETECTED EMAILs----------" >> Mem_Report.txt
        cat $MYPATH/Analyzer/mem/Bulk_Extractor_Results/emails.txt | sort | uniq >> Mem_Report.txt
        echo "----------DETECTED IPs-----------" >> Mem_Report.txt
        cat $MYPATH/Analyzer/mem/Bulk_Extractor_Results/ipadr.txt | sort | uniq >> Mem_Report.txt
        echo "----------DETECTED URLs----------" >> Mem_Report.txt
        cat $MYPATH/Analyzer/mem/Bulk_Extractor_Results/URL.txt | sort | uniq >> Mem_Report.txt

	echo "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~" >> Mem_Report.txt
        echo "============Strings============" >> Mem_Report.txt
        echo "----------DETECTED EMAILs----------" >> Mem_Report.txt
        cat $MYPATH/Analyzer/mem/Strings_Results/emails.txt | sort | uniq >> Mem_Report.txt
        echo "----------DETECTED IPs-----------" >> Mem_Report.txt
        cat $MYPATH/Analyzer/mem/Strings_Results/ip_adr.txt | sort | uniq >> Mem_Report.txt
        echo "----------DETECTED URLs----------" >> Mem_Report.txt
        cat $MYPATH/Analyzer/mem/Strings_Results/url.txt | sort | uniq >> Mem_Report.txt

	echo "MEM LOG file has been recorded and saved in $MYPATH/Analyzer/Mem_Report.txt"

	read -p "Do you with to keep $MYPATH/Analyzer/mem dir (created for the different scans)?y/n:   " CHOISE

        if [[ $CHOISE == n  ]]
                then
                cd  $MYPATH/Analyzer
                sudo rm -r $MYPATH/Analyzer/mem

	elif [[ $CHOISE == y  ]]
                then
                echo "Files saved in $MYPATH/Analyzer/mem"
        else
                echo "invalid input"
        fi
}


function LOGHDD()
{


	cd $MYPATH/Analyzer/
	echo "============SUMMERY============" >> HDD_Report.txt
	echo "----------File Info----------" >> HDD_Report.txt
	sed -n '2,$p'  $MYPATH/Analyzer/hdd/exifres/fileinfo.txt >> HDD_Report.txt
	echo "Current Date: $(date)" >> HDD_Report.txt
	echo "----------Hashes(MD5/SHA1)-----------" >> HDD_Report.txt
        cat $MYPATH/Analyzer/hdd/Hashes/hashes.txt >> HDD_Report.txt

	echo "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~" >> HDD_Report.txt
	echo "===========Foremost Extraction List===========" >> HDD_Report.txt
        sed -n '13,$p' $MYPATH/Analyzer/Foremost_Results/Extracted_Files/audit.txt >> HDD_Report.txt

	echo "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~" >> HDD_Report.txt
	echo "============Bulk_Extractor============" >> HDD_Report.txt
	echo "----------DETECTED EMAILs----------" >> HDD_Report.txt
	cat $MYPATH/Analyzer/hdd/Bulk_Extractor_Results/bulk_emails.txt | sort | uniq >> HDD_Report.txt
	echo "----------DETECTED IPs-----------" >> HDD_Report.txt
	cat $MYPATH/Analyzer/hdd/Bulk_Extractor_Results/ipadr.txt | sort | uniq >> HDD_Report.txt
	echo "----------DETECTED URLs----------" >> HDD_Report.txt
	cat $MYPATH/Analyzer/hdd/Bulk_Extractor_Results/URL.txt | sort | uniq >> HDD_Report.txt

	echo "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~" >> HDD_Report.txt
	echo "==============Strings==============" >> HDD_Report.txt
	echo "----------DETECTED EMAILs----------" >> HDD_Report.txt
	cat $MYPATH/Analyzer/hdd/Strings_Results/emails.txt | sort | uniq >> HDD_Report.txt
	echo "----------DETECTED IPs-----------" >> HDD_Report.txt
	cat $MYPATH/Analyzer/hdd/Strings_Results/ip_adr.txt | sort | uniq >> HDD_Report.txt
	echo "----------DETECTED URLs----------" >> HDD_Report.txt
	cat $MYPATH/Analyzer/hdd/Strings_Results/url.txt | sort | uniq >> HDD_Report.txt

	echo "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~" >> HDD_Report.txt
	echo "============Binwalk============" >> HDD_Report.txt
	cat $MYPATH/Analyzer/hdd/Binwalk_Results/binwalk_report.txt >> HDD_Report.txt

	echo "HDD LOG file has been recorded and saved in $MYPATH/Analyzer/HDD_Report.txt"


	read -p "Do you with to keep $MYPATH/Analyzer/hdd dir (created for the different scans)?y/n:   " CHOISE

	if [[ $CHOISE == n ]]
		then
		cd  $MYPATH/Analyzer
		sudo rm -r $MYPATH/Analyzer/hdd/
	elif [[ $CHOISE == y  ]]
		then
		echo "Files saved in $MYPATH/Analyzer/mem"
	else
		echo "invalid input"
	fi

}

# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#Making a condition to validate the file's path and declaring the scanning and logging functions

function HAND()
{

sudo updatedb
if [[ $(locate $2) == $P ]]
	then

	if [[ $TYPE == "mem" ]] || [[ $TYPE == "MEM" ]]
		then
			echo "Path $2 is verified ,executing memory analysis"
			echo " |***********************************************************************************************|  "
			MEM $P
			LOGMEM
			echo " |***********************************************************************************************|  "
			echo " ~~~Scan Complete~~~ "

	elif [[ $TYPE == "hdd" ]] || [[ $TYPE == "HDD" ]]
		then
			echo "Path $2 is verified ,executing hard drive disk analysis"
			echo " |***********************************************************************************************|  "
			HDD $P
			LOGHDD
			echo " |***********************************************************************************************|  "
			echo " ~~~Scan Complete~~~ "

	else
		echo "$TYPE is an invalid file type"
		return
	end
	fi
else
	echo "Cannot locate $P"
	return
end
fi
}

#Declaring HAND function

HAND $TYPE $P

