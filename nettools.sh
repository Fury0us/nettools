#!/bin/bash
COLUMNS=12
exiftool() {
	echo -en '\n'
	clear
	read -p $'\e[31mFile Path?: \e[0m' photo
	PS3=("#exif: ")
	exif=("View All Metadata" "Erase Metadata" "View Metadata Tags" "Edit Metadata" "Get GPS Coordinates" "Extract Metadata to Text" "Previous Menu")
	select ex in "${exif[@]}"; do
	case $ex in
	"View All Metadata")
	sudo exiftool $photo
	;;
	"Erase Metadata")
	sudo exiftool -all= $photo
	;;
	"View Metadata Tags")
	sudo exiftool -a $photo
	;;
	"Edit Metadata")
	read -p $'\e[31mTAGMANE?: \e[0m' tag
	read -p $'\e[31mValue?\e[0m' value
	sudo exiftool -$tag="$value"
	;;
	"Get GPS Coordinates")
	sudo exiftool -GPSLatitude -GPSLongitude $photo
	;;
	"Extract Metadata to Text")
	sudo exiftool -a -u -G1 -w TXT "$photo".txt $photo
	;;
	"Previous Menu")
	auditing_tools
	;;
	esac
done
}
holehe() {
	if [ $HOME/.local/bin/holehe ]
	then
		clear
		echo -en '\n'
		echo $'\e[31mholehe is installed, continuing..\e[0m'
	else
		clear
		echo -en '\n'
		pip3 install holehe
		echo -en '\n'
		echo $'\e[31mholehe has been installed!\e[0m'
	fi
	read -p $'\e[31mDomain/Email to search?: \e[0m' scan
	holehe $scan
	echo -en '\n'
	auditing_tools
}
skipfish() {
	echo -en '\n'
	clear
	read -p $'\e[31mURL?\e[0m' URL
	read -p $'\e[31mOutput loc?: \e[0m' OUTPUT
	PS3=("#skip: ")
	skip=("Custom Config File" "Generate a Report" "Maximum Depth" "Spec Login" "Previous Menu")
	select sk in "${skip[@]}"; do
	case $sk in
	"Custom Config File")
	;;
	"Generate a Report")
	;;
	"Maximum Depth")
	;;
	"Spec Login")
	;;
	"Previous Menu")
	;;
	esac
done
}
harvester() {
	echo -en '\n'
	clear
	PS3=("#harv :")
	harvest=("Manage API Keys" "Domain Search" "Email Lookup" "Comprehensive Scan(email/domain" "Previous Menu")
	select harv in "${harvest[@]}"; do
	case $harv in
	"Manage API Keys")
	harvester_api
	;;
	"Domain Search")
	;;
	"Email Lookup")
	;;
	"Comprehensive Scan(email/domain")
	;;
	"Previous Menu")
	auditing_tools
	;;
esac
done
}
harvester_api() {
	echo -en '\n'
	clear
	PS3=("#harv-api: ")
	hapi=("bevigil" "binaryedge" "bufferoverun" "Censys ID" "Secret" "criminalip" "fullhunt" "Github" "Hunter" "hunterhow" "Intelx" "netlas" "onyphe" "PentestTools" "ProjectDiscovery" "RocketReach" "Securitytrail" "Tomba Key" "Virustotal" "zoomeye" "Previous Menu")
	select ha in "${hapi[@]}"; do
	case $ha in
	"bevigil")
	;;
	"binaryedge")
	;;
	"bufferoverun")
	;;
	"Censys ID")
	;;
	"Secret")
	;;
	"criminalip")
	;;
	"fullhunt")
	;;
	"Github")
	;;
	"Hunter")
	;;
	"hunterhow")
	;;
	"Intelx")
        ;;
        "netlas")
        ;;
        "onyphe")
        ;;
        "PentestTools")
        ;;
        "ProjectDiscovery")
        ;;
        "RocketReach")
        ;;
        "Securitytrail")
        ;;
        "Tomba Key")
        ;;
        "Secret")
        ;;
        "virustotal")
        ;;
	"zoomeye")
	;;
	"Previous Menu")
	auditing_tools
	;;
esac
done
}
metagoofil() {
echo "metagoofil"
}
pixiewps() {
echo "pixiewps"
}
reaver() {
echo "reaver"
}
device_options() {
#Device-Options start here
	echo -en '\n'
	PS3=("#dev: ")
	devoptions=("Randomize Device Info" "List IP Address" "List MAC" "Proxychains Firefox Session" "Main Menu")
	select devop in "${devoptions[@]}"; do
	case $devop in
	"Randomize Device Info")
	echo -en '\n'
	sudo ifconfig $winterface down
	sleep 1
	        #Start MAC Address Generation
# Extract the first half of the MAC address from the vendor
first_half=$(macchanger -l | awk '{print $3}' | shuf -n 1)

# Generate the second half of the MAC address randomly
second_half=""
for i in {1..6}; do
  random_hex=$(openssl rand -hex 1)
  second_half="${second_half}${random_hex}"
  if [ $i -ne 6 ]; then
    second_half="${second_half}:"
  fi
done

# Remove the unnecessary extra characters from the right
second_half=${second_half::-9}
macaddr=${first_half}:${second_half}
        sleep 1
        sudo macchanger -m $macaddr $winterface
	sleep 1
	sudo ifconfig $winterface inet 192.168.$(( RANDOM % 256 )).$(( RANDOM % 256 )) netmask 255.255.252.0 broadcast 192.168.$(( RANDOM % 256 )).$(( RANDOM % 256 ))
	sleep 1
        sudo ifconfig $winterface inet 192.168.$(( RANDOM % 256 )).$(( RANDOM % 256 )) netmask 255.255.252.0 broadcast 192.168.$(( RANDOM % 256 )).$(( RANDOM % 256 ))
	sleep 1
	sudo ifconfig $winterface inet 192.168.$(( RANDOM % 256 )).$(( RANDOM % 256 )) netmask 255.255.252.0 broadcast 192.168.$(( RANDOM % 256 )).$(( RANDOM % 256 ))
#Begin IPV6 Change

#-----Link-Local IPV6


# Function to generate a random 4-digit hex
random_hex() {
  printf "%04x" $(( RANDOM % 65536 ))
}

# Generate the Link-local IPv6 address
ipv6_address="fe80::$(random_hex):$(random_hex):$(random_hex):$(random_hex)/64"

# Set the Link-local IPv6 address
sudo ip -6 addr add $ipv6_address dev $winterface

#-----GLOBAL IPV6
# Function to generate a random hex number
generate_hex() {
    hexchars="0123456789abcdef"
    printf "%s" "${hexchars:$(( $RANDOM % 16 )):1}"
}

# Generate GlOBAL IPv6 address with Class C network rules
generate_ipv6() {
    blocks=""
    for i in {1..7}; do
        block=""
        for j in {1..4}; do
            block+=$(generate_hex)
        done
        blocks+="${block}:"
    done

    block=""
    for j in {1..4}; do
        block+=$(generate_hex)
    done
    blocks+="${block}"

    # Remove the trailing colon if present
    ipv6=${blocks%:}

    echo "$ipv6"
}

# Generate and print a random IPv6 address
random_ipv6=$(generate_ipv6)
echo -en '\n'
echo "Random IPv6 address: $random_ipv6"
echo -en '\n'
sudo ip -6 addr replace $random_ipv6/64 dev $winterface
	sleep 1
	sudo ifconfig $winterface up
	echo -en '\n'
	sudo macchanger -s $winterface
	echo -en '\n'
	device_options
	COLUMNS=12
	;;
	"List IP Address")
        echo -en '\n'
	ifconfig $winterface | grep 'inet'
        echo -en '\n'
	device_options
        COLUMNS=12
	;;
	"List MAC")
        echo -en '\n'
	sudo macchanger -s $winterface
        echo -en '\n'
	device_options
        COLUMNS=12
	;;
	"Proxychains Firefox Session")
	clear
	read -p $'\e[1;31mWould you like to start a proxychains session in firefox?(yes/no): \e[0m' input
	if [ $input = "yes" ] || [ $input = "y" ]
	then
                sudo systemctl stop tor
		sleep 0.5
		sudo service tor start
		sleep 0.5
		sudo -k
		sleep 0.5
	        proxychains firefox
	else
	        exit
	fi
	sleep 1
	sudo service tor stop
	sudo systemctl stop tor
	sudo service NetworkManager start
	sleep 1
	echo $'\e[1;31m'
	echo -en '\n'
	device_options
	COLUMNS=12
	;;
	"Main Menu")
	echo -en '\n'
	main_menu
	;;
esac
done
}
auditing_tools() {
	#Auditing-Tools start here
	echo -en '\n'
	COLUMNS=12
	PS3=("#aud: ")
	audit=("Script(Pre-Made)" "Script(Kali-Based)" "Passive Recon" "Active Recon" "Main Menu")
	select aud in "${audit[@]}"; do
	case $aud in
		"Script(Pre-Made)")
        	echo -en '\n'
		PS3=("#kiddie: ")
		madescr=("Set Interface Into Monitor Mode" "Set Interface Into Managed Mode" "Launch Airgeddon" "Launch Wifite" "Launch Wifite /w rockyou" "Launch Wifite(attack ALL)(WPA ONLY)" "Install & Run Routersploit" "Previous Menu")
		select madescr in "${madescr[@]}"; do
		case $madescr in
                "Set Interface Into Monitor Mode")
                sudo airmon-ng start $winterface &&
                sudo ifconfig $winterface"mon" down &&
                sudo macchanger -r -b $winterface"mon" &&
                sudo ifconfig $winterface"mon" up &&
                sudo airmon-ng check kill
		echo -en '\n'
		auditing_tools
        	COLUMNS=12
                ;;
                "Set Interface Into Managed Mode")
                sudo airmon-ng stop $winterface"mon" &&
                sudo service NetworkManager start
                cd ~
                source .bashrc
                echo -en '\n'
                auditing_tools
                COLUMNS=12
                ;;
                "Set Interface Into Managed Mode")
                sudo airmon-ng stop $winterface"mon"
                sudo service NetworkManager start
                cd ~
                source .bashrc
                echo -en '\n'
                auditing_tools
                COLUMNS=12
                ;;
		"Launch Airgeddon")
		echo -en '\n'
		sudo airgeddon
                echo -en '\n'
                auditing_tools
                COLUMNS=12
		;;
		"Launch Wifite")
		echo -en '\n'
		sudo wifite -mac
                echo -en '\n'
                auditing_tools
                COLUMNS=12
		;;
		"Launch Wifite /w rockyou")
		echo -en '\n'
		sudo wifite -mac --dict /usr/share/wordlists/rockyou.txt
                echo -en '\n'
                auditing_tools
                COLUMNS=12
		;;
		"Launch Wifite(attack ALL)(WPA ONLY)")
		echo -en '\n'
		sudo wifite -mac --all --dict /usr/share/wordlists/null.txt
                echo -en '\n'
                auditing_tools
                COLUMNS=12
		;;
		"Install & Run Routersploit")
		echo -en '\n'
		generate_rsf
                echo -en '\n'
                auditing_tools
                COLUMNS=12
		;;
		"Previous Menu")
		echo -en '\n'
		break 1;;
		esac
		done
		auditing_tools
		COLUMNS=12
	;;
	"Script(Kali-Based)")
        echo -en '\n'
		PS3=("#kbased: ")
		kaliscr=("Set Interface Into Monitor Mode" "Set Interface Into Managed Mode" "Search for devices(wifi needed)" "Airodump-ng (all)" "Airodump-ng (Channel)" "Airodump-ng (Chan+Bssid)" "Airodump-ng (Silent Cap)" "Aireplay-ng (BSSID)" "Aireplay-ng (MAC+BSSID)" "Aireplay-ng (diff deauth code)" "Previous Menu")
		select kalisc in "${kaliscr[@]}"; do
		case $kalisc in
		"Set Interface Into Monitor Mode")
		sudo ifconfig $winterface down &&
		sudo iwconfig $winterface mode monitor &&
		sudo macchanger -r -b $winterface &&
		sudo ifconfig $winterface up
		echo -en '\n'
                auditing_tools
                COLUMNS=12
		;;
		"Set Interface Into Managed Mode")
		sudo ifconfig $winterface down &&
		sudo iwconfig $winterface mode managed &&
		sudo macchanger -r -b $winterface &&
		sudo ifconfig $winterface up
		cd ~
		sudo service NetworkManager restart
		source .bashrc
                echo -en '\n'
                auditing_tools
                COLUMNS=12
		;;
		"Search for devices(wifi needed)")
		sudo netdiscover
                echo -en '\n'
                auditing_tools
                COLUMNS=12
		;;
		"Airodump-ng (all)")
		echo -en '\n'
		sudo airodump-ng $winterface
                echo -en '\n'
                auditing_tools
                COLUMNS=12
		;;
		"Airodump-ng (Channel)")
		echo -en '\n'
		read -p $'\e[1;31mChannel?: \e[0m' chann
		sudo airodump-ng -c $chann $winterface
                echo -en '\n'
                auditing_tools
                COLUMNS=12
		;;
		"Airodump-ng (Chan+Bssid)")
		echo -en '\n'
		read -p $'\e[1;31mChannel?: \e[0m' chann
		read -p $'\e[1;31mBSSID?: \e[0m' bssid
		sudo airodump-ng -c $chann --bssid $bssid $winterface
                echo -en '\n'
                auditing_tools
                COLUMNS=12
		;;
		"Airodump-ng (Silent Cap)")
		echo -en '\n'
		read -p $'\e[1;31mChannel?: \e[0m' chann
		read -p $'\e[1;31mBSSID?: \e[0m' bssid
		read -p $'\e[1;31Name of Network?: \e[0m' capfile
		sudo airodump-ng -c $chann --bssid $bssid $winterface -w $capfile
                echo -en '\n'
                auditing_tools
                COLUMNS=12
		;;
		"Aireplay-ng (BSSID)")
		read -p $'\e[1;31mBSSID?: \e[0m' bssid
		sudo aireplay-ng --deauth 0 -a $bssid
                echo -en '\n'
                auditing_tools
                COLUMNS=12
		;;
		"Aireplay-ng (MAC+BSSID)")
		read -p $'\e[1;31mBSSID?: \e[0m' bssid
                read -p $'\e[1;31mClient MAC?: \e[0m' clientmac
                sudo aireplay-ng --deauth 0 -a $bssid -c $clientmac $winterface
                echo -en '\n'
                auditing_tools
                COLUMNS=12
		;;
		"Aireplay-ng (diff deauth code)")
                read -p $'\e[1;31mBSSID?: \e[0m' bssid
                read -p $'\e[1;31mClient MAC?: \e[0m' clientmac
                read -p $'\e[1;31mDeauth Code?: \e[0m' decode
		sudo aireplay-ng --deauth 0 -a $bssid -c $clientmac $winterface --deauth-rc $decode
                echo -en '\n'
                auditing_tools
                COLUMNS=12
		;;
		"Previous Menu")
		break 1;;
		esac
		done
		auditing_tools
		COLUMNS=12
		;;
	"Passive Recon")
#Passive Recon includes tools like p0f, whois, nslookup, dig, Netcraft, Shodan, DNS
	echo -en '\n'
	PS3=("#passcon: ")
	passcon=("holehe" "p0f Scan" "extract data with exiftool" "whois lookup" "dig lookup" "nslookup" "DNSenum" "Open Shodan" "whatweb" "Previous Menu")
	select passc in "${passcon[@]}"; do 
	case $passc in
		"holehe")
		echo -en '\n'
		holehe
		echo -en '\n'
		COLUMNS=12
		;;
		"p0f Scan")
                read -p $'\e[31mName of capture file?(exclude .txt): \e[0m' capture
                read -p $'\e[31mIP?: \e[0m' ipaddress
		sudo p0f -i $winterface -s $ipaddress -o $capture.log 
                echo -en '\n'
                auditing_tools
                COLUMNS=12
		;;
		"extract data with exiftool")
		echo -en '\n'
		exiftool
                echo -en '\n'
                auditing_tools
                COLUMNS=12
		;;
		"whois lookup")
		read -p $'\e[1;31mDomain Name?(website): \e[0m' domain
		whois $domain > $domain"whois".txt
                echo -en '\n'
                auditing_tools
                COLUMNS=12
		;;
		"dig lookup")
		read -p $'\e[1;31mDomain Name?(website): \e[0m' domain
		dig $domain > $domain"dig".txt
                echo -en '\n'
                auditing_tools
                COLUMNS=12
		;;
		"nslookup")
		read -p $'\e[1;31mDomain Name?(website): \e[0m' domain
		sudo nslookup $domain > $domain"nslookup".txt
                echo -en '\n'
                auditing_tools
                COLUMNS=12
		;;
		"DNSEnum")
		read -p $'\e[1;31mDomain Name?: \e[0m' domain
		sudo dnsenum $domain > $domain"dnsenum".txt
                echo -en '\n'
                auditing_tools
                COLUMNS=12
		;;
		"Open Shodan")
		sudo shodan
                echo -en '\n'
                auditing_tools
                COLUMNS=12
		;;
		"whatweb")
		read -p $'\e[1;31mDomain?: \e[0m' domain
		sudo whatweb $domain > $domain"whatweb".txt
                echo -en '\n'
                auditing_tools
                COLUMNS=12
		;;
		"Previous Menu")
		break 1;;
		esac
		done
		auditing_tools
		COLUMNS=12
		;;
	"Active Recon")
#Active Recon includes tools like Dnsenum and Nmap
	echo -en '\n'
	PS3=("#actcon: ")
	actcon=("Nmap TCP Scan(Stealth)" "Nmap UDP Scan(Stealth)" "Nmap All Scan(TCP)(Stealth)" "Nmap All Scan(UDP)(Stealth)" "hping3 scan" "hping3 scan(typeofservice)" "hping3 scan(Fragmented & Spoofed IP)" "Previous Menu")
	select actc in "${actcon[@]}"; do
    case $actc in
		"Nmap TCP Scan(Stealth)")
		read -p '\e[1;31mDomain or IP?: \e[0m' domain
		echo -en '\n'
		sudo nmap -sT -Pn $domain > $domain"nmaptcp".txt
		echo -en '\n'
                echo -en '\n'
                auditing_tools
                COLUMNS=12
		;;
		"Nmap UDP Scan(Stealth)")
		read -p $'\e[1;31mDomain or IP?: \e[0m' domain
		echo -en '\n'
		sudo nmap -sU -Pn $domain > $domain"nmapudp".txt
		echo -en '\n'
                echo -en '\n'
                auditing_tools
                COLUMNS=12
		;;
		"Nmap All Scan(TCP)(Stealth)")
		read -p $'\e[1;31mDomain or IP?: \e[0m' domain
		echo -en '\n'
		sudo nmap -A -Pn $domain > $domain"nmapall".txt
		echo -en '\n'
                echo -en '\n'
                auditing_tools
                COLUMNS=12
		;;
		"hping3 scan")
		read -p $'\e[1;31mIP Address?: \e[0m' ipaddr
		echo -en '\n'
		sudo hping3 $ipaddr
		echo -en '\n'
                echo -en '\n'
                auditing_tools
                COLUMNS=12
		;;
		"hping3 scan(website)")
                read -p $'\e[31m#of packets to send?: \e[0m' pack
		echo -en '\n'
                read -p $'\e[31mwebsite?: \e[0m' web
                echo -en '\n'
                sudo hping3 -c $pack -S $web -I $winterface
                echo -en '\n'
                echo -en '\n'
                auditing_tools
                COLUMNS=12
		;;
		"hping3 scan(Fragmented Packets)")
		read -p $'\e[31m#of packets to send?: \e[0m' pack
                read -p $'\e[31mWebsite?: \e[0m' web
		sudo hping3 -c $pack -S $web -V --fast -I $winterface -f
                echo -en '\n'
                auditing_tools
                COLUMNS=12
		;;
		"Previous Menu")
		break 1;;
		esac
		done
		auditing_tools
		COLUMNS=12
		;;
	"Main Menu")
	echo -en '\n'
	main_menu
	;;
esac
done
}
	main_menu
password_cracking() {
	#PASSWORD CRACKING start here
	echo -en '\n'
	PS3=("#crack: ")
	pwcrack=("Convert to .hc22000" "Aircrack Dictionary Attack" "Hashcat Dictionary Attack" "Generate Password List" "Main Menu")
	select pcrack in "${pwcrack[@]}"; do
	case $pcrack in
	"Convert to .hc2200")
        if [ /usr/bin/hcxpcapngtool ]
        then
        echo -en '\n'
	read -p $'\e[1;31mcap file?: \e[0m' capfile
	read -p $'\e[1;31moutput?(.hash): \e[0m' output
	sleep 0.5
	sudo hcxpcapngtool -o $output $capfile
        echo -en '\n'
	password_cracking
        COLUMNS=12
	else
	echo $'\e[31mYou NEED to install hcxtools!!!\e[0m'
	fi
	;;
	"Aircrack Dictionary Attack")
        echo -en '\n'
        read -p $'\e[31mDictionary file?: \e[0m' wordlist
        read -p $'\e[31m.cap file?: \e[0m' capfile
	sudo aircrack-ng $capfile -w $wordlist
        echo -en '\n'
        password_cracking
        COLUMNS=12
	;;
	"Hashcat Dictionary Attack")
        echo -en '\n'
	read -p $'\e[1;31mHashfile?(with location): \e[0m' hashfile
	read -p $'\e[1;31mWordlist?: \e[0m' wordlist
	sleep 0.5
	sudo hashcat -a 0 -m 22000 $hashfile $wordlist
        echo -en '\n'
	sleep 0.5
	sudo hashcat -a 0 -m 22000 $hashfile $wordlist --show
        password_cracking
        COLUMNS=12
	;;
	"Generate Password List")
        echo -en '\n'
	PS3=("#wordlst:")
	wordlist=("Launch Cupp" "Launch Cupp (Interactive Mode)" "Character Based (Crunch)" "Pattern (Crunch)")
	select wrdlst in "{wordlst[@]}";do
	case $wrdlst in
	"Launch Cupp (Interactive Mode)")
        sudo cupp -i
	echo -en '\n'
        password_cracking
        COLUMNS=12
	;;
	"Character Based (Crunch)")
        tput setaf 1 ; echo "please seperate words or phrases by a space, not comma, as this will jumble all characters" ; tput sgr0
        read -p $'\e[31Words, Numbers, Symbols?(seperate w/ space): \e[0m' chars
        sudo crunch 1 1 -p $chars
        echo -en '\n'
        password_cracking
        COLUMNS=12
	;;
	"Pattern (Crunch)")
	echo "pattern, eg: @@god@@@@ where the only the @'s, ,'s, %'s, and ^'s will change."
        echo "@ will insert lower case characters"
        echo ", will insert upper case characters"
        echo "% will insert numbers"
        echo "^ will insert symbols"
        sleep 0.5
        read -p $'\e[31mPattern?: \e[0m' patt
        read -p $'\e[31mLength in number of pattern?' patnum
        read -p $'\e[31mOutput File Name?(exclude .txt): \e[0m' output
        sudo crunch $patnum $patnum -t $patt > $output.txt
        echo -en '\n'
        password_cracking
        COLUMNS=12
	;;
	"Previous Menu")
	break 1;;
	esac
	done
	echo -en '\n'
	password_cracking
	COLUMNS=12
	;;
	"Main Menu")
	echo -en '\n'
	main_menu
	;;
	esac
	done
}
clear
echo $'\e[31m\e[1mWelcome!\e[0m'
echo -en '\n'
sleep 0.5
echo $'\e[1;31m    _   __       __        ______               __                __   \e[0m'
echo $'\e[1;31m   / | / /___   / /_      /_  __/____   ____   / /_____    _____ / /_  \e[0m'
echo $'\e[1;31m  /  |/ // _ \ / __/______ / /  / __ \ / __ \ / // ___/   / ___// __ \ \e[0m'
echo $'\e[1;31m / /|  //  __// /_ /_____// /  / /_/ // /_/ // /(__  )_  (__  )/ / / / \e[0m'
echo $'\e[1;31m/_/ |_/ \___/ \__/       /_/   \____/ \____//_//____/(_)/____//_/ /_/  \e[0m'
sleep 1
echo -en '\n'
winterface=$(iwconfig 2>/dev/null | awk '/^[a-z]/ {print $1; exit}')
winterface2=$(iwconfig 2>/dev/null | grep "wlan1" | awk '{print $1; exit}')
winterface3=$(iwconfig 2>/dev/null | grep "wlan2" | awk '{print $1; exit}')
echo $'\e[1;31mAssigned interface is: \e[0m'
tput bold ; tput blink ; tput setaf 1 ; echo $winterface ; tput sgr0
echo $'\e[1;31mOther Interfaces: \e[0m'
tput bold ; tput setaf 1 ; echo $winterface2 ; tput sgr0
tput bold ; tput setaf 1 ; echo $winterface3 ; tput sgr0
echo -en '\n'
sleep 2
clear
#Begin Check if script has what it needs....

# List of commands and their corresponding packages
commands=("airgeddon" "wifite" "aircrack-ng" "macchanger" "hashcat" "airmon-ng" "ifconfig" "proxychains" "tor")

# Function to check if a command is present on the system and install it if needed
check_and_install_command() {
  local command_name=$1
  if command -v $command_name &> /dev/null
  then
    echo "$command_name is Present on your system."
  else
    echo "$command_name is NOT Present on your system, Installing..."
    sudo apt update && sudo apt install $command_name -y
  fi
}

# Loop over the commands
for command in "${commands[@]}"
do
  echo -en '\n'
  clear
  check_and_install_command $command
  echo -en '\n'
  sleep 0.01
done

# If you encounter errors, fix
clear
sleep 0.01
tput blink ; tput setaf 1 ; tput bold ; echo "If you encountered any errors at startup, please re-install the required dependencies and try again" ; tput sgr0
sleep 2
clear
echo $'\e[1;31m'
#BEGIN THE 'main_menu() { }' call to function @ main.
#____________________________________________________
main_menu() {
#FUNCTION MAIN MENU
#____________________________________________________
PS3=("#main: ")
options=("Device Options" "Auditing Tools" "Password Cracking" "Exit")
select opt in "${options[@]}"; do
case $opt in
"Device Options")
		device_options
	;;
"Auditing Tools")
		auditing_tools
	;;
"Password Cracking")
		password_cracking
	;;
"Exit")
exit;;
esac
done
}
generate_rsf() {

	if [ ~/routersploit/rsf.py = 1 ]
	then
		sudo python3 ~/routersploit/rsf.py
	else
		sudo apt-get install python3-pip &&
		git clone https://www.github.com/threat9/routersploit &&
		cd ~/routersploit &&
		sudo python3 -m pip install -r requirements.txt &&
		cd ~/routersploit &&
		sudo python3 rsf.py
	fi
}
main_menu
