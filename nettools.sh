#!/bin/bash
echo $'\e[1;31m'
COLUMNS=12
android_menu() {
COLUMNS=12
clear
asci_intro
echo -en '\n'
PS3=("#android: ")
andmen=("Install ADB Kali" "PhoneSploit" "CiLocks" "ADB-Toolkit" "SmsEye3" "GalleryEye" "LocationEye" "Previous Menu" "Exit")
COLUMNS=12
echo -en '\n'
read -p $'\e[1;31mUsername?: \e[0m' usrv
echo -en '\n'
echo $'\e[1;36m'
select and in "${andmen[@]}"; do
case $and in
"Install ADB Kali")
if [ /usr/bin/fastboot ]
then
echo $'\e[1;31mFastboot is already installed\e[0m'
else
sudo apt install fastboot &&
clear &&
echo $'\e[1;31mFastboot has been installed\e[0m'
fi
if [ /usr/bin/adb ]
then
echo $'\e[1;31mADB is already installed\e[0m'
else
sudo apt install adb &&
clear &&
echo $'\e[1;31mADB has been installed\e[0m'
fi &&
sleep 3 &&
android_menu
;;
"PhoneSploit")
cd /home/$usrv &&
sudo -u $usrv sudo git clone https://github.com/AzeemIdrisi/PhoneSploit-Pro &&
cd PhoneSploit-Pro &&
echo $'\e[1;31mexit script to launch\e[0m' &&
sleep 3 &&
android_menu
;;
"CiLocks")
cd /home/$usrv &&
sudo -u $usrv sudo git clone https://github.com/tegal1337/CiLocks &&
cd CiLocks &&
echo $'\e[1;31mexit script to launch\e[0m' &&
sleep 3 &&
android_menu
;;
"ADB-Toolkit")
cd /home/$usrv &&
sudo -u $usrv sudo git clone https://github.com/ASHWIN990/ADB-Toolkit &&
cd ADB-Toolkit &&
echo $'\e[1;31mexit script to launch\e[0m' &&
sleep 3 &&
android_menu
;;
"SmsEye3")
cd /home/$usrv &&
sudo -u $usrv sudo git clone https://github.com/AbyssalArmy/SmsEye3 &&
cd SmsEye3 &&
echo $'\e[1;31mexit script to launch\e[0m' &&
sleep 3 &&
cd ~ &&
android_menu
;;
"GalleryEye")
cd /home/$usrv &&
sudo -u $usrv sudo git clone https://github.com/AbyssalArmy/GalleryEye &&
cd GalleryEye &&
echo $'\e[1;31mexit script to launch\e[0m' &&
sleep 3 &&
cd ~ &&
android_menu
;;
"LocationEye")
cd /home/$usrv &&
sudo -u $usrv sudo git clone https://github.com/AbyssalArmy/LocationEye &&
cd LocationEye &&
echo $'\e[1;31mexit script to launch\e[0m' &&
sleep 3 &&
cd ~ &&
android_menu
;;
"Previous Menu")
clear
main_menu
;;
"Exit")
exit
;;
esac
done
echo $'\e[0m'
}
asci_intro() {
echo $'\e[1;32m--------------------------------------------------------------------------\e[0m'
echo $'\e[1;32m|\e[1;31m     _   __       __        ______               __                __   \e[1;32m|\e[0m'
echo $'\e[1;32m|\e[1;31m    / | / /___   / /_      /_  __/____   ____   / /_____    _____ / /_  \e[1;32m|\e[0m'
echo $'\e[1;32m|\e[1;31m   /  |/ // _ \ / __/______ / /  / __ \ / __ \ / // ___/   / ___// __ \ \e[1;32m|\e[0m'
echo $'\e[1;32m|\e[1;31m  / /|  //  __// /_ /_____// /  / /_/ // /_/ // /(__  )_  (__  )/ / / / \e[1;32m|\e[0m'
echo $'\e[1;32m|\e[1;31m /_/ |_/ \___/ \__/       /_/   \____/ \____//_//____/(_)/____//_/ /_/  \e[1;32m|\e[0m'
echo $'\e[1;32m--------------------------------------------------------------------------\e[0m'
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

aarmitage() {
if [ /usr/bin/armitage ]
then
sudo msfdb init &&
sudo armitage
else
sudo apt install armitage -y &&
clear &&
sudo msfdb init &&
sudo armitage
fi
}
commixx() {
if [ /usr/bin/commix ]
then
commix --help
else
sudo apt install commix -y &&
clear &&
commix --help
fi
}
eevilginx2() {
if [ /usr/bin/evilginx2 ]
then
evilginx2
else
sudo apt install evilginx2 -y &&
clear &&
evilginx2
fi
}
holeheehee() {
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
	read -p $'\e[31mmail to search?: \e[0m' scan
	read -p $'\e[1;31mEnter Username: \e[0m' ur
	su -l $ur -c "holehe $scan"
	echo -en '\n'
	echo $'\e[1;31m'
	COLUMNS=12
	auditing_tools
}
hhydra() {
if [ /usr/bin/hydra ]
then
hydra -h
else
sudo apt install hydra &&
clear &&
hydra -h
fi
}
payloads() {
echo -en '\n'
COLUMNS=12
asci_intro
echo -en '\n'
PS3=("#payload: ")
payload_menu=("Venom C2 Framework" "TheFatRat" "Previous Menu" "Main Menu")
select pa in "${payload_menu[@]}"; do
case $pa in
"Venom C2 Framework")
echo -en '\n'
echo $'\e[1;31mInstalling Venom C2 Framework\e[0m'
git clone https://github.com/r00t-3x10it/venom &&
cd venom &&
sudo ./venom.sh
payloads
COLUMNS=12
;;
"TheFatRat")
echo -en '\n'
echo $'\e[1;31mInstalling TheFatRat...\e[0m'
echo -en '\n'
echo $'\e[1;31mThis may take a while...\e[0m'
sleep 1 &&
git clone https://github.com/screetsec/TheFatRat &&
cd TheFatRat &&
sudo bash update &&
sudo bash setup.sh &&
sudo fatrat
sleep 1 &&
echo $'\e[1;31mYou can launch by using: sudo fatrat\e[0m'
echo -en '\n'
payloads
COLUMNS=12
;;
"Previous Menu")
clear
auditing_tools
COLUMNS=12
;;
"Main Menu")
clear
main_menu
COLUMNS=12
;;
esac
done
}
skipfish() {
	echo -en '\n'
	clear
	read -p $'\e[31mURL?\e[0m' URL
	read -p $'\e[31mOutput loc?: \e[0m' OUTPUT
	asci_intro
	echo -en '\n'
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
ssqlmap() {
if [ /usr/bin/sqlmap ]
then
sqlmap --help
else
sudo apt install sqlmap &&
clear &&
sqlmap --help
fi
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
echo "type e to return"
while [ $i < "e" ]; do
cat << EOF
	"bevigil"
	"binaryedge"
	"bufferoverun"
	"Censys ID"
	"Secret"
	"criminalip"
	"fullhunt"
	"Github"
	"Hunter"
	"hunterhow"
	"Intelx"
        "netlas"
        "onyphe"
        "PentestTools"
        "ProjectDiscovery"
        "RocketReach"
        "Securitytrail"
        "Tomba Key"
        "Secret"
        "virustotal"
	"zoomeye"
	"Previous Menu"
EOF
done
	auditing_tools
}
infoga() {
read -p $'\e[1;31mUsername?: \e[0m' una
if [ -d /home/$una/Infoga ]
then
echo "Infoga Already Exists"
cd /home/$una/Infoga &&
sudo python setup.py install &&
sudo python infoga.py
else
echo "Installing Infoga"
sudo git clone https://github.com/GiJ03/Infoga &&
cd /home/$una/Infoga &&
sudo python setup.py install &&
sudo python infoga.py
fi
}
moriarty() {
read -p $'\e[1;31mUsername?: \e[0m' una
if [ -d /home/$una/Moriarty-Project ]
then
echo "Moriarty-Project Already Exists"
cd /home/$una/Moriarty-Project &&
sudo bash install.sh &&
sudo bash run.sh
else
echo "Installing Moriarty-Project"
sudo git clone https://github.com/AzizKpln/Moriarty-Project &&
cd Moriarty-Project &&
sudo bash install.sh &&
sudo bash run.sh
fi
}
spiderfoot() {
read -p $'\e[1;31mUsername?: \e[0m' una
if [ -d /home/$una/spiderfoot ]
then
echo "spiderfoot already exists"
cd /home/$una/spiderfoot &&
echo $'\e[1;31mYou can run spiderfoot by running: python3 ./sf.py -l (localip:port)\e[0m'
else
echo "installing spiderfoot"
sudo git clone https://github.com/smicallef/spiderfoot &&
cd spiderfoot &&
pip3 install -r requirements.txt &&
echo $'\e[1;31mYou can run spiderfoot by running: python3 ./sf.py -l (localip:port)\e[0m'
sleep 1
fi
}
gitrob() {
if [ /usr/bin/go ]
then
echo "golang is installed"
else
echo "installing golang"
sudo apt update &&
sudo apt upgrade &&
sudo apt install golang
fi
read -p $'\e[1;31mUsername?: \e[0m' una
if [ -d /home/$una/gitrob ]
then
echo "gitrob already exists at: $dirs"
cd /home/$una/gitrob &&
make build &&
echo $'\e[1;31mYou can run gitrob with the command: ./bin/gitrob-(ARCH) (sub-command)\e[0m'
else
echo "installing gitrob"
sudo git clone https://github.com/narendrakadali/gitrob &&
cd gitrob &&
sudo make build &&
echo $'\e[1;31mYou can run gitrob with the command: ./bin/gitrob-(ARCH) (sub-command)\e[0m'
fi
}
recondog() {
read -p $'\e[1;31mUsername?: \e[0m' una
if [ -d /home/$una/ReconDog ]
then
echo "ReconDog already exists at: $dirs"
cd /home/$una/ReconDog &&
pip3 install -r requirements.txt &&
sudo python dog
else
echo "Installing ReconDog"
sudo git clone https://github.com/s0md3v/ReconDog &&
cd ReconDog &&
pip3 install -r requirements.txt &&
sudo python dog
fi
}
duckscrap() {
COLUMNS=12

}

pixiewps() {
echo "pixiewps"
}
reaver() {
echo "reaver"
}
winterface_change() {
read -p $'\e[1;31mInterface Name?: \e[0m' newint
winterface="$newint"
}
device_options() {
#Device-Options start here
	clear
	echo -en '\n'
	asci_intro
	echo -en '\n'
	COLUMNS=12
	PS3=("#dev: ")
	devoptions=("Change Assigned Interface" "Randomize Device Info" "List IP Address" "List MAC" "Proxychains Firefox Session" "Main Menu")
	echo $'\e[1;32m'
	select devop in "${devoptions[@]}"; do
	case $devop in
	"Change Assigned Interface")
        winterface_change
	;;
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
	sleep 5
	device_options
        COLUMNS=12
	;;
	"List MAC")
        echo -en '\n'
	sudo macchanger -s $winterface
        echo -en '\n'
	sleep 5
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
echo $'\e[0m'
}
auditing_tools() {
	#Auditing-Tools start here
	clear
	echo -en '\n'
	COLUMNS=12
	asci_intro
	echo -en '\n'
	PS3=("#aud: ")
	audit=("Script(Pre-Made)" "Script(Kali-Based)" "Passive Recon" "Active Recon" "Payloads Menu" "Main Menu")
	echo $'\e[1;31m'
	select aud in "${audit[@]}"; do
	case $aud in
		"Script(Pre-Made)")
		clear
        	echo -en '\n'
		PS3=("#kiddie: ")
		madescr=("Set Interface Into Monitor Mode" "Set Interface Into Managed Mode" "Launch Airgeddon" "Launch Wifite" "Wifite(client only)" "Wifite Auto Attack(DEAUTH)" "Wifite Auto Attack(NO DEAUTH)" "Launch Wifite /w rockyou" "Launch Wifite(2.4gz & 5g)(WPA ONLY)" "Install & Run Routersploit" "Previous Menu")
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
		"Wifite(client only)")
		echo -en '\n'
		sudo wifite --all --clients-only
		echo -en '\n'
		;;
		"Wifite Auto Attack(DEAUTH)")
		echo -en '\n'
		cd ~ &&
		sudo wifite -c 1-11 --clients-only --all --skip-crack --no-pmkid -inf -p 30
		echo -en '\n'
		;;
		"Wifite Auto Attack(NO DEAUTH)")
		echo -en '\n'
		cd ~ &&
		sudo wifite -c 1-11 --clients-only --skip-crack --wps --pmkid -inf -p 30
		;;
		"Launch Wifite /w rockyou")
		echo -en '\n'
		sudo wifite -mac --dict /usr/share/wordlists/rockyou.txt
                echo -en '\n'
                auditing_tools
                COLUMNS=12
		;;
		"Launch Wifite(2.4gz & 5g)(WPA ONLY)")
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
	clear
        echo -en '\n'
	asci_intro
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
	clear
	echo -en '\n'
	asci_intro
	echo -en '\n'
	PS3=("#passcon: ")
	passcon=("Infoga" "Moriarty" "Spiderfoot" "GitRob" "ReconDog" "holehe" "p0f Scan" "whois lookup" "dig lookup" "nslookup" "DNSenum" "Open Shodan" "whatweb" "Previous Menu")
	select passc in "${passcon[@]}"; do 
	case $passc in
		"Infoga")
                echo -en '\n'
		infoga
                echo -en '\n'
                COLUMNS=12
		;;
		"Moriarty")
                echo -en '\n'
		moriarty
                echo -en '\n'
                COLUMNS=12
		;;
		"Spiderfoot")
                echo -en '\n'
		spiderfoot
                echo -en '\n'
                COLUMNS=12
		;;
		"GitRob")
                echo -en '\n'
		gitrob
                echo -en '\n'
                COLUMNS=12
		;;
		"ReconDog")
                echo -en '\n'
		recondog
                echo -en '\n'
                COLUMNS=12
		;;
		"holehe")
		echo -en '\n'
		holeheehee
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
	clear
	echo -en '\n'
	asci_intro
	echo -en '\n'
	PS3=("#actcon: ")
	actcon=("Angry IP" "Armitage" "Commix" "Evilginx2" "Hydra" "Sqlmap" "Nmap TCP Scan(Stealth)" "Nmap UDP Scan(Stealth)" "Nmap All Scan(TCP)(Stealth)" "Nmap All Scan(UDP)(Stealth)" "hping3 scan" "hping3 scan(typeofservice)" "hping3 scan(Fragmented & Spoofed IP)" "Previous Menu")
	select actc in "${actcon[@]}"; do
    case $actc in
		"Angry IP")
		if [ /usr/bin/ipscan ]
		then
		echo "AngryIP is installed"
		else
		sudo apt install ipscan &&
		echo -en '\n'
		echo "installed AngryIP"
		echo -en '\n'
		sudo ipscan
		fi
		;;
		"Armitage")
		clear
		aarmitage
		echo -en '\n'
		auditing_tools
		COLUMNS=12
		;;
		"Commix")
		clear
		commixx
		echo -en '\n'
		auditing_tools
		COLUMNS=12
		;;
		"Evilginx2")
		clear
		eevilginx2
                echo -en '\n'
                auditing_tools
                COLUMNS=12
		;;
		"Hydra")
		clear
		hhydra
		echo -en '\n'
                auditing_tools
                COLUMNS=12
		;;
		"Sqlmap")
		clear
		ssqlmap
		echo -en '\n'
		auditing_tools
		COLUMNS=12
		;;
		"Nmap TCP Scan(Stealth)")
		read -p '\e[1;31mDomain or IP?: \e[0m' domain
		echo -en '\n'
		sudo nmap -sT -Pn $domain > $domain"nmaptcp".txt
		echo -en '\n'
                auditing_tools
                COLUMNS=12
		;;
		"Nmap UDP Scan(Stealth)")
		read -p $'\e[1;31mDomain or IP?: \e[0m' domain
		echo -en '\n'
		sudo nmap -sU -Pn $domain > $domain"nmapudp".txt
		echo -en '\n'
                auditing_tools
                COLUMNS=12
		;;
		"Nmap All Scan(TCP)(Stealth)")
		read -p $'\e[1;31mDomain or IP?: \e[0m' domain
		echo -en '\n'
		sudo nmap -A -Pn $domain > $domain"nmapall".txt
                echo -en '\n'
                auditing_tools
                COLUMNS=12
		;;
		"hping3 scan")
		read -p $'\e[1;31mIP Address?: \e[0m' ipaddr
		echo -en '\n'
		sudo hping3 $ipaddr
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
	"Payloads Menu")
	clear
	payloads
	echo -en '\n'
	main_menu
	;;
	"Main Menu")
	echo -en '\n'
	main_menu
	;;
esac
done
echo $'\e[0m'
}
	main_menu
password_cracking() {
	clear
	#PASSWORD CRACKING start here
	echo -en '\n'
	asci_intro
	echo -en '\n'
	echo $'\e[1;32m'
	PS3=("#crack: ")
	pwcrack=("Convert to .hc22000" "Aircrack Dictionary Attack" "Hashcat Dictionary Attack" "Generate Password List" "Main Menu")
	COLUMNS=12
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
	echo $'\e[0m'
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
commands=("airgeddon" "wifite" "aircrack-ng" "macchanger" "hashcat" "airmon-ng" "ifconfig" "proxychains" "tor" "spiderfoot" "dnsrecon" "dnsenum")

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
main_menu() {
#FUNCTION MAIN MENU
#____________________________________________________
clear
COLUMNS=12
asci_intro
echo -en '\n'
PS3=("#main: ")
options=("Device Options" "Auditing Tools" "Password Cracking" "Android Hacking Menu" "Exit")
echo $'\e[1;36m'
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
"Android Hacking Menu")
		android_menu
	;;
"Exit")
exit;;
esac
done
echo $'\e[0m'
}
main_menu
