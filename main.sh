#!/bin/bash
# Author: @github.com/raoshaab

############# Checking for pre-condition ###########

# Function to check if Burp Suite is running
function check_burp() {
    default_ip='127.0.0.1:8080'
    check=$(curl -s http://${default_ip}/ 2>/dev/null | grep Burp -o | head -n1)

    if [[ $check == Burp ]]; then
        echo "+------------------------------------------+"
        echo "|                                          |"
        echo "|         Burp Suite is running!          |"
        echo -e "+------------------------------------------+\n\n"
    else
        echo -e "\033[1;91m"
        echo "+----------------------------------------------- +"
        echo "|                  Error                         |"
        echo "| Burp Suite proxy is not running at (127.0.0.1:8080) |"
        echo -e "+-----------------------------------------------+\n\n"

        # To enter other IP address and port
        echo "Enter the Burp Suite IP and port (e.g., 192.168.1.1:9001):"
        exec < /dev/tty && read proxy && exec <&-

        check=$(curl -s ${proxy} 2>/dev/null | grep Burp -o | head -n1)
        if [[ $check == Burp ]]; then
            echo "+------------------------------------------+"
            echo "|                                          |"
            echo "|         Burp Suite is running!          |"
            echo -e "+------------------------------------------+\n\n"
            default_ip=${proxy}
        else
            echo -e "\033[1;91m"
            echo "+------------------------------------------------+"
            echo "|                  Error                         |"
            echo "| Burp Suite proxy is not running at (${proxy})|"
            echo -e "+---------------------------------------------+\n\n"
            banner
            exit
        fi
    fi
}

# Function to check internet connectivity
function check_internet() {
    ping 8.8.8.8 -c1 &>/dev/null
    if [ $? == 0 ]; then
        echo -e "\033[0;92m"
        echo "+------------------------------------------+"
        echo "|                                          |"
        echo "|         Internet is ready to go          |"
        echo -e "+------------------------------------------+\n\n"
    else
        echo -e "\033[1;91m"
        echo "+------------------------------------------+"
        echo "|               Error                      |"
        echo "|             No Internet                  |"
        echo -e "+------------------------------------------+\n\n"
        banner
        exit
    fi
}

# Function to check ADB and root access
function check_adb() {
    adb get-state >/dev/null 2>&1
    if [ $? == 0 ]; then
        echo "+------------------------------------------+"
        echo "|                                          |"
        echo "|                ADB Connected!            |"
        echo -e "+------------------------------------------+\n\n"
    else
        echo -e "\033[1;91m"
        echo "+------------------------------------------+"
        echo "|       ADB is not running                 |"
        echo "|               or                          |"
        echo "|   More than one emulator exists           |"
        echo -e "+------------------------------------------+\n\n"
        banner
        exit
    fi

    # Checking root access
    adb shell -n 'su -c ""' >/dev/null 2>&1
    if [ $? == 0 ]; then
        echo ' '
    else
        echo "+------------------------------------------+"
        echo "|                                          |"
        echo "|  Give root access to ADB from Superuser  |"
        echo "|                                          |"
        echo "|   If using Android Studio Emulator       |"
        echo "|   ==>  https://github.com/newbit1/rootAVD|"
        echo "|   For Genymotion https://t.ly/n_5F       |"
        echo -e "+------------------------------------------+\n\n"
        banner
        exit
    fi
}

# Function to move Burp Suite certificate to Android root folder
function move_certificate() {
    cert_check=$(adb shell 'su -c "ls /system/etc/security/cacerts|grep 9a5ba575.0"')
    res='y'
    # Checking existing Burp Suite certificate
    if [[ "$cert_check" == "9a5ba575.0" ]]; then
        echo -e "\033[1;91m"
        echo -e "The Burp Suite certificate already exists. This will replace the existing one.\n"
        echo -e "\033[0;92mIf you want to replace it, press Y. If not, press N."
        exec < /dev/tty && read res && exec <&-
    fi

    if [[ $res == 'N' || $res == 'n' ]]; then
        echo 'No changes in Burp Suite certificate.'
    elif [[ $res == 'Y' || $res == 'y' ]]; then
        wget --quiet ${default_ip}/cert -O cacert.der
        openssl x509 -inform DER -in cacert.der -out cacert.pem
        name=$(echo $(openssl x509 -inform PEM -subject_hash_old -in cacert.pem | head -1).0)
        mv cacert.pem $name
        echo "Copying the Burp Suite certificate to the Android system..."
        adb push $name /sdcard/ >/dev/null 2>&1
        adb remount >/dev/null 2>&1
        adb shell -n "su -c 'remount'" >/dev/null 2>&1
        if [ $? == 0 ]; then
            echo ' '
        else
            adb shell -n "su -c 'mount -o r,w /'" >/dev/null 2>&1
        fi
        adb shell -n "su -c 'mv /sdcard/$name /system/etc/security/cacerts'" >/dev/null 2>&1
        adb shell -n "su -c 'chmod 644 /system/etc/security/cacerts/$name'" >/dev/null 2>&1
        echo "+------------------------------------------+"
        echo "|                                          |"
        echo "|      Certificate moved successfully      |"
        echo -e "+------------------------------------------+\n\n"
        echo "The device will reboot now."
        echo "adb reboot"
    fi
}

# Function to display the banner
function banner() {
    echo -e "
    mmmmm                         mm              #          mmmm
    #   \"#  mmm   m mm            ##   m mm    mmm#   m mm  m\"  \"m
    #mmm#\" \"#  #  \"#\"  #          #  #  #\"  #  #\" \"#   #\"  \" #  m #
    #      #\"\"\"\"  #   #   \"\"\"    #mm#  #   #  #   #   #     #    #
    #      \"#mm\"  #   #         #    # #   #  \"#m##   #      #mm#
    
    #Author: github.com/@raoshaab"
}

# Main execution flow
banner
check_burp
check_internet
check_adb
move_certificate
