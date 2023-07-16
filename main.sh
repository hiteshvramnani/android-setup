#!/bin/bash 
#Author: @github.com/raoshaab

# Checking for pre-conditions

# Function for Burp Suite
function burp() {
    default_ip='127.0.0.1:8080'
    check=$(curl -s http://${default_ip}/ 2>/dev/null | grep Burp -o | head -n1)

    if [[ $check == Burp ]]; then
        echo "+------------------------------------------+"
        echo "|                                          |"
        echo "|         Burp Suite Running done!!        |"
        echo -e "+------------------------------------------+\n\n"
    else
        echo -e "\033[1;91m" 
        echo "+----------------------------------------------- +"
        echo "|                  Error                         |" 
        echo "| Burp Suite proxy not running at (127.0.0.1:8080) |" 
        echo -e "+-----------------------------------------------+\n\n" 
      
        # To enter other IP address and port 
        echo "Enter the Burp Suite IP and port (e.g., 192.168.1.1:9001):" 
        exec < /dev/tty && read proxy && exec <&-

        check=$(curl -s ${proxy} 2>/dev/null | grep Burp -o | head -n1)
        if [[ $check == Burp ]]; then
            echo "+------------------------------------------+"
            echo "|                                          |"
            echo "|         Burp Suite Running done!!        |"
            echo -e "+------------------------------------------+\n\n"
            default_ip=${proxy}
        else
            echo -e "\033[1;91m" 
            echo "+------------------------------------------------+"
            echo "|                  Error                         |" 
            echo "| Burp Suite proxy not running at (${proxy})|" 
            echo -e "+---------------------------------------------+\n\n" && banner && exit
        fi
    fi
}

# Function for internet connectivity 
function net() {
    ping 8.8.8.8 -c1 &>/dev/null 
    if [ $? == 0 ]; then
        echo -e "\033[0;92m"
    else 
        echo -e "\033[1;91m" 
        echo "+------------------------------------------+"
        echo "|               Error                      |"
        echo "|             No Internet                  |" 
        echo -e "+------------------------------------------+\n\n" && banner && exit
    fi
}

# Function for ADB & Root Access 
function adb_check() {
    adb get-state >/dev/null 2>&1 
    if [ $? == 0 ]; then
        echo "+------------------------------------------+"
        echo "|                                          |"
        echo "|                ADB Connected!!           |"
        echo -e "+------------------------------------------+\n\n"
    else  
        echo -e "\033[1;91m" 
        echo "+------------------------------------------+"
        echo "|       ADB is not running                 |"
        echo "|               or                          |"
        echo "|   More than one emulator exists           |" 
        echo -e "+------------------------------------------+\n\n" && banner && exit
    fi

    # Checking root access
    adb shell -n 'su -c ""' >/dev/null 2>&1
    if [ $? == 0 ]; then
        echo ' '
    else 
        echo "+------------------------------------------+"
        echo "|                                          |"
        echo "|  Give root Access to ADB from Superuser  |"
        echo "|                                          |"
        echo "|   If using Android Studio Emulator       |"
        echo "|   ==>  https://github.com/newbit1/rootAVD|"
        echo "|   For Genymotion https://t.ly/n_5F       |"
        echo -e "+------------------------------------------+\n\n" && banner && exit
    fi
}

# Before Starting
function before_start() {
    # Moving Certificate for Android via ADB
    function burpcer() {
        cert_check=$(adb shell 'su -c "ls /system/etc/security/cacerts|grep 9a5ba575.0"')
        res='y'
        
        # Checking existing Burp Suite certificate
        if [[ "$cert_check" == "9a5ba575.0" ]]; then 
            echo -e "\033[1;91m" 
            echo -e "Already Burp Suite certificate found. This will replace the existing one.\n"
            
            echo -e "\033[0;92mIf you want to replace it, press Y. If not, press N/n:" 
            exec < /dev/tty && read res && exec <&-
        fi

        if [[ $res == 'N' || $res == 'n' ]]; then  
            echo 'No changes in Burp Suite certificate.'
        elif [[ $res == 'Y' || $res == 'y' ]]; then 
            wget --quiet ${default_ip}/cert -O cacert.der 
            openssl x509 -inform DER -in cacert.der -out cacert.pem
            name=$(echo $(openssl x509 -inform PEM -subject_hash_old -in cacert.pem | head -1).0)
            mv cacert.pem $name
            adb push $name /sdcard/ >/dev/null 2>&1
            adb remount >/dev/null 2>&1  
            adb shell -n "su -c 'remount'" >/dev/null 2>&1 
            if [ $? == 0 ]; then 
                echo ' ' 
            else 
                adb shell -n "su -c 'mount -o r,w /'"  >/dev/null 2>&1 
            fi
            adb shell -n "su -c 'mv /sdcard/$name /system/etc/security/cacerts'" >/dev/null 2>&1 
            adb shell -n "su -c 'chmod 644 /system/etc/security/cacerts/$name'" >/dev/null 2>&1 

            echo "+------------------------------------------+"
            echo "|                                          |"
            echo "|      Certificate Moved Successfully      |"
            echo -e "+------------------------------------------+\n\n"
            echo "Device will reboot now :><: " 
            echo "adb reboot &"
        fi
    }

    # All Apps 
    function andro_apps() {
        # ProxyToggle
        prox_app=$(adb shell "pm list packages -3 | cut -f 2 -d \":\" | grep com.kinandcarta.create.proxytoggle" | tr -d '\r')
        if [[ "$prox_app" = "com.kinandcarta.create.proxytoggle" ]]; then
            echo 'ProxyToggle is already installed.'
        else
            wget --quiet https://github.com/theappbusiness/android-proxy-toggle/releases/download/v1.0.1/Proxy.Toggle.v1.0.1.zip
            unzip -q Proxy.Toggle.v1.0.1.zip 
            adb install -t -r proxy-toggle.apk >/dev/null 2>&1
            adb shell pm grant com.kinandcarta.create.proxytoggle android.permission.WRITE_SECURE_SETTINGS 
            echo "+------------------------------------------+"
            echo "|                                          |"
            echo "|            Proxy App installed           |"
            echo -e "+------------------------------------------+\n\n"
        fi

        # ADB WiFi
        prox_app=$(adb shell "pm list packages -3 | cut -f 2 -d \":\" | grep com.sujanpoudel.adbwifi" | tr -d '\r')
        if [[ "$prox_app" == "com.sujanpoudel.adbwifi" ]]; then
            echo 'ADB WiFi is already installed.'
        else
            wget -q https://github.com/raoshaab/Andro_set/raw/main/assets/adb_wifi.apk -O wifiadb.apk
            adb install -t -r wifiadb.apk
            echo "+------------------------------------------+"
            echo "|                                          |"
            echo "|         ADB WiFi App installed           |"
            echo -e "+------------------------------------------+\n\n"
        fi

        # ProxyDroid
        prox_app=$(adb shell "pm list packages -3 | cut -f 2 -d \":\" | grep org.proxydroid" | tr -d '\r')
        if [[ "$prox_app" == "org.proxydroid" ]]; then
            echo 'ProxyDroid is already installed.'
        else
            wget -q https://github.com/raoshaab/Andro_set/raw/main/assets/org.proxydroid.apk -O proxydroid.apk
            adb install -t -r proxydroid.apk
            echo "+------------------------------------------+"
            echo "|                                          |"
            echo "|         ProxyDroid App installed         |"
            echo -e "+------------------------------------------+\n\n"
        fi
    }

    # PC Tools
    function pc_tools() {
        # JADX - Dex to Java decompiler, apktool, Android Screen Share 
        (jadx --version | scrcpy -v && apktool -version) &>/dev/null  
        if [[ $? != 0 ]]; then
            echo 'Installing PC Tools...' 
            apt-get -qq install jadx scrcpy apktool -y &>/dev/null 
           
            echo "+------------------------------------------+"
            echo "|                                          |"
            echo "|     JADX, Apktool, Scrcpy installed     |"
            echo -e "+------------------------------------------+\n\n"
      
        else
            echo "+------------------------------------------+"
            echo "|                                          |"
            echo "|  JADX, Apktool, Scrcpy already installed |"
            echo -e "+------------------------------------------+\n\n"
        fi

        # Frida and Objection
        (frida --version && objection version) &>/dev/null
        if [ $? == 0 ]; then 
            echo "+------------------------------------------+"
            echo "|                                          |"
            echo "|   Frida and Objection already installed  |"
            echo -e "+------------------------------------------+\n\n"
        else
            pip3 install frida frida-tools objection &>/dev/null 
            
            echo "+------------------------------------------+"
            echo "|                                          |"
            echo "|         Frida setup ready                |"
            echo -e "+------------------------------------------+\n\n"
        fi
    }

    # Android Frida Server
    function frida_ando() {
        # Checking for Frida server in Android 
        frida_android=$(adb shell "frida-server --version" 2>/dev/null )
        check=$(echo $frida_android | grep -o '\.' | head -n1)
        if [[ $check = '.' ]]; then 
            echo -e "\033[1;91mFrida server is already installed with version ${frida_android} \n\n \033[0;92mIf you want to upgrade or reinstall, press Y/y."
            exec < /dev/tty && read res && exec <&-
            if [[ $res == 'Y' || $res == 'y' ]]; then 
                magisk_version=$(adb shell "magisk -v | cut -d ':' -f2" 2>/dev/null)
                if [[ $magisk_version == "MAGISK" ]]; then  
                    # Magisk will flash Frida server module which autostarts on reboot
                    magisk_module
                else 
                    frida_manual
                fi
            else     
                echo 'Frida server is already installed.'  
            fi 
        elif [[ $check = '' ]]; then  
            magisk_version=$(adb shell "magisk -v | cut -d ':' -f2" 2>/dev/null)
            if [[ $magisk_version == "MAGISK" ]]; then  
                # Magisk will flash Frida server module which autostarts on reboot
                magisk_module
            else 
                # Downloading Frida server from source 
                frida_manual
            fi 
        else
            echo "Function not working."
        fi
    }

    # Function to fix Frida server version mismatch
    function frida_mismatch() {
        lat_frida_version=$(curl -IkLs -o /dev/null -w %{url_effective}  https://github.com/frida/frida/releases/latest | grep -o "[^/]*$" | sed "s/v//g")
        
        pc_version=$(frida --version 2>/dev/null)
        android_version=$(adb shell -n 'sh -c "/data/local/tmp/frida-server --version"'  2>/dev/null)

        echo -e " Latest Version  => ${lat_frida_version} \n Pc version      => ${pc_version} \n Android Version => ${android_version}"

        if [[ ${pc_version} != ${android_version} ]]; then 
            if [[ ${lat_frida_version} != ${pc_version} ]]; then 
                echo -e "\n\tPc Version is outdated.\n"
                echo "Downloading the latest version..."
                pip3 install frida --upgrade &>/dev/null 
                echo -e "\n\nLatest version installed."
            elif [[ ${lat_frida_version} != ${android_version} ]]; then 
                frida_android 
            fi
        elif [[ ${android_version} == ${pc_version} ]]; then 
            echo -e "\n\n Same Version in Android (${android_version}) and PC (${pc_version})"  
        fi
    }

    # Install Magisk (for Genymotion)
    function install_magisk() {
        # If device == genymotion 
        # Then 
        adb push magisk.zip /sdcard/
        adb shell "/system/bin/flash-archive.sh /sdcard/magisk.zip"
    }

    burpcer
    pc_tools
    andro_apps
    frida_ando
}

# Main menu
function start() {
    banner      
    echo -e "\033[0;37m"
    echo -e "\n1. All"
    echo "2. Move Burp Suite Certificate to Android root folder"
    echo "3. PC Tools (JADX, Frida, Objection, Android Screen Control & Mirror)"
    echo "4. Android Frida Server"
    echo "5. Fix Frida Server Version Mismatch"
    echo "6. Android Apps (ProxyToggle, ProxyDroid, ADB WiFi)"
    echo "0. Exit"
    echo -e "\e[3$(( $RANDOM * 6 / 32767 + 1 ))m"
    echo -e "Select an option:"
    # Allows us to read user input below, assigns stdin to keyboard and then again to script
    exec < /dev/tty && read option && exec <&- && clear

    # Acting on the user input
    case $option in
    1) all
    ;;
    2) net; adb_check; burpcer
    ;;
    3) net; pc_tools   
    ;;
    4) net; adb_check; frida_ando
    ;;
    5) net; adb_check; frida_mismatch
    ;;
    6) net; adb_check; andro_apps
    ;;
    0) banner; exit
    ;;
    esac 
    start       
}

start
