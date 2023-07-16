#!/bin/bash
#Author: @github.com/raoshaab

#############Checking for pre-condition###########

#For Burpsuite
function burp() {
    default_ip='127.0.0.1:8080'
    check=$(curl -s http://${default_ip}/ 2>/dev/null | grep Burp -o | head -n1)

    if [[ $check == Burp ]]; then
        echo "+------------------------------------------+"
        echo "|                                          |"
        echo "|         Burpsuite Running done !!        |"
        echo -e "+------------------------------------------+\n\n"

    else
        echo -e "\033[1;91m"
        echo "+----------------------------------------------- +"
        echo "|                  Error                         |"
        echo "| Burpsuite proxy not running at(127.0.0.1:8080) |"
        echo -e "+-----------------------------------------------+\n\n"

        #To enter other Ip address and port
        echo "Enter the Burpsuite Ip and port i.e 192.168.1.1:9001"
        exec < /dev/tty && read proxy && exec <&-

        check=$(curl -s ${proxy} 2>/dev/null | grep Burp -o | head -n1)
        if [[ $check == Burp ]]; then
            echo "+------------------------------------------+"
            echo "|                                          |"
            echo "|         Burpsuite Running done !!        |"
            echo -e "+------------------------------------------+\n\n"
            default_ip=${proxy}

        else
            echo -e "\033[1;91m"
            echo "+------------------------------------------------+"
            echo "|                  Error                         |"
            echo "| Burpsuite proxy not running at (${proxy})|"
            echo -e "+---------------------------------------------+\n\n" && banner && exit
        fi
    fi
}

#For Internet connectivity
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

####### For adb & Root Access
function adb_check() {
    adb get-state >/dev/null 2>&1
    if [ $? == 0 ]; then
        echo "+------------------------------------------+"
        echo "|                                          |"
        echo "|                adb Connected !!          |"
        echo -e "+------------------------------------------+\n\n"
    else
        echo -e "\033[1;91m"
        echo "+------------------------------------------+"
        echo "|       adb is not running                 |"
        echo "|               oR                         |"
        echo "|   More than one emulator exits           |"
        echo -e "+------------------------------------------+\n\n" && banner && exit
    fi
    #checking root access
    adb shell -n 'su -c ""' >/dev/null 2>&1
    if [ $? == 0 ]; then
        echo ' '

    else
        echo "+------------------------------------------+"
        echo "|                                          |"
        echo "|  Give root Access to adb from Superuser  |"
        echo "|                                          |"
        echo "|   If using Android Studio Emulator       |"
        echo "|   ==>  https://github.com/newbit1/rootAVD|"
        echo "|   For Genymotion https://t.ly/n_5F       |"
        echo -e "+------------------------------------------+\n\n" && banner && exit
    fi
}

#====================================================================Before Starting ===================================================================
#https://github.com/whalehub/custom-certificate-authorities
#https://pswalia2u.medium.com/install-burpsuites-or-any-ca-certificate-to-system-store-in-android-10-and-11-38e508a5541a
###############  Moving Certificate for Android via adb -----------------------------------
function burpcer() {

    cert_check=$(adb shell 'su -c "ls /system/etc/security/cacerts|grep 9a5ba575.0"')
    res='y'
    #checking existing Burpsuite certificate
    if [[ "$cert_check" == "9a5ba575.0" ]]; then
        echo -e "\033[1;91m"
        echo -e "Already Burpsuite Certificate found, this will replace existing one\n"

        echo -e "\033[0;92mIf you want to replace it press Y if not then N/n "
        exec < /dev/tty && read res && exec <&-

    fi

    if [[ $res == 'N' || $res == 'n' ]]; then
        echo 'No changes in Burp Certificate '
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
            adb shell -n "su -c 'mount -o r,w /'" >/dev/null 2>&1
        fi
        adb shell -n "su -c 'mv /sdcard/$name /system/etc/security/cacerts'" >/dev/null 2>&1
        adb shell -n "su -c 'chmod 644  /system/etc/security/cacerts/$name'" >/dev/null 2>&1

        echo "+------------------------------------------+"
        echo "|                                          |"
        echo "|      Certificate Move Successfully       |"
        echo -e "+------------------------------------------+\n\n"
        echo "Device will reboot now :><: "
        echo "adb reboot &"

    fi
}

#All Apps
############### Proxy toggle-----------------------
function andro_apps() {
    prox_app=$(adb shell "pm list packages -3|cut -f 2 -d ":"|grep com.kinandcarta.create.proxytoggle" | tr -d '\r')
    if [[ "$prox_app" = "com.kinandcarta.create.proxytoggle" ]]; then
        echo 'ProxyToggle Already installed'
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

    ############### ADB WIFI -------------------------

    prox_app=$(adb shell "pm list packages -3|cut -f 2 -d ":"|grep com.sujanpoudel.adbwifi" | tr -d '\r')
    if [[ "$prox_app" == "com.sujanpoudel.adbwifi" ]]; then
        echo 'ADB Wifi Already installed'
    else
        wget -q https://github.com/raoshaab/Andro_set/raw/main/assets/adb_wifi.apk -O wifiadb.apk
        adb install -t -r wifiadb.apk
        echo "+------------------------------------------+"
        echo "|                                          |"
        echo "|         ADB Wifi App installed           |"
        echo -e "+------------------------------------------+\n\n"
    fi
    ##############Proxy Droid -----------------------

    prox_app=$(adb shell "pm list packages -3|cut -f 2 -d ":"|grep  org.proxydroid" | tr -d '\r')
    if [[ "$prox_app" == "org.proxydroid" ]]; then
        echo 'ProxyDroid Already installed'
    else

        wget -q https://github.com/raoshaab/Andro_set/raw/main/assets/org.proxydroid.apk -O proxydroid.apk
        adb install -t -r proxydroid.apk
        echo "+------------------------------------------+"
        echo "|                                          |"
        echo "|         ProxyDroid App installed         |"
        echo -e "+------------------------------------------+\n\n"
    fi
}

#Pc tools
function pc_tools() {
    ################ JADX - Dex to Java decompiler, apktool
    ################ Android Screen Share
    (jadx --version | scrcpy -v && apktool -version) &>/dev/null
    if [[ $? != 0 ]]; then
        echo 'Installing Pc Tools '
        apt-get -qq install jadx scrcpy apktool -y &>/dev/null

        echo "+------------------------------------------+"
        echo "|                                          |"
        echo "|     JADX~Apktool~Scrcpy  installed       |"
        echo -e "+------------------------------------------+\n\n"

    else
        echo "+------------------------------------------+"
        echo "|                                          |"
        echo "|  JADX~Apktool~Scrcpy already installed   |"
        echo -e "+------------------------------------------+\n\n"
    fi

    (frida --version && objection version) &>/dev/null
    if [ $? == 0 ]; then
        echo "+------------------------------------------+"
        echo "|                                          |"
        echo "|   Frida Objection already installed      |"
        echo -e "+------------------------------------------+\n\n"

    else
        pip3 install frida frida-tools objection &>/dev/null

        echo "+------------------------------------------+"
        echo "|                                          |"
        echo "|         Frida Setup Ready                |"
        echo -e "+------------------------------------------+\n\n"
    fi
}

# Android
# Not able to match android_cpu with frida, use ~= ,using regex to match
# If magisk is available, then frida_magisk module will be installed
function magisk_module() {
    #frida
    magisk_version=$(curl -IkLs -o /dev/null -w %{url_effective} https://github.com/ViRb3/magisk-frida/releases/latest | grep -o "[^/]*$" | sed "s/v//g")
    baseurl="https://github.com/ViRb3/magisk-frida/releases/download/$magisk_version/MagiskFrida-$magisk_version.zip"
    echo '      Downloading Module .....'
    wget --quiet $baseurl -O frida_module.zip
    adb push frida_module.zip /data/local/tmp/ >/dev/null 2>&1
    echo '      Flashing MagsikFrida .......'
    echo -e '\n\n    ********************************************
    *               MagiskFrida                *
    ********************************************'
    adb shell -n "su -c  'magisk  --install-module /data/local/tmp/frida_module.zip' " >/dev/null 2>&1

    #trust
    wget -q https://github.com/NVISOsecurity/MagiskTrustUserCerts/releases/download/v0.4.1/AlwaysTrustUserCerts.zip -O trust_module.zip
    adb push trust_module.zip /data/local/tmp >/dev/null 2>&1
    adb shell -n "su -c  'magisk  --install-module /data/local/tmp/trust_module.zip'" >/dev/null 2>&1
    echo -e '\n\n    ********************************************
    *            Always Trust User Certs         *
    ********************************************'

    echo "+------------------------------------------+"
    echo "|                                          |"
    echo "|    MagiskFrida, Trust Certs installed    |"
    echo -e "+------------------------------------------+\n\n"
}

#frida
function android_frida() {
    adb_check
    adb push ~/frida/frida-server /data/local/tmp/ >/dev/null 2>&1
    adb shell -n "su -c 'chmod 755 /data/local/tmp/frida-server'"
    adb shell -n "su -c '/data/local/tmp/frida-server &'" >/dev/null 2>&1
    adb shell -n "su -c 'killall frida-server' " >/dev/null 2>&1
    adb shell -n "su -c '/data/local/tmp/frida-server -l 0.0.0.0:1337 >/dev/null 2>&1 &'" >/dev/null 2>&1

    echo "+------------------------------------------+"
    echo "|                                          |"
    echo "|         Frida Server Running             |"
    echo -e "+------------------------------------------+\n\n"
}

#Fix Frida Version Mismatch
function fix_frida() {
    adb shell -n "su -c 'killall frida-server' " >/dev/null 2>&1
    adb shell -n "su -c 'pkill frida-server' " >/dev/null 2>&1
    adb shell -n "su -c 'killall -9 frida-server' " >/dev/null 2>&1
    adb shell -n "su -c 'pkill -9 frida-server' " >/dev/null 2>&1
    adb push ~/frida/frida-server /data/local/tmp/ >/dev/null 2>&1
    adb shell -n "su -c 'chmod 755 /data/local/tmp/frida-server'"
    adb shell -n "su -c '/data/local/tmp/frida-server &'" >/dev/null 2>&1
    adb shell -n "su -c 'killall frida-server' " >/dev/null 2>&1
    adb shell -n "su -c '/data/local/tmp/frida-server -l 0.0.0.0:1337 >/dev/null 2>&1 &'" >/dev/null 2>&1

    echo "+------------------------------------------+"
    echo "|                                          |"
    echo "|         Frida Server Running             |"
    echo -e "+------------------------------------------+\n\n"
}

# Main menu
while true; do
    echo "+------------------------------------------+"
    echo "|               MENU                       |"
    echo "+------------------------------------------+"
    echo "| 1. All                                    |"
    echo "| 2. Move Burpsuite Certificate to Android  |"
    echo "|    root folder                            |"
    echo "| 3. Pc Tools (JADX, frida, objection,     |"
    echo "|    Android Screen Control & Mirror)       |"
    echo "| 4. Android Frida Server                   |"
    echo "| 5. Fix Frida Server Version mismatch      |"
    echo "| 6. Android Apps (proxytoggle, proxydroid, |"
    echo "|    ADBwifi)                               |"
    echo "| 0. Exit                                   |"
    echo "+------------------------------------------+"

    echo -e "Select an option: \c"
    exec < /dev/tty && read option && exec <&-

    case $option in
    1)
        net
        burpcer
        pc_tools
        android_frida
        andro_apps
        ;;
    2)
        burpcer
        ;;
    3)
        pc_tools
        ;;
    4)
        android_frida
        ;;
    5)
        fix_frida
        ;;
    6)
        andro_apps
        ;;
    0)
        echo "Exiting..."
        exit
        ;;
    *)
        echo "Invalid option. Please try again."
        ;;
    esac

done
