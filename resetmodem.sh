#!/bin/bash
#===============================================================================
#
# FILE: monyet.sh
#
# USAGE: ./monyet.sh cek (signal|status) | /monyet.sh reboot modem
#
# DESCRIPTION: Modem fastNyet Cisco DPC2100 tool.
#
# OPTIONS: cek (signal|status) | reboot modem
# REQUIREMENTS: bash, coreutils, curl, grep, perl-libwww-perl
# BUGS: ---
# NOTES: Tested on Firstmedia/FastNet Cisco DPC2100R3 - Hardware v3.0
# AUTHOR: Indra Kurniawan (), https://twitter.com/idKurniawan
# VERSION: 1.0
# CREATED: 10/23/2014 09:21:20 PM WIB
# REVISION: ---
#===============================================================================

login() {
echo "[*] Authenticating to Modem."
curl -s http://192.168.100.1/goform/_aslvl -d 'SAAccessLevel=2&SAPassword=W2402' > /dev/null
}

yakin() {
read -r -p "${1:-Yakin nih? [y/N]} " response
case $response in
[yY][eE][sS]|[yY])
true
;;
*)
false
;;
esac
}

reboot() {
echo "[*] Rebooting Modem."
curl -s http://192.168.100.1/goform/gscan -d 'SADownStartingFrequency=54900000' > /dev/null
}

signal() {
DS=$(GET http://192.168.100.1/signal.asp | grep -A3 Status | head -3 | grep ';' | cut -d ';' -f2)
DCI=$(GET http://192.168.100.1/signal.asp | grep -A3 ID | head -3 | grep ';' | cut -d ';' -f2)
DF=$(GET http://192.168.100.1/signal.asp | grep -A3 Frequency | grep ';' | head -1 | cut -d ';' -f2)
DM=$(GET http://192.168.100.1/signal.asp | grep -A3 Modulation | grep ';' | head -1 | cut -d ';' -f2)
BR=$(GET http://192.168.100.1/signal.asp | grep -A3 Rate | grep ';' | head -1 | cut -d ';' -f2)
DPL=$(GET http://192.168.100.1/signal.asp | grep -A3 Level | grep ';' | head -1 | cut -d ';' -f2)
SNR=$(GET http://192.168.100.1/signal.asp | grep -A3 Noise | grep ';' | head -1 | cut -d ';' -f2)

US=$(GET http://192.168.100.1/signal.asp | grep -A3 Status | tail -3 | grep ';' | cut -d ';' -f2)
UCI=$(GET http://192.168.100.1/signal.asp | grep -A3 ID | tail -3 | grep ';' | cut -d ';' -f2)
UF=$(GET http://192.168.100.1/signal.asp | grep -A3 Frequency | grep ';' | tail -1 | cut -d ';' -f2)
UM=$(GET http://192.168.100.1/signal.asp | grep -A3 Modulation | grep ';' | tail -1 | cut -d ';' -f2)
SR=$(GET http://192.168.100.1/signal.asp | grep -A3 Rate | tail -3 | grep ';' | cut -d ';' -f2)
UPL=$(GET http://192.168.100.1/signal.asp | grep -A3 Level | grep ';' | tail -1 | cut -d ';' -f2)

echo "===== Downstream Channel =="
echo "[+] Downstream Status : "$DS
echo "[+] Channel ID : "$DCI
echo "[+] Downstream Frequency : "$DF
echo "[+] Modulation : "$DM
echo "[+] Bit Rate : "$BR
echo "[+] Power Level : "$DPL
echo "[+] Signal to Noise Ratio : "$SNR
echo "===== Upstream Channel ===="
echo "[+] Upstream Status : "$US
echo "[+] Channel ID : "$UCI
echo "[+] Upstream Frequency : "$UF
echo "[+] Modulation : "$UM
echo "[+] Symbol Rate : "$SR
echo "[+] Power Level : "$UPL
}

status() {
CMS=$(GET http://192.168.100.1/status.asp | grep -A2 Status | cut -d ';' -f2 | tail -1 | cut -d '<' -f1)
IL=$(GET http://192.168.100.1/status.asp | grep -A2 Address | grep [0-9] | head -1 | cut -d ';' -f2 | cut -d '<' -f1)
CT=$(GET http://192.168.100.1/status.asp | grep -A2 Time | head -3 | cut -d ';' -f2 | tail -1)
TSLR=$(GET http://192.168.100.1/status.asp | grep -A2 Reset | head -3 | cut -d ';' -f2 | tail -1 | cut -d '<' -f1)
CF=$(GET http://192.168.100.1/status.asp | grep -A2 File | cut -d ';' -f2 | cut -d '<' -f1 | tail -1)
CMC=$(GET http://192.168.100.1/status.asp | grep -A2 Cert | tail -1 | cut -d ';' -f2 | cut -d '<' -f1)

CON=$(GET http://192.168.100.1/status.asp | grep -A10 Connect | tail -3 | cut -d '>' -f4 | cut -d '<' -f1 | head -1)
MAC=$(GET http://192.168.100.1/status.asp | grep -A10 Connect | tail -3 | cut -d '>' -f4 | cut -d '<' -f1 | grep ':')
IP=$(GET http://192.168.100.1/status.asp | grep -A10 Connect | tail -3 | cut -d '>' -f4 | cut -d '<' -f1 | tail -1)

echo "===== Cable Modem ====="
echo "[+] Cable Modem Status : "$CMS
echo "[+] Local IP Address : "$IL
echo "[+] Current Time : "$CT
echo "[+] Time Since Last Reset : "$TSLR
echo "[+] Configuration File : "$CF
echo "[+] Cable Modem Certificate : "$CMC
echo "===== CPE Connections ====="
echo "[+] Connected to : "$CON
echo "[+] MAC Address : "$MAC
echo "[+] Public IP Address : "$IP
}

case "$1" in
cek)
if [ "$2" = "signal" ]; then
login; signal;
elif [ "$2" = "status" ]; then
login; status;
else
echo "[?] Karep mu opo cuk ?!?! Silit ah..."
echo "[!] Cara pake : $0 {cek signal|status} | {reboot modem}"
fi;
exit 1;
;;
reboot)
if [ "$2" = "modem" ]; then
login; yakin && reboot;
else
echo "[?] Karep mu opo cuk ?!?! Silit ah..."
echo "[!] Cara pake : $0 {cek signal|status} | {reboot modem}"
fi;
exit 1;
;;
*)
echo "[!] Cara pake : $0 {cek signal|status} | {reboot modem}"
exit 1;
;;
esac
exit 0;
