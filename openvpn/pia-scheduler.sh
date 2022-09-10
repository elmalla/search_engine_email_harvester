#!/bin/bash
#################################


cd /root/OpenVPN
while true
       do
           echo "VPN AUS M connecting" 
           systemctl start openvpn@ausM.service
           echo "VPN connected"
           sleep 15
           ip="$(dig +short myip.opendns.com @resolver1.opendns.com)"
           echo "$ip"
           sleep 340
           echo "AUS M VPN killing" 
           killall openvpn
           echo "VPN killed"
           sleep 30
           echo "waitting...."
           

           echo "VPN AUS S connecting" 
           systemctl start openvpn@ausS.service
           echo "VPN connected"
           sleep 15
           ip="$(dig +short myip.opendns.com @resolver1.opendns.com)"
           echo "$ip"
           sleep 380
           echo "AUS S VPN killing" 
           killall openvpn
           echo "VPN killed"
           sleep 30
           echo "waitting...."
           

           echo "VPN UK connecting" 
           systemctl start openvpn@uk.service
           echo "VPN connected"
           sleep 15
           ip="$(dig +short myip.opendns.com @resolver1.opendns.com)"
           echo "$ip"
           sleep 300
           echo "UK VPN killing" 
           killall openvpn
           echo "VPN killed"
           sleep 30
           echo "waitting...."
           
          echo "VPN Netherland connecting" 

           systemctl start openvpn@nd.service
           echo "Netherland VPN connected"
           sleep 15
           ip="$(dig +short myip.opendns.com @resolver1.opendns.com)"
           echo "$ip"
           sleep 350
           echo "Netherland VPN killing" 
           killall openvpn
           echo "VPN killed"
           sleep 30
           echo "waitting...."

           echo "VPN US connecting"  
           systemctl start openvpn@us.service
           echo "US VPN connected"
           sleep 15
           ip="$(dig +short myip.opendns.com @resolver1.opendns.com)"
           echo "$ip"
           sleep 400
           echo "US VPN killing" 
           killall openvpn
           echo "VPN killed"
           sleep 30
           echo "waitting...."

           echo "VPN  connecting" 
           systemctl start openvpn@ausM.service
           echo "VPN connected"
           sleep 15
           ip="$(dig +short myip.opendns.com @resolver1.opendns.com)"
           echo "$ip"
           sleep 340
           echo " VPN killing" 
           killall openvpn
           echo "VPN killed"
           sleep 30
           echo "waitting...."
          

       done
done 
            


