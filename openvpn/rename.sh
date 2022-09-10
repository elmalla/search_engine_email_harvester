#!/bin/bash
#################################


cd /root/OpenVPN

files=`ls -1 *.txt`
# Rename all *.ovpn to *.conf
for f in *.ovpn; do 
mv -- "$f" "${f%.ovpn}.conf"
done            


