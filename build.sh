#!/bin/bash
apt-get update
apt-get install python3 -y
apt-get install python3-pip
chmod +x Vapid.py  
pip3 install pefile
dos2unix Vapid
