#!/bin/bash
apt-get update
apt-get install python3 -y
apt-get install python3-pip
cp vapid.py vapid
chmod +x vapid.py  
pip3 install pefile
dos2unix vapid
