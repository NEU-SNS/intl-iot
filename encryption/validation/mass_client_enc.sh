#!/bin/bash
DIR_TXT=synthetic

#### PLAIN TEXT TRAFFIC ###
echo "Have you started the socket server by python socket_server.py 12345"
read ans
while ! [ "$ans" = "y" ]
do
    echo "Have you started the socket server by python socket_server.py 12345"
    read ans
done


echo "Have you started capture pcap? (in a separate window, run tshark -i lo0 -w ${DIR_TXT}/enc.pcap)"
read ans
while ! [ "$ans" = "y" ]
do
    echo "Have you started capture pcap? (in a separate window, run tshark -i lo0 -w ${DIR_TXT}/enc.pcap)"
    read ans
done
#exit 0

for f in ${DIR_TXT}/f*.enc
do
    python etp_client.py $f 1
#    break
done

#### ENCRYPT traffic ####

