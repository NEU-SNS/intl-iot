#!/bin/bash

filelistciphers=list_ciphers.txt
fileserverlog=server.log
dirsynthetic=synthetic
if ! [ -e $filelistciphers ]
then
    python3 get_supported_ciphers.py > $filelistciphers
    echo "Populate the list_ciphers.txt at the local machine"
fi

#tshark -i lo0 -w synthetic/tls.pcap
while read cp
do
    echo "`date`: Cipher: $cp"

    for txtfile in $dirsynthetic/f*.txt
    do
        pkill -f ssl_server.py
        # check if port 8443 has been released
#        pid="`lsof -Pi :8443 -sTCP:LISTEN`"
#        echo "PORT: $pid"
#        while [ "$pid" != "" ]
#        do
#            sleep 2
#            echo "`date`: [ALERT] port busy, try to kill ssl_server again!!"
#            pkill -f ssl_server.py
#        done
        python ssl_server.py $cp >> $fileserverlog 2>&1 &
        printf "\t`date`: wait for the ssl server to bind (3s)\n"
        sleep 3
        printf "\t`date`: client sending $txtfile content\n"
        python ssl_client.py $txtfile
        printf "\t`date`: client sent $txtfile\n\n"
        pkill -f ssl_server.py
        pkill -f ssl_server.py
        pkill -f ssl_server.py
#        break
    done

    printf "`date`: Done with $cp \n\n"
    pkill -f ssl_server.py
    printf "`date`: wait for 30s \n\n"
    sleep 30
#    break
done < $filelistciphers

echo "`date`: server msg saved to $fileserverlog"
echo "`date`: All ciphers tried!"