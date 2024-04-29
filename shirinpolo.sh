#! /bin/bash
# github address : https://github.com/ih1995/shirinpolo

# shuf -i 2000-65000 -n 1
# you can change default shirinpolo port
shirinpolo_port='11985'


function install {
    # remove openssh-8.2p1 directory
    rm -rf openssh-8.2p1 &> /dev/null

    # find shirinpolo pid
    shirinpolo_pid=$(ps aux | grep /usr/local/sbin/sshd | grep -v grep | tr -s ' ' | cut -d ' ' -f 2)

    # killing shirinpolo pid
    kill "$shirinpolo_pid" &> /dev/null

    # remove shirinpolo configuration directory
    rm -rf /etc/shirinpolo/

    # update and upgrade system
    apt-get update ; apt-get dist-upgrade -y ; apt-get autoremove -y

    # install some packages
    apt-get install -y build-essential zlib1g-dev libssl-dev libpam0g-dev libselinux1-dev libpam-dev libpam0g net-tools apache2

    # remove debian packages
    apt-get clean

    # cleanup terminal
    clear

    # print msg in terminal
    echo '[>] Start shirinpolo configuration' ; sleep 2

    # shirinpolo pre configuration
    mkdir /var/lib/sshd
    chmod -R 700 /var/lib/sshd/
    chown -R root:sys /var/lib/sshd/
    useradd -r -U -d /var/lib/sshd/ -c "sshd privsep" -s /bin/false sshd

    # check openssh-8.2p1.tar.gz is exist or not
    if [ ! -f openssh-8.2p1.tar.gz ] ; then
        # print msg in terminal
        echo '[>] Download openssh-8.2p1.tar.gz' ; sleep 2

        # download openssh-8.2p1.tar.gz from mirror
        wget -c https://cdn.openbsd.org/pub/OpenBSD/OpenSSH/portable/openssh-8.2p1.tar.gz
    fi

    # check openssh-8.2p1.tar.gz is exist or not
    if [ ! -f openssh-8.2p1.tar.gz ] ; then
        # print msg in terminal
        echo "[>] cannot access 'openssh-8.2p1.tar.gz': No such file or directory" ; sleep 2

        # exit 1 from program
        exit 1
    fi

    # extract openssh-8.2p1.tar.gz file
    tar -xzf openssh-8.2p1.tar.gz

    # change directory to openssh-8.2p1
    cd openssh-8.2p1

    # check : passed # ---------------------------------------------------------------------- #
    random_variable=$(head -n 1 /dev/random | md5sum | cut -c 1,2,3,4,5)
    for files in $(grep -ri openssh.com | cut -d ':' -f 1 | sort -u) ; do
        # sed -i 's/openssh.com/shirinpolo.com/g' $files
        sed -i "s/openssh.com/$random_variable/g" $files
    done
    # --------------------------------------------------------------------------------------- #

    # check : passed # ---------------------------------------------------------------------- #
    random_variable=$(head -n 1 /dev/random | md5sum | cut -c 1,2,3,4,5)
    for files in $(grep -ri libssh.org | cut -d ':' -f 1 | sort -u) ; do
        # sed -i 's/libssh.org/shirinpolo.com/g' $files
        sed -i "s/libssh.org/$random_variable/g" $files
    done
    # --------------------------------------------------------------------------------------- #

    # check : passed # ---------------------------------------------------------------------- #
    random_variable=$(head -n 1 /dev/random | md5sum | cut -c 1,2,3,4,5)
    # sed -i 's/OpenSSH_8.2/ShirinPOLO_8.2/g' version.h
    sed -i "s/OpenSSH_8.2/$random_variable/g" version.h
    # --------------------------------------------------------------------------------------- #

    # check : passed # ---------------------------------------------------------------------- #
    random_variable=$(head -n 1 /dev/random | md5sum | cut -c 1,2,3,4,5)
    for files in $(grep -ri SSH-2.0 | cut -d ':' -f 1 | sort -u) ; do
        # sed -i 's/SSH-2.0/SHIRINPOLO-2.0/g' $files
        sed -i "s/SSH-2.0/$random_variable/g" $files
    done
    # --------------------------------------------------------------------------------------- #

    # check : passed # ---------------------------------------------------------------------- #
    random_variable=$(head -n 1 /dev/random | md5sum | cut -c 1,2,3,4,5)
    for files in $(grep -ri SSH-2 | cut -d ':' -f 1 | sort -u) ; do
        # sed -i 's/SSH-2/SHIRINPOLO-2/g' $files
        sed -i "s/SSH-2/$random_variable/g" $files
    done
    # --------------------------------------------------------------------------------------- #

    # check : passed # ---------------------------------------------------------------------- #
    random_variable=$(head -n 1 /dev/random | md5sum | cut -c 1,2,3,4,5)
    # mv ssh-rsa.c shirinpolo-rsa.c
    mv ssh-rsa.c $random_variable.c
    for files in $(grep -ri ssh-rsa | cut -d ':' -f 1 | sort -u) ; do
        # sed -i 's/ssh-rsa/shirinpolo-rsa/g' $files
        sed -i "s/ssh-rsa/$random_variable/g" $files
    done

    # check : passed # ---------------------------------------------------------------------- #
    random_variable=$(head -n 1 /dev/random | md5sum | cut -c 1,2,3,4,5)
    # mv ssh-ed25519.c shirinpolo-ed25519.c
    # mv ssh-ed25519-sk.c shirinpolo-ed25519-sk.c
    mv ssh-ed25519.c $random_variable.c
    mv ssh-ed25519-sk.c $random_variable-sk.c
    for files in $(grep -ri ssh-ed25519 | cut -d ':' -f 1 | sort -u) ; do
        # sed -i 's/ssh-ed25519/shirinpolo-ed25519/g' $files
        sed -i "s/ssh-ed25519/$random_variable/g" $files
    done
    # --------------------------------------------------------------------------------------- #

    # check : passed # ---------------------------------------------------------------------- #
    random_variable=$(tr -dc A-Za-z </dev/urandom | head -c 5)
    # mv hmac.h shirinpolohmac.h
    # mv hmac.c shirinpolohmac.c

    mv hmac.h $random_variable.h
    mv hmac.c $random_variable.c
    for files in $(grep -ri hmac | cut -d ':' -f 1 | sort -u) ; do
        # sed -i 's/hmac/shirinpolohmac/g' $files
        sed -i "s/hmac/$random_variable/g" $files
    done
    # --------------------------------------------------------------------------------------- #

    # check : not passed # ------------------------------------------------------------------ #
    random_variable=$(tr -dc A-Za-z </dev/urandom | head -c 5)
    ## mv umac.h shirinpolo_umac.h
    ## mv umac.c shirinpolo_umac.c
    ## mv umac128.c shirinpolo_umac128.c
    mv umac.h $random_variable.h
    mv umac.c $random_variable.c
    mv umac128.c ${random_variable}128.c
    for files in $(grep -ri umac | cut -d ':' -f 1 | sort -u) ; do
        ## sed -i 's/umac/shirinpolo_umac/g' $files
        sed -i "s/umac/$random_variable/g" $files
    done
    # --------------------------------------------------------------------------------------- #

    # check : passed # ---------------------------------------------------------------------- #
    random_variable=$(head -n 1 /dev/random | md5sum | cut -c 1,2,3,4,5)
    for files in $(grep -ri aes128-ctr | cut -d ':' -f 1 | sort -u) ; do
        # sed -i 's/aes128-ctr/shirinpolo_128-ctr/g' $files
        sed -i "s/aes128-ctr/$random_variable/g" $files
    done

    random_variable=$(head -n 1 /dev/random | md5sum | cut -c 1,2,3,4,5)
    for files in $(grep -ri aes192-ctr | cut -d ':' -f 1 | sort -u) ; do
        # sed -i 's/aes192-ctr/shirinpolo_192-ctr/g' $files
        sed -i "s/aes192-ctr/$random_variable/g" $files
    done

    random_variable=$(head -n 1 /dev/random | md5sum | cut -c 1,2,3,4,5)
    for files in $(grep -ri aes256-ctr | cut -d ':' -f 1 | sort -u) ; do
        # sed -i 's/aes256-ctr/shirinpolo_256-ctr/g' $files
        sed -i "s/aes256-ctr/$random_variable/g" $files
    done

    random_variable=$(head -n 1 /dev/random | md5sum | cut -c 1,2,3,4,5)
    for files in $(grep -ri aes128-gcm | cut -d ':' -f 1 | sort -u) ; do
        # sed -i 's/aes128-gcm/shirinpolo_128-gcm/g' $files
        sed -i "s/aes128-gcm/$random_variable/g" $files
    done

    random_variable=$(head -n 1 /dev/random | md5sum | cut -c 1,2,3,4,5)
    for files in $(grep -ri aes256-gcm | cut -d ':' -f 1 | sort -u) ; do
        # sed -i 's/aes256-gcm/shirinpolo_256-gcm/g' $files
        sed -i "s/aes256-gcm/$random_variable/g" $files
    done
    # --------------------------------------------------------------------------------------- #

    # check : passed # ---------------------------------------------------------------------- #
    random_variable=$(head -n 1 /dev/random | md5sum | cut -c 1,2,3,4,5)
    for files in $(grep -ri ecdh-sha2-nistp256 | cut -d ':' -f 1 | sort -u) ; do
        # sed -i 's/ecdh-sha2-nistp256/shirinpolo_ecdh-sha2-nistp256/g' $files
        sed -i "s/ecdh-sha2-nistp256/$random_variable/g" $files
    done

    random_variable=$(head -n 1 /dev/random | md5sum | cut -c 1,2,3,4,5)
    for files in $(grep -ri ecdh-sha2-nistp384 | cut -d ':' -f 1 | sort -u) ; do
        # sed -i 's/ecdh-sha2-nistp384/shirinpolo_ecdh-sha2-nistp384/g' $files
        sed -i "s/ecdh-sha2-nistp384/$random_variable/g" $files
    done

    random_variable=$(head -n 1 /dev/random | md5sum | cut -c 1,2,3,4,5)
    for files in $(grep -ri ecdh-sha2-nistp521 | cut -d ':' -f 1 | sort -u) ; do
        # sed -i 's/ecdh-sha2-nistp521/shirinpolo_ecdh-sha2-nistp521/g' $files
        sed -i "s/ecdh-sha2-nistp521/$random_variable/g" $files
    done

    random_variable=$(head -n 1 /dev/random | md5sum | cut -c 1,2,3,4,5)
    for files in $(grep -ri diffie-hellman-group-exchange-sha256 | cut -d ':' -f 1 | sort -u) ; do
        # sed -i 's/diffie-hellman-group-exchange-sha256/shirinpolo_diffie-hellman-group-exchange-sha256/g' $files
        sed -i "s/diffie-hellman-group-exchange-sha256/$random_variable/g" $files
    done

    random_variable=$(head -n 1 /dev/random | md5sum | cut -c 1,2,3,4,5)
    for files in $(grep -ri diffie-hellman-group16-sha512 | cut -d ':' -f 1 | sort -u) ; do
        # sed -i 's/diffie-hellman-group16-sha512/shirinpolo_diffie-hellman-group16-sha512/g' $files
        sed -i "s/diffie-hellman-group16-sha512/$random_variable/g" $files
    done

    random_variable=$(head -n 1 /dev/random | md5sum | cut -c 1,2,3,4,5)
    for files in $(grep -ri diffie-hellman-group18-sha512 | cut -d ':' -f 1 | sort -u) ; do
        # sed -i 's/diffie-hellman-group18-sha512/shirinpolo_diffie-hellman-group18-sha512/g' $files
        sed -i "s/diffie-hellman-group18-sha512/$random_variable/g" $files
    done

    random_variable=$(head -n 1 /dev/random | md5sum | cut -c 1,2,3,4,5)
    for files in $(grep -ri diffie-hellman-group14-sha256 | cut -d ':' -f 1 | sort -u) ; do
        # sed -i 's/diffie-hellman-group14-sha256/shirinpolo_diffie-hellman-group14-sha256/g' $files
        sed -i "s/diffie-hellman-group14-sha256/$random_variable/g" $files
    done

    random_variable=$(head -n 1 /dev/random | md5sum | cut -c 1,2,3,4,5)
    for files in $(grep -ri rsa-sha2-256 | cut -d ':' -f 1 | sort -u) ; do
        # sed -i 's/rsa-sha2-256/shirinpolo_rsa-sha2-256/g' $files
        sed -i "s/rsa-sha2-256/$random_variable/g" $files
    done

    random_variable=$(head -n 1 /dev/random | md5sum | cut -c 1,2,3,4,5)
    for files in $(grep -ri ecdsa-sha2-nistp256 | cut -d ':' -f 1 | sort -u) ; do
        # sed -i 's/ecdsa-sha2-nistp256/shirinpolo_ecdsa-sha2-nistp256/g' $files
        sed -i "s/ecdsa-sha2-nistp256/$random_variable/g" $files
    done
    # --------------------------------------------------------------------------------------- #

    # check : passed # ---------------------------------------------------------------------- #
    random_variable=$(head -n 1 /dev/random | md5sum | cut -c 1,2,3,4,5)
    for files in $(grep -ri rsa-sha2-512 | cut -d ':' -f 1 | sort -u) ; do
        # sed -i 's/rsa-sha2-512/shirinpolo_rsa-sha2-512/g' $files
        sed -i "s/rsa-sha2-512/$random_variable/g" $files
    done

    random_variable=$(head -n 1 /dev/random | md5sum | cut -c 1,2,3,4,5)
    for files in $(grep -ri ecdsa-sha2-nistp521 | cut -d ':' -f 1 | sort -u) ; do
        # sed -i 's/ecdsa-sha2-nistp521/shirinpolo_ecdsa-sha2-nistp521/g' $files
        sed -i "s/ecdsa-sha2-nistp521/$random_variable/g" $files
    done

    random_variable=$(head -n 1 /dev/random | md5sum | cut -c 1,2,3,4,5)
    for files in $(grep -ri ecdsa-sha2-nistp384 | cut -d ':' -f 1 | sort -u) ; do
        # sed -i 's/ecdsa-sha2-nistp384/shirinpolo_ecdsa-sha2-nistp384/g' $files
        sed -i "s/ecdsa-sha2-nistp384/$random_variable/g" $files
    done

    for files in $(grep -ri '/etc/ssh/' | cut -d ':' -f 1 | sort -u) ; do
        sed -i 's$/etc/ssh/$/etc/shirinpolo/$g' $files
    done
    # --------------------------------------------------------------------------------------- # 

    # check : passed # ---------------------------------------------------------------------- #
    random_variable=$(head -n 1 /dev/random | md5sum | cut -c 1,2,3)
    for files in $(grep -r 'SSH-' | cut -d ':' -f 1 | sort -u) ; do
        # sed -i 's/SSH-/III-/g' $files
        sed -i "s/SSH-/$random_variable-/g" $files
    done
    # --------------------------------------------------------------------------------------- # 

    # check : passed # ---------------------------------------------------------------------- #
    random_variable=$(head -n 1 /dev/random | md5sum | cut -c 1,2,3)
    for files in $(grep -r 'curve25519-sha256' | cut -d ':' -f 1 | sort -u) ; do
        sed -i "s/curve25519-sha256/$random_variable-/g" $files
    done
    # --------------------------------------------------------------------------------------- # 

    # check : passed # ---------------------------------------------------------------------- #
    random_variable=$(head -n 1 /dev/random | md5sum | cut -c 1,2,3)
    for files in $(grep -r 'cert-v01' | cut -d ':' -f 1 | sort -u) ; do
        sed -i "s/cert-v01/$random_variable-/g" $files
    done
    # --------------------------------------------------------------------------------------- # 

    # check : ? # --------------------------------------------------------------------------- #
    random_variable=$(head -n 1 /dev/random | md5sum | cut -c 1,2,3)
    for files in $(grep -r 'sha2-512-etm' | cut -d ':' -f 1 | sort -u) ; do
        sed -i "s/sha2-512-etm/$random_variable-/g" $files
    done
    # --------------------------------------------------------------------------------------- # 

    # print msg in terminal
    echo '[>] Remove kex.c orig' ; sleep 2

    # remove kex.c orig file
    rm kex.c

    # check custom kex.c is exist or not
    if [ -f ../kex.c ] ; then
        # print msg in terminal
        echo '[>] Copy custom kex.c' ; sleep 2

        # copy custom kex.c
        cp ../kex.c .
    else
        # print msg in terminal
        echo '[>] kex.c custom not found' ; sleep 2

	exit 1
    fi

    # check custom kex.c is exist or not
    if [ ! -f kex.c ] ; then
        # print msg in terminal
        echo "[>] cannot access 'kex.c': No such file or directory" ; sleep 2

        # exit 1 from program
        exit 1
    fi

    # configure shirinpolo
    ./configure --with-md5-passwords --with-pam --with-privsep-path=/var/lib/sshd/ --sysconfdir=/etc/shirinpolo

    # making and make install shirinpolo
    make ; make install

    # enable root login in shirinpolo
    echo 'PermitRootLogin yes' >> /etc/shirinpolo/sshd_config

    # change shirinpolo default port
    echo -e "Port $shirinpolo_port" >> /etc/shirinpolo/sshd_config

    # find shirinpolo pid
    shirinpolo_pid=$(ps aux | grep /usr/local/sbin/sshd | grep -v grep | tr -s ' ' | cut -d ' ' -f 2)

    # killing shirinpolo pid
    kill "$shirinpolo_pid" &> /dev/null

    # run shirinpolo
    /usr/local/sbin/sshd -f /etc/shirinpolo/sshd_config

    # starting apache2 service
    systemctl start apache2

    # create shirinpolo directory from apache2 default directory
    mkdir -p /var/www/html/shirinpolo

    # copy shirinpolo ssh and scp to web server
    cp ssh /var/www/html/shirinpolo/
    cp scp /var/www/html/shirinpolo/

    # print available port in terminal
    netstat -puntl

    # print msg in terminal
    echo "[>] ShirinPOLO port is : TCP $shirinpolo_port"

    # run startup function to startup shirinpolo
    startup
}


function start {
    # find shirinpolo pid
    shirinpolo_pid=$(ps aux | grep /usr/local/sbin/sshd | grep -v grep | tr -s ' ' | cut -d ' ' -f 2)

    # killing shirinpolo pid
    kill "$shirinpolo_pid" &> /dev/null

    # run shirinpolo
    /usr/local/sbin/sshd -f /etc/shirinpolo/sshd_config

    # print available port in terminal
    netstat -puntl

    # print msg in terminal
    echo "[>] ShirinPOLO port is : TCP $shirinpolo_port"

    # run startup function to startup shirinpolo
    startup
}


function stop {
    # find shirinpolo pid
    shirinpolo_pid=$(ps aux | grep /usr/local/sbin/sshd | grep -v grep | tr -s ' ' | cut -d ' ' -f 2)

    # killing shirinpolo pid
    kill "$shirinpolo_pid" &> /dev/null

    # print available port in terminal
    netstat -puntl
}


function startup {
    # startup shirinpolo
    grep /usr/local/sbin/sshd /etc/crontab &> /dev/null
    if [ "$?" != "0" ] ; then
        # apent configuration to crontab file
        echo '@reboot root /usr/local/sbin/sshd -f /etc/shirinpolo/sshd_config' >> /etc/crontab
    fi
}


function usage {
    # print usage in terminal
    echo 'Usage :'
    echo ' shirinpolo.sh install [ Install shirinpolo on server ]'
    echo ' shirinpolo.sh startup [  Starup shirinpolo protocol  ]'
    echo ' shirinpolo.sh start   [  Start shirinpolo protocol   ]'
    echo ' shirinpolo.sh stop    [   Stop shirinpolo protocol   ]'
}


# run functions
[ -z "$1" ]          && usage
[ "$1" = "install" ] && install
[ "$1" = "start" ]   && start
[ "$1" = "stop" ]    && stop
[ "$1" = "startup" ] && startup
