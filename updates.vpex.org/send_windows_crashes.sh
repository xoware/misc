#!/bin/bash

cd /var/www/updates/windows/uploads/

for i in $(find . -name 'trace'); do
        DIR=`dirname $i`
        echo "$i  is in $DIR"
	echo -n "Version: "  > mail-body
        cat ${DIR}/version >> mail-body

	echo "" >> mail-body
	cat ${DIR}/trace >> mail-body

	echo -e "\nLog:\n" >> mail-body
	cat ${DIR}/log >> mail-body
	/root/bin/sendEmail -f someone@xoware.com -t karl@xoware.com -u "Windows Crash $i" \
          -s mx1.emailsrvr.com -o tls=no -o message-file=mail-body
	rm -rf $DIR
done
