#!/bin/bash
#~ELASTICSEARCH_ELB_DNS_NAME=
#~KIBANA_PASSWORD=
mkdir -p /opt/kibana
cd /opt/kibana
wget https://download.elastic.co/kibana/kibana/kibana-4.1.1-linux-x64.tar.gz
tar xvf kibana-*.tar.gz
mv kibana-4.1.1-linux-x64/* ./

# from https://gist.githubusercontent.com/orih/182da221010f56e4644e/raw/b42ab63fd40c8b4f18289aa91bb92d55bb1e0c5d/kibana.sh
cat > /tmp/kibana.sh << EOF
#!/bin/sh

### BEGIN INIT INFO
# Provides:          kibana
# Required-Start:    $local_fs $remote_fs $network
# Should-Start:      $time
# Required-Stop:     $local_fs $remote_fs $network
# Default-Start:     3 5
# Default-Stop:      0 1 2 6
# Short-Description: Kibana 4
# Description:       Service controller for Kibana 4
### END INIT INFO

INSTALLED_DIR=/opt/kibana
EXEC_SCRIPT="\$INSTALLED_DIR/bin/kibana"
LOG_DIR=/var/log/kibana
PID_DIR=/var/run
PID_FILE="\$PID_DIR"/kibana.pid
LOG_FILE="\$LOG_DIR"/kibana.log

test -d \$LOG_DIR || mkdir \$LOG_DIR

# Source function library.
. /etc/init.d/functions

RETVAL=0

case "\$1" in
    start)
        if [ ! -f "\$PID_FILE" ]; then
          echo -n "Starting Kibana"
          nohup \$EXEC_SCRIPT 0<&- &> \$LOG_FILE &
          echo \$! > \$PID_FILE
          success
        else
          echo -n "Kibana is already running"
          RETVAL=1
          failure
        fi
        echo
        ;;
    stop)
        if [ -f "\$PID_FILE" ]; then
          echo -n "Stopping Kibana"
          test -f \$PID_FILE && cat \$PID_FILE | xargs kill -s SIGKILL && rm -f \$PID_FILE
          success
        else
          echo -n "Kibana is not running"
          RETVAL=1
          failure
        fi
        echo
        ;;
    restart)
        \$0 stop
        \$0 start
        ;;
    reload)
        \$0 restart
        ;;
    status)
        status kibana
        RETVAL=\$?
        ;;
*)
echo "Usage: \$0 {start|stop|status|restart|reload}"
exit 1
;;
esac
exit \$RETVAL
EOF

mv /tmp/kibana.sh /etc/init.d/kibana
chmod +x /etc/init.d/kibana

sed -i "s|localhost:9200|$ELASTICSEARCH_ELB_DNS_NAME:9200|" /opt/kibana/config/kibana.yml

yum -y install nginx httpd-tools
htpasswd -bc /opt/kibana/.htpasswd kibanauser $KIBANA_PASSWORD

cat > /tmp/nginx.conf << EOF
user nobody;
worker_processes 2;
pid /var/run/nginx.pid;
events {
    worker_connections  1024;
}
http {
    gzip on;
    gzip_disable "msie6";
    include       mime.types;
    default_type  application/xml;
    log_format compression '\$remote_addr - \$remote_user [$time_local] '
                           '"\$request" \$status \$body_bytes_sent '
                           '"\$http_referer" "\$http_user_agent" "\$gzip_ratio"';
    error_log /var/log/nginx/notice.log notice;
    server {
        listen 81;
        return 200;
        access_log off;
    }
    server {
        listen       80;
        auth_basic "Restricted Access";
        auth_basic_user_file /opt/kibana/.htpasswd;
        location / {
            proxy_pass http://localhost:5601;
            proxy_http_version 1.1;
            proxy_set_header Upgrade \$http_upgrade;
            proxy_set_header Connection 'upgrade';
            proxy_set_header Host \$host;
            proxy_cache_bypass \$http_upgrade;
            proxy_buffering off;
        }
    }
}
EOF

mv -f /tmp/nginx.conf /etc/nginx/nginx.conf
service nginx restart
# sad hack to let elasticsearch ELB register instances before we come up.  503s causes kibana to crash.
# See https://github.com/elastic/kibana/pull/3033 .
# not a problem for ELB healthchecks, nginx handles it.
sleep 360
service kibana start
