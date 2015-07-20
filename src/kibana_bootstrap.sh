#!/bin/bash
#~ELASTICSEARCH_ELB_DNS_NAME=
mkdir -p /opt/kibana
cd /opt/kibana
wget https://download.elastic.co/kibana/kibana/kibana-4.1.1-linux-x64.tar.gz
tar xvf kibana-*.tar.gz
mv kibana-4.1.1-linux-x64/* ./

cd /etc/init.d && wget https://gist.githubusercontent.com/orih/182da221010f56e4644e/raw/b42ab63fd40c8b4f18289aa91bb92d55bb1e0c5d/kibana.sh
mv /etc/init.d/kibana.sh /etc/init.d/kibana
chmod +x /etc/init.d/kibana

# Need to update kibana config to look at the ELB
sed -i "s|localhost:9200|$ELASTICSEARCH_ELB_DNS_NAME:9200|" /opt/kibana/config/kibana.yml

service kibana start
