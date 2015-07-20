#!/bin/bash
#~ELASTICSEARCH_ELB_DNS_NAME=
cat <<EOF >> /etc/yum.repos.d/elasticsearch.repo
[logstash-1.5]
name=Logstash repository for 1.5.x packages
baseurl=http://packages.elasticsearch.org/logstash/1.5/centos
gpgcheck=1
gpgkey=http://packages.elasticsearch.org/GPG-KEY-elasticsearch
enabled=1
EOF

yum -y install logstash

cat > /tmp/logstash.conf << EOF
input {
sqs {
    queue => "logstashincoming"
    region => "us-west-2"
    threads => 80
}
file {
    path => "/var/log/*log"
    type => "syslog"
}
file {
    path => "/var/log/messages"
    type => "syslog"
}
}

output {
elasticsearch {
    protocol => "http"
    host => "$ELASTICSEARCH_ELB_DNS_NAME"
    port => "9200"
    flush_size => 500
}
}
EOF

mv /tmp/logstash.conf /etc/logstash/conf.d/logstash.conf

service logstash restart
