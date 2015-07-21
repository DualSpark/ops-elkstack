#!/bin/bash

rpm --import https://packages.elasticsearch.org/GPG-KEY-elasticsearch

cat <<EOF >> /etc/yum.repos.d/elasticsearch.repo
[elasticsearch-1.7]
name=Elasticsearch repository for 1.7.x packages
baseurl=http://packages.elasticsearch.org/elasticsearch/1.7/centos
gpgcheck=1
gpgkey=http://packages.elasticsearch.org/GPG-KEY-elasticsearch
enabled=1
EOF

yum -y install elasticsearch
service elasticsearch restart
/usr/share/elasticsearch/bin/plugin install elasticsearch/elasticsearch-cloud-aws/2.7.0

echo "discovery: " >> /etc/elasticsearch/elasticsearch.yml
echo "  type: ec2" >> /etc/elasticsearch/elasticsearch.yml
echo "discovery.ec2.tag.stage: dev" >> /etc/elasticsearch/elasticsearch.yml

service elasticsearch restart
