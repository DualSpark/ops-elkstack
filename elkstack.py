from networkbase import NetworkBase
from troposphere import ec2, Tags, Base64

class ElkStack(NetworkBase):
    '''
    ELK stack template generation
    '''

    def create_action(self):
        self.initialize_template()

        self.create_logstash()
        self.create_kibana()
        self.create_elasticsearch()

        # This triggers serialization of the template and any child stacks
        self.write_template_to_file()

    def create_logstash(self):
        logstash_startup = '''#!/bin/bash

cat <<EOF >> /etc/yum.repos.d/elasticsearch.repo
[logstash-1.5]
name=Logstash repository for 1.5.x packages
baseurl=http://packages.elasticsearch.org/logstash/1.5/centos
gpgcheck=1
gpgkey=http://packages.elasticsearch.org/GPG-KEY-elasticsearch
enabled=1
EOF

yum -y install logstash

service logstash restart

# it's listening to the world, lock down later and via SG and VPCs, etc...
# edit /etc/elasticsearch/elasticsearch.yml to change where it listens to.
        '''

        # this resource needs to be dropped into a VPC.  For now, we can use a public subnet.
        res = ec2.Instance("logstash", InstanceType="m3.medium", ImageId="ami-951945d0",
            Tags=Tags(Name="logstash",), UserData=Base64(logstash_startup))
        self.template.add_resource(res)

    def create_kibana(self):
        kibana_startup = '''#!/bin/bash

        mkdir -p /opt/kibana
        cd /opt/kibana
        wget https://download.elastic.co/kibana/kibana/kibana-4.1.1-linux-x64.tar.gz
        tar xvf kibana-*.tar.gz
        mv kibana-4.1.1-linux-x64/* ./

        cd /etc/init.d && wget https://gist.githubusercontent.com/orih/182da221010f56e4644e/raw/b42ab63fd40c8b4f18289aa91bb92d55bb1e0c5d/kibana.sh
        mv /etc/init.d/kibana.sh /etc/init.d/kibana
        chmod +x /etc/init.d/kibana
        service kibana start
        '''
        # this resource needs to be dropped into a VPC.  For now, we can use a public subnet.
        res = ec2.Instance("kibana", InstanceType="m3.medium", ImageId="ami-951945d0",
            Tags=Tags(Name="kibana",), UserData=Base64(kibana_startup))
        self.template.add_resource(res)

    def create_elasticsearch(self):
        elasticsearch_startup = '''#!/bin/bash

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
'''
        # this resource needs to be dropped into a VPC.  For now, we can use a public subnet.
        res = ec2.Instance("es", InstanceType="m3.medium", ImageId="ami-951945d0",
            Tags=Tags(Name="es",), UserData=Base64(elasticsearch_startup))
        self.template.add_resource(res)

if __name__ == '__main__':
    ElkStack()
