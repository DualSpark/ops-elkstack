from environmentbase.networkbase import NetworkBase
from troposphere import ec2, Tags, Base64, Ref, iam, GetAtt
from troposphere.ec2 import NetworkInterfaceProperty
from troposphere.iam import Role, InstanceProfile
from troposphere.iam import PolicyType as IAMPolicy, Policy
from troposphere.sqs import Queue
import json


class ElkStack(NetworkBase):
    '''
    ELK stack template generation
    '''

    def create_action(self):
        self.initialize_template()
        self.construct_network()

        # Matthew's debug fun
        # print self.local_subnets['public']['0'].JSONrepr() # First public subnet

        # SQS queue
        queue = self.create_logstash_queue()

        # IAM profile for logstash to chat with SQS
        policies = self.create_instance_profiles_for_reading_SQS()

        # EC2 instances
        self.create_logstash()
        # self.create_kibana()
        # self.create_elasticsearch()

        # And some way of logstash to talk to elasticsearch: R53?

        self.write_template_to_file()


    def create_logstash_queue(self):
        self.queue = Queue("logstashincoming", QueueName="logstashincoming")
        self.template.add_resource(self.queue)

    def create_instance_profiles_for_reading_SQS(self):
        # configured per https://www.elastic.co/guide/en/logstash/current/plugins-inputs-sqs.html
        self.policies = [iam.Policy(
            PolicyName='logstashqueueaccess',
            PolicyDocument={
                "Statement": [{
                    "Effect": "Allow",
                        "Action": [
                            "sqs:ChangeMessageVisibility",
                            "sqs:ChangeMessageVisibilityBatch",
                            "sqs:GetQueueAttributes",
                            "sqs:GetQueueUrl",
                            "sqs:ListQueues",
                            "sqs:SendMessage",
                            "sqs:SendMessageBatch",
                            "sqs:ReceiveMessage"
                        ],
                        "Resource": GetAtt("logstashincoming", "Arn")}]
            })]

        self.create_instance_profile(layer_name = "logstashsqsrole", iam_policies = self.policies)

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
        host => "localhost"
        port => "9200"
        flush_size => 500
    }
}
EOF

mv /tmp/logstash.conf /etc/logstash/conf.d/logstash.conf

service logstash restart
        '''

        # instance size dropped to a t2.small for making debugging cheaper.
        res = ec2.Instance("logstash", InstanceType="t2.small", ImageId="ami-e7527ed7",
            Tags=Tags(Name="logstash",), UserData=Base64(logstash_startup),
            KeyName=Ref(self.template.parameters['ec2Key']),
            IamInstanceProfile=Ref('logstashsqsroleInstancePolicy'),
            # SubnetId=Ref(self.local_subnets['public']['0']),
            NetworkInterfaces=[
            NetworkInterfaceProperty(
                GroupSet=[
                    Ref(self.common_sg)],
                AssociatePublicIpAddress='true',
                DeviceIndex='0',
                DeleteOnTermination='true',
                SubnetId=Ref(self.local_subnets['public']['0']))]
            )

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
        res = ec2.Instance("kibana", InstanceType="t2.small", ImageId="ami-e7527ed7",
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
        res = ec2.Instance("es", InstanceType="t2.small", ImageId="ami-e7527ed7",
            Tags=Tags(Name="es",), UserData=Base64(elasticsearch_startup))
        self.template.add_resource(res)


def main():
    ElkStack()

if __name__ == '__main__':
    main()
