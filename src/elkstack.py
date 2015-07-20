from environmentbase.networkbase import NetworkBase
from troposphere import ec2, Tags, Base64, Ref, iam, GetAtt, GetAZs, Join
from troposphere.ec2 import NetworkInterfaceProperty
from troposphere.iam import Role, InstanceProfile
from troposphere.iam import PolicyType as IAMPolicy, Policy
from troposphere.sqs import Queue
import troposphere.elasticloadbalancing as elb
import json
import string
import os


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
        # order is important: need to create the ELB for ElasticSearch before
        # calling create_logstash: it uses it for log shipping destination.
        self.elasticsearch_elb = self.create_elasticsearch()
        self.create_logstash()
        self.create_kibana()

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
        startup_vars = []
        startup_vars.append(Join('=', ['ELASTICSEARCH_ELB_DNS_NAME', GetAtt(self.elasticsearch_elb, 'DNSName')]))
        # instance size dropped to a t2.small for making debugging cheaper.
        res = ec2.Instance("logstash", InstanceType="t2.small", ImageId="ami-e7527ed7",
            Tags=Tags(Name="logstash",), UserData=self.build_bootstrap(['src/logstash_bootstrap.sh'], variable_declarations= startup_vars),
            KeyName=Ref(self.template.parameters['ec2Key']),
            IamInstanceProfile=Ref('logstashsqsroleInstancePolicy'),
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
        # this resource needs to be dropped into a VPC.  For now, we can use a public subnet.
        res = ec2.Instance("kibana", InstanceType="t2.small", ImageId="ami-e7527ed7",
            Tags=Tags(Name="kibana",), UserData=self.build_bootstrap(['src/kibana_bootstrap.sh']))
        self.template.add_resource(res)

    def create_elasticsearch(self):
        # this resource needs to be dropped into a VPC.  For now, we can use a public subnet.
        elasticsearchinstance = ec2.Instance("es", InstanceType="t2.small", ImageId="ami-e7527ed7",
            Tags=Tags(Name="es",), UserData=self.build_bootstrap(['src/elasticsearch_bootstrap.sh']))
        self.template.add_resource(elasticsearchinstance)

        # ELB for the instance
        # NEEDS A SECURITY GROUP
        elasticsearch_elb = self.template.add_resource(elb.LoadBalancer(
            'ESELB',
            AccessLoggingPolicy=elb.AccessLoggingPolicy(
                EmitInterval=5,
                Enabled=True,
                S3BucketName="logging",
                S3BucketPrefix="myELB",
            ),
            AvailabilityZones=self.azs, # should be from networkbase
            ConnectionDrainingPolicy=elb.ConnectionDrainingPolicy(
                Enabled=True,
                Timeout=300,
            ),
            CrossZone=True,
            Instances=[elasticsearchinstance],
            Listeners=[
                elb.Listener(
                    LoadBalancerPort="9200",
                    InstancePort="9200",
                    Protocol="HTTP",
                ),
            ],
            HealthCheck=elb.HealthCheck(
                Target=Join("", ["HTTP:", "9200", "/"]),
                HealthyThreshold="3",
                UnhealthyThreshold="10",
                Interval="30",
                Timeout="5",
            )
        ))
        return elasticsearch_elb


def main():
    ElkStack()

if __name__ == '__main__':
    main()
