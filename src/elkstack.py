"""
elkstack

Tool bundle manages generation, deployment, and feedback of cloudformation resources.

Usage:
    elkstack (create|deploy) [--config-file <FILE_LOCATION>] [--debug] [--template-file=<TEMPLATE_FILE>]

Options:
  -h --help                            Show this screen.
  -v --version                         Show version.
  --debug                              Prints parent template to console out.
  --config-file <CONFIG_FILE>          Name of json configuration file. Default value is config.json
  --stack-name <STACK_NAME>            User-definable value for the CloudFormation stack being deployed.
  --template-file=<TEMPLATE_FILE>      Name of template to be either generated or deployed.
"""

from environmentbase.networkbase import NetworkBase
from environmentbase.cli import CLI
from environmentbase.environmentbase import CONFIG_REQUIREMENTS
from environmentbase.template import Template
from troposphere import ec2, Tags, Base64, Ref, iam, GetAtt, GetAZs, Join, FindInMap
from troposphere.ec2 import NetworkInterfaceProperty
from troposphere.iam import Role, InstanceProfile
from troposphere.iam import PolicyType as IAMPolicy, Policy
from troposphere.sqs import Queue
import troposphere.elasticloadbalancing as elb
import json
import string
import os
import docopt


class ElkTemplate(Template):

    def __init__(self, resource_name='ElkStack'):
        super(ElkTemplate, self).__init__(resource_name)

    def create_logstash_queue(self):
        self.queue = Queue("logstashincoming", QueueName="logstashincoming")
        self.add_resource(self.queue)

    def create_instance_profiles_for_reading_sqs(self, env_name):
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

        self.add_instance_profile(layer_name="logstashsqsrole", iam_policies=self.policies, path_prefix=env_name)

    def create_elasticsearch(self, ami_id):
        self.elastic_sg = self.add_resource(ec2.SecurityGroup('elasticsearchSecurityGroup',
            GroupDescription='For elasticsearch ingress from logstash',
            VpcId=Ref(self.vpc_id),
            SecurityGroupEgress=[ec2.SecurityGroupRule(
                        FromPort='9200',
                        ToPort='9200',
                        IpProtocol='tcp',
                        SourceSecurityGroupId=Ref(self.common_security_group))], # AWS bug: should be DestinationSecurityGroupId
            SecurityGroupIngress= [ec2.SecurityGroupRule(
                        FromPort='9200',
                        ToPort='9200',
                        IpProtocol='tcp',
                        SourceSecurityGroupId=Ref(self.common_security_group))]
            ))

        elasticsearchinstance = ec2.Instance(
            "es",
            InstanceType="t2.micro",
            ImageId=FindInMap(Ref('RegionMap'), Ref('AWS::Region'), ami_id),
            Tags=Tags(Name="es",),
            UserData=self.build_bootstrap(['src/elasticsearch_bootstrap.sh']),
            KeyName=Ref(self.parameters['ec2Key']),
            NetworkInterfaces=[
                NetworkInterfaceProperty(
                    GroupSet=[
                        Ref(self.common_security_group),
                        Ref(self.elastic_sg)],
                    AssociatePublicIpAddress='true',
                    DeviceIndex='0',
                    DeleteOnTermination='true',
                    SubnetId=self.subnets['public'][0])])

        self.add_resource(elasticsearchinstance)

        instances = []
        instances.append(elasticsearchinstance)

        # ELB for the instance
        self.elasticsearch_elb = self.add_resource(elb.LoadBalancer(
            'ESELB',
            AccessLoggingPolicy=elb.AccessLoggingPolicy(
                Enabled=False,
            ),
            Subnets=self.subnets['public'],  # should be from networkbase
            ConnectionDrainingPolicy=elb.ConnectionDrainingPolicy(
                Enabled=True,
                Timeout=300,
            ),
            Scheme="internal",
            CrossZone=True,
            Instances=[Ref(r) for r in instances],
            Listeners=[
                elb.Listener(
                    LoadBalancerPort="9200",
                    InstancePort="9200",
                    Protocol="HTTP",
                ),
            ],
            SecurityGroups=[Ref(self.common_security_group), Ref(self.elastic_sg)],
            HealthCheck=elb.HealthCheck(
                Target=Join("", ["HTTP:", "9200", "/"]),
                HealthyThreshold="3",
                UnhealthyThreshold="10",
                Interval="30",
                Timeout="5",
            )
        ))

    def create_logstash_outbound_sg(self):
        self.logstash_sg = self.add_resource(ec2.SecurityGroup(
            'logstashSecurityGroup',
            GroupDescription='For logstash egress to elasticsearch',
            VpcId=Ref(self.vpc_id),
            SecurityGroupEgress=[ec2.SecurityGroupRule(
                        FromPort='9200',
                        ToPort='9200',
                        IpProtocol='tcp',
                        SourceSecurityGroupId=Ref(self.elastic_sg))], # AWS bug: should be DestinationSecurityGroupId
            # SecurityGroupIngress= [ec2.SecurityGroupRule(
            #             FromPort='9200',
            #             ToPort='9200',
            #             IpProtocol='tcp',
            #             SourceSecurityGroupId=Ref(self.elastic_sg))]
            ))

    def create_logstash(self, ami_id):
        startup_vars = []
        startup_vars.append(Join('=', ['ELASTICSEARCH_ELB_DNS_NAME', GetAtt(self.elasticsearch_elb, 'DNSName')]))

        logstash = ec2.Instance(
            "logstash",
            InstanceType="t2.micro",
            ImageId=FindInMap(Ref('RegionMap'), Ref('AWS::Region'), ami_id),
            Tags=Tags(Name="logstash",),
            UserData=self.build_bootstrap(['src/logstash_bootstrap.sh'], variable_declarations=startup_vars),
            KeyName=Ref(self.parameters['ec2Key']),
            IamInstanceProfile=Ref('logstashsqsroleInstancePolicy'),
            NetworkInterfaces=[
                NetworkInterfaceProperty(
                    GroupSet=[
                        Ref(self.common_security_group),
                        Ref(self.logstash_sg)],
                    AssociatePublicIpAddress='true',
                    DeviceIndex='0',
                    DeleteOnTermination='true',
                    SubnetId=self.subnets['public'][0])]
            )

        self.add_resource(logstash)

    def create_kibana(self, ami_id):
        # This is open to the world, should switch to nginx for basic auth
        self.kibana_ingress_sg = self.add_resource(ec2.SecurityGroup(
            'kibanaIngressSecurityGroup',
            GroupDescription='For kibana ingress',
            VpcId=Ref(self.vpc_id),
            SecurityGroupEgress=[ec2.SecurityGroupRule(
                FromPort='5601',
                ToPort='5601',
                IpProtocol='tcp',
                CidrIp='0.0.0.0/0')], # AWS bug: should be DestinationSecurityGroupId
            SecurityGroupIngress= [ec2.SecurityGroupRule(
                FromPort='5601',
                ToPort='5601',
                IpProtocol='tcp',
                CidrIp='0.0.0.0/0')]
            ))

        # Not DRY:
        startup_vars = []
        startup_vars.append(Join('=', ['ELASTICSEARCH_ELB_DNS_NAME', GetAtt(self.elasticsearch_elb, 'DNSName')]))

        kibana = ec2.Instance("kibana", InstanceType="t2.micro",
            ImageId=FindInMap(Ref('RegionMap'), Ref('AWS::Region'), ami_id),
            Tags=Tags(Name="kibana",), UserData=self.build_bootstrap(['src/kibana_bootstrap.sh'], variable_declarations= startup_vars),
            KeyName=Ref(self.parameters['ec2Key']),
            NetworkInterfaces=[
            NetworkInterfaceProperty(
                GroupSet=[
                    Ref(self.common_security_group),            # common
                    Ref(self.kibana_ingress_sg),    # users can talk to kibana
                    Ref(self.elastic_sg)],          # kibana can talk to the ES ELB
                AssociatePublicIpAddress='true',
                DeviceIndex='0',
                DeleteOnTermination='true',
                SubnetId=self.subnets['public'][0])])

        self.add_resource(kibana)


class ElkStack(NetworkBase):
    """
    ELK stack template generation
    """

    def __init__(self, *args, **kwargs):
        CONFIG_REQUIREMENTS['elk'] = [
            ('elasticsearch_ami_id', basestring),
            ('logstash_ami_id', basestring),
            ('kibana_ami_id', basestring)
        ]

        super(ElkStack, self).__init__(*args, **kwargs)

    def create_action(self):
        elk_config = self.config.get('elk')
        env_name = self.globals.get('environment_name', 'environmentbase')
        self.initialize_template()
        self.construct_network()

        elk_template = ElkTemplate()
        self.add_common_params_to_child_template(elk_template)
        # ----------------------------------
        elk_template.create_logstash_queue()

        elk_template.create_instance_profiles_for_reading_sqs(env_name)

        elk_template.create_elasticsearch(elk_config.get('elasticsearch_ami_id'))

        elk_template.create_logstash_outbound_sg()

        elk_template.create_logstash(elk_config.get('logstash_ami_id'))

        elk_template.create_kibana(elk_config.get('kibana_ami_id'))
        # ----------------------------------
        self.add_child_template(elk_template)
        self.write_template_to_file()


def main():
    cli = CLI(doc=__doc__)
    ElkStack(view=cli)

if __name__ == '__main__':
    main()
