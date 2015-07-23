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
from environmentbase.resources import CONFIG_REQUIREMENTS
from environmentbase.template import Template
from troposphere import ec2, Tags, Base64, Ref, iam, GetAtt, GetAZs, Join, FindInMap, Output
from troposphere.ec2 import NetworkInterfaceProperty
from troposphere.iam import Role, InstanceProfile
from troposphere.iam import PolicyType as IAMPolicy, Policy
from troposphere.sqs import Queue
from troposphere.autoscaling import Tag
import troposphere.autoscaling as autoscaling
import troposphere.elasticloadbalancing as elb
import json
import string
import os
import docopt
from environmentbase import resources



class ElkTemplate(Template):

    E_BOOTSTRAP_SH = resources.get_resource('elasticsearch_bootstrap.sh', __name__)
    L_BOOTSTRAP_SH = resources.get_resource('kibana_bootstrap.sh', __name__)
    K_BOOTSTRAP_SH = resources.get_resource('logstash_bootstrap.sh', __name__)

    DEFAULT_CONFIG = {
        'elk': {
            'elasticsearch_ami_id': 'amazonLinuxAmiId',
            'logstash_ami_id': 'amazonLinuxAmiId',
            'kibana_ami_id': 'amazonLinuxAmiId'
        }
    }

    CONFIG_SCHEMA = {
        'elk': {
            'elasticsearch_ami_id': 'str',
            'logstash_ami_id': 'str',
            'kibana_ami_id': 'str'
        }
    }

    def __init__(self, env_name, e_ami_id, l_ami_id, k_ami_id):
        super(ElkTemplate, self).__init__('ElkStack')
        self.env_name = env_name
        self.e_ami_id = e_ami_id
        self.l_ami_id = l_ami_id
        self.k_ami_id = k_ami_id

    def build_hook(self):
        self.create_logstash_queue()
        self.create_instance_profiles_for_reading_sqs(self.env_name)
        self.create_elasticsearch(self.e_ami_id)
        self.create_logstash_outbound_sg()
        self.create_logstash(self.l_ami_id)
        self.create_instance_profiles_for_talking_to_ec2(self.env_name)
        self.create_kibana(self.k_ami_id)

    def create_logstash_queue(self):
        self.queue = Queue("logstashincoming", QueueName="logstashincoming")
        self.add_resource(self.queue)

    def create_instance_profiles_for_reading_sqs(self, env_name):
        # configured per https://www.elastic.co/guide/en/logstash/current/plugins-inputs-sqs.html
        self.policies = [iam.Policy(
            PolicyName='logstashsqsrole',
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

    def create_instance_profiles_for_talking_to_ec2(self, env_name):
        # configured per https://github.com/elastic/elasticsearch-cloud-aws
        self.queryec2 = [iam.Policy(
            PolicyName='queryinstancesrole',
            PolicyDocument={
                "Statement": [{
                    "Effect": "Allow",
                        "Action": [
                            "ec2:DescribeAvailabilityZones",
                            "ec2:DescribeInstances",
                            "ec2:DescribeRegions",
                            "ec2:DescribeSecurityGroups",
                            "ec2:DescribeTags"
                        ],
                        "Resource": ["*"] }]
            })]
        self.add_instance_profile(layer_name="queryinstancesrole", iam_policies=self.queryec2, path_prefix=env_name)

    def create_elasticsearch(self, ami_id):
        # Elasticsearch SG for ingress from logstash
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

        # Elastichsearch to Elasticsearch inter-node communication SG
        self.elastic_internal_sg = self.add_resource(ec2.SecurityGroup('elasticsearchNodeSecurityGroup',
            GroupDescription='For elasticsearch nodes to chatter to each other',
            VpcId=Ref(self.vpc_id),
            SecurityGroupEgress=[ec2.SecurityGroupRule(
                        FromPort='9300',
                        ToPort='9400',
                        IpProtocol='tcp',
                        SourceSecurityGroupId=Ref(self.elastic_sg))], # AWS bug: should be DestinationSecurityGroupId
            SecurityGroupIngress= [ec2.SecurityGroupRule(
                        FromPort='9300',
                        ToPort='9400',
                        IpProtocol='tcp',
                        SourceSecurityGroupId=Ref(self.elastic_sg))]
            ))

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

        startup_vars = []
        startup_vars.append(Join('=', ['REGION', Ref('AWS::Region')]))

        # ASG launch config for instances
        self.launch_config = autoscaling.LaunchConfiguration('ElastichSearchers' + 'LaunchConfiguration',
                ImageId=FindInMap('RegionMap', Ref('AWS::Region'), ami_id),
                InstanceType='t2.micro',
                SecurityGroups=[Ref(self.common_security_group), Ref(self.elastic_sg), Ref(self.elastic_internal_sg)],
                KeyName=Ref(self.parameters['ec2Key']),
                AssociatePublicIpAddress=True, # set to false when dropped into private subnet
                InstanceMonitoring=False,
                UserData=self.build_bootstrap([ElkTemplate.E_BOOTSTRAP_SH], variable_declarations=startup_vars),
                IamInstanceProfile=Ref('queryinstancesroleInstancePolicy'))

        self.add_resource(self.launch_config)

        # ASG with above launch config
        self.es_asg = autoscaling.AutoScalingGroup('ElastichSearchers' + 'AutoScalingGroup',
            AvailabilityZones=self.azs,
            LaunchConfigurationName=Ref(self.launch_config),
            MaxSize=1,
            MinSize=1,
            DesiredCapacity=1,
            VPCZoneIdentifier=self.subnets['public'], # switch to private later
            TerminationPolicies=['OldestLaunchConfiguration', 'ClosestToNextInstanceHour', 'Default'],
            LoadBalancerNames=[Ref(self.elasticsearch_elb)],
            Tags=[
                Tag('stage', 'dev', True),
                Tag('Name', 'elasticsearch', True)
            ]) # https://github.com/elastic/elasticsearch-cloud-aws
        self.add_resource(self.es_asg)

        self.add_output([
            Output(
                "ElasticSearchELBURL",
                Description="ElasticSearch ELB URL",
                Value=GetAtt(self.elasticsearch_elb, 'DNSName'),
            ),
        ])

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
            ))

    def create_logstash(self, ami_id):
        startup_vars = []
        startup_vars.append(Join('=', ['ELASTICSEARCH_ELB_DNS_NAME', GetAtt(self.elasticsearch_elb, 'DNSName')]))

        logstash = ec2.Instance(
            "logstash",
            InstanceType="t2.micro",
            ImageId=FindInMap('RegionMap', Ref('AWS::Region'), ami_id),
            Tags=Tags(Name="logstash",),
            UserData=self.build_bootstrap([ElkTemplate.L_BOOTSTRAP_SH], variable_declarations=startup_vars),
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
        self.kibana_ingress_sg = self.add_resource(ec2.SecurityGroup(
            'kibanaIngressSecurityGroup',
            GroupDescription='For kibana ingress',
            VpcId=Ref(self.vpc_id),
            SecurityGroupEgress=[ec2.SecurityGroupRule(
                FromPort='80',
                ToPort='80',
                IpProtocol='tcp',
                CidrIp='0.0.0.0/0')], # AWS bug: should be DestinationSecurityGroupId
            SecurityGroupIngress= [ec2.SecurityGroupRule(
                FromPort='80',
                ToPort='80',
                IpProtocol='tcp',
                CidrIp='0.0.0.0/0')]
            ))

        # Not DRY:
        startup_vars = []
        startup_vars.append(Join('=', ['ELASTICSEARCH_ELB_DNS_NAME', GetAtt(self.elasticsearch_elb, 'DNSName')]))
        startup_vars.append(Join('=', ['KIBANA_PASSWORD', 'kpassword'])) # move to input from user

        kibana = ec2.Instance("kibana", InstanceType="t2.micro",
            ImageId=FindInMap('RegionMap', Ref('AWS::Region'), ami_id),
            Tags=Tags(Name="kibana",),
            UserData=self.build_bootstrap([ElkTemplate.K_BOOTSTRAP_SH], variable_declarations= startup_vars),
            KeyName=Ref(self.parameters['ec2Key']),
            NetworkInterfaces=[
            NetworkInterfaceProperty(
                GroupSet=[
                    Ref(self.common_security_group),    # common
                    Ref(self.kibana_ingress_sg),        # users can talk to kibana
                    Ref(self.elastic_sg)],              # kibana can talk to the ES ELB
                AssociatePublicIpAddress='true',
                DeviceIndex='0',
                DeleteOnTermination='true',
                SubnetId=self.subnets['public'][0])])

        self.add_resource(kibana)


class ElkStack(NetworkBase):
    """
    ELK stack template generation
    """

    @staticmethod
    def get_factory_defaults_hook():
        return ElkTemplate.DEFAULT_CONFIG

    @staticmethod
    def get_config_schema_hook():
        return ElkTemplate.CONFIG_SCHEMA

    def create_action(self):
        elk_config = self.config.get('elk')
        env_name = self.globals.get('environment_name', 'environmentbase')
        self.initialize_template()
        self.construct_network()

        elk_template = ElkTemplate(env_name,
            elk_config.get('elasticsearch_ami_id'),
            elk_config.get('logstash_ami_id'),
            elk_config.get('kibana_ami_id'))

        self.add_child_template(elk_template)
        self.write_template_to_file()


def main():
    cli = CLI(doc=__doc__)
    ElkStack(view=cli)

if __name__ == '__main__':
    main()
