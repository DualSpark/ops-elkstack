#!/usr/bin/env python

"""
elkstack

Tool bundle manages generation, deployment, and feedback of cloudformation resources.

Usage:
    elkstack (init|create|deploy|delete) [--config-file <FILE_LOCATION>] [--debug] [--template-file=<TEMPLATE_FILE>]

Options:
  -h --help                            Show this screen.
  -v --version                         Show version.
  --debug                              Prints parent template to console out.
  --config-file <CONFIG_FILE>          Name of json configuration file. Default value is config.json
  --stack-name <STACK_NAME>            User-definable value for the CloudFormation stack being deployed.
  --template-file=<TEMPLATE_FILE>      Name of template to be either generated or deployed.
"""

from environmentbase.networkbase import NetworkBase
from environmentbase.environmentbase import EnvConfig
from environmentbase.cli import CLI
from environmentbase.template import Template
from troposphere import ec2, Tags, Ref, iam, GetAtt, Join, FindInMap, Output
from troposphere.ec2 import NetworkInterfaceProperty
from troposphere.sqs import Queue
from troposphere.autoscaling import Tag
import troposphere.autoscaling as autoscaling
import troposphere.elasticloadbalancing as elb
from environmentbase import resources
from environmentbase.patterns import bastion

class ElkTemplate(Template):
    """
    Enhances basic template by adding elasticsearch, kibana and logstash services.
    """

    # Load USER_DATA scripts from package
    E_BOOTSTRAP_SH = resources.get_resource('elasticsearch_bootstrap.sh', __name__)
    L_BOOTSTRAP_SH = resources.get_resource('logstash_bootstrap.sh', __name__)
    K_BOOTSTRAP_SH = resources.get_resource('kibana_bootstrap.sh', __name__)

    # When no config.json file exists a new one is created using the 'factory default' file.  This function
    # augments the factory default before it is written to file with the config values required by an ElkTemplate
    @staticmethod
    def get_factory_defaults():
        return {
            'elk': {
                'elasticsearch_ami_id': 'amazonLinuxAmiId',
                'logstash_ami_id': 'amazonLinuxAmiId',
                'kibana_ami_id': 'amazonLinuxAmiId'
            }
        }

    # When the user request to 'create' a new ELK template the config.json file is read in. This file is checked to
    # ensure all required values are present. Because ELK stack has additional requirements beyond that of
    # EnvironmentBase this function is used to add additional validation checks.
    @staticmethod
    def get_config_schema():
        return {
            'elk': {
                'elasticsearch_ami_id': 'str',
                'logstash_ami_id': 'str',
                'kibana_ami_id': 'str'
            }
        }


    # Collect all the values we need to assemble our ELK stack
    def __init__(self, env_name, e_ami_id, l_ami_id, k_ami_id, public_subnet_layer='public', private_subnet_layer='private'):
        super(ElkTemplate, self).__init__('Elk')
        self.env_name = env_name
        self.e_ami_id = e_ami_id
        self.l_ami_id = l_ami_id
        self.k_ami_id = k_ami_id
        self.public_subnet_layer = public_subnet_layer
        self.private_subnet_layer = private_subnet_layer

    # Called after add_child_template() has attached common parameters and some instance attributes:
    # - RegionMap: Region to AMI map, allows template to be deployed in different regions without updating AMI ids
    # - ec2Key: keyname to use for ssh authentication
    # - vpcCidr: IP block claimed by whole VPC
    # - vpcId: resource id of VPC
    # - commonSecurityGroup: sg identifier for common allowed ports (22 in from VPC)
    # - utilityBucket: S3 bucket name used to send logs to
    # - availabilityZone[0-9]: Indexed names of AZs VPC is deployed to
    # - [public|private]Subnet[0-9]: indexed and classified subnet identifiers
    #
    # and some instance attributes referencing the attached parameters:
    # - self.vpc_cidr
    # - self.vpc_id
    # - self.common_security_group
    # - self.utility_bucket
    # - self.subnets: keyed by type, layer name, and index (e.g. self.subnets['public']['web'][1])
    # - self.azs: List of parameter references
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
                            "sqs:ReceiveMessage",
                            "sqs:DeleteMessage",
                            "sqs:DeleteMessageBatch"
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
            VpcId=self.vpc_id,
            SecurityGroupEgress=[ec2.SecurityGroupRule(
                        FromPort='9200',
                        ToPort='9200',
                        IpProtocol='tcp',
                        SourceSecurityGroupId=self.common_security_group)], # AWS bug: should be DestinationSecurityGroupId
            SecurityGroupIngress= [ec2.SecurityGroupRule(
                        FromPort='9200',
                        ToPort='9200',
                        IpProtocol='tcp',
                        SourceSecurityGroupId=self.common_security_group)]
            ))

        # Elastichsearch to Elasticsearch inter-node communication SG
        self.elastic_internal_sg = self.add_resource(ec2.SecurityGroup('elasticsearchNodeSecurityGroup',
            GroupDescription='For elasticsearch nodes to chatter to each other',
            VpcId=self.vpc_id,
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
            Subnets=self.subnets['private'][self.private_subnet_layer],  # should be from networkbase
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
            SecurityGroups=[self.common_security_group, Ref(self.elastic_sg)],
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
        self.launch_config = self.add_resource(autoscaling.LaunchConfiguration('ElasticSearchers' + 'LaunchConfiguration',
                ImageId=FindInMap('RegionMap', Ref('AWS::Region'), ami_id),
                InstanceType='t2.micro',
                SecurityGroups=[self.common_security_group, Ref(self.elastic_sg), Ref(self.elastic_internal_sg)],
                KeyName=Ref(self.parameters['ec2Key']),
                AssociatePublicIpAddress=False,
                InstanceMonitoring=False,
                UserData=self.build_bootstrap([ElkTemplate.E_BOOTSTRAP_SH], variable_declarations=startup_vars),
                IamInstanceProfile=Ref('queryinstancesroleInstancePolicy')))

        # ASG with above launch config
        self.es_asg = self.add_resource(autoscaling.AutoScalingGroup('ElasticSearchers' + 'AutoScalingGroup',
            AvailabilityZones=self.azs,
            LaunchConfigurationName=Ref(self.launch_config),
            MaxSize=1,
            MinSize=1,
            DesiredCapacity=1,
            VPCZoneIdentifier=self.subnets['private'][self.private_subnet_layer],
            TerminationPolicies=['OldestLaunchConfiguration', 'ClosestToNextInstanceHour', 'Default'],
            LoadBalancerNames=[Ref(self.elasticsearch_elb)],
            Tags=[
                Tag('stage', 'dev', True),
                Tag('Name', 'elasticsearch', True)
            ]) # https://github.com/elastic/elasticsearch-cloud-aws
        )

    def create_logstash_outbound_sg(self):
        self.logstash_sg = self.add_resource(ec2.SecurityGroup(
            'logstashSecurityGroup',
            GroupDescription='For logstash egress to elasticsearch',
            VpcId=self.vpc_id,
            SecurityGroupEgress=[ec2.SecurityGroupRule(
                        FromPort='9200',
                        ToPort='9200',
                        IpProtocol='tcp',
                        SourceSecurityGroupId=Ref(self.elastic_sg))], # AWS bug: should be DestinationSecurityGroupId
            ))

    def create_logstash(self, ami_id):
        startup_vars = []
        startup_vars.append(Join('=', ['ELASTICSEARCH_ELB_DNS_NAME', GetAtt(self.elasticsearch_elb, 'DNSName')]))

        self.logstash_launch_config = autoscaling.LaunchConfiguration('Logstashers' + 'LaunchConfiguration',
            ImageId=FindInMap('RegionMap', Ref('AWS::Region'), ami_id),
            InstanceType='t2.micro',
            SecurityGroups=[self.common_security_group, Ref(self.logstash_sg)],
            KeyName=Ref(self.parameters['ec2Key']),
            AssociatePublicIpAddress=False,
            InstanceMonitoring=False,
            UserData=self.build_bootstrap([ElkTemplate.L_BOOTSTRAP_SH], variable_declarations=startup_vars),
            IamInstanceProfile=Ref('logstashsqsroleInstancePolicy'))
        self.add_resource(self.logstash_launch_config)

        self.logstash_asg = autoscaling.AutoScalingGroup('Logstashers' + 'AutoScalingGroup',
            AvailabilityZones=self.azs,
            LaunchConfigurationName=Ref(self.logstash_launch_config),
            MaxSize=1,
            MinSize=1,
            DesiredCapacity=1,
            VPCZoneIdentifier=self.subnets['private'][self.private_subnet_layer],
            TerminationPolicies=['OldestLaunchConfiguration', 'ClosestToNextInstanceHour', 'Default'],
            Tags=[
                Tag('stage', 'dev', True),
                Tag('Name', 'logstash', True)
            ])
        self.add_resource(self.logstash_asg)

    def create_kibana(self, ami_id):
        self.kibana_ingress_sg = self.add_resource(ec2.SecurityGroup(
            'kibanaIngressSecurityGroup',
            GroupDescription='For kibana ingress',
            VpcId=self.vpc_id,
            SecurityGroupEgress=[
                ec2.SecurityGroupRule(
                    FromPort='5601',
                    ToPort='5601',
                    IpProtocol='tcp',
                    CidrIp='0.0.0.0/0'),
                ec2.SecurityGroupRule(
                    FromPort='81',
                    ToPort='81',
                    IpProtocol='tcp',
                    CidrIp='0.0.0.0/0')
                    ],
            SecurityGroupIngress= [
                ec2.SecurityGroupRule(
                    FromPort='5601',
                    ToPort='5601',
                    IpProtocol='tcp',
                    CidrIp='0.0.0.0/0'),
                # for ELB healthcheck, okay to open to world
                ec2.SecurityGroupRule(
                    FromPort='81',
                    ToPort='81',
                    IpProtocol='tcp',
                    CidrIp='0.0.0.0/0')]
            ))

        self.kibana_elb = self.add_resource(elb.LoadBalancer(
            'KibanaELB',
            AccessLoggingPolicy=elb.AccessLoggingPolicy(
                Enabled=False,
            ),
            Subnets=self.subnets['public'][self.public_subnet_layer],  # should be from networkbase
            ConnectionDrainingPolicy=elb.ConnectionDrainingPolicy(
                Enabled=True,
                Timeout=300,
            ),
            CrossZone=True,
            Listeners=[
                elb.Listener(
                    LoadBalancerPort="5601",
                    InstancePort="5601",
                    Protocol="HTTP",
                ),
            ],
            SecurityGroups=[self.common_security_group, Ref(self.kibana_ingress_sg)],
            HealthCheck=elb.HealthCheck(
                Target=Join("", ["HTTP:", "81", "/"]),
                HealthyThreshold="3",
                UnhealthyThreshold="10",
                Interval="30",
                Timeout="5",
            )
        ))
        # Not DRY:
        startup_vars = []
        startup_vars.append(Join('=', ['ELASTICSEARCH_ELB_DNS_NAME', GetAtt(self.elasticsearch_elb, 'DNSName')]))
        startup_vars.append(Join('=', ['KIBANA_PASSWORD', 'kpassword'])) # move to input from user

        self.kibana_launch_config = autoscaling.LaunchConfiguration('Kibana' + 'LaunchConfiguration',
            ImageId=FindInMap('RegionMap', Ref('AWS::Region'), ami_id),
            InstanceType='t2.micro',
            SecurityGroups=[self.common_security_group, Ref(self.elastic_sg), Ref(self.kibana_ingress_sg)],
            KeyName=Ref(self.parameters['ec2Key']),
            AssociatePublicIpAddress=True,
            InstanceMonitoring=False,
            UserData=self.build_bootstrap([ElkTemplate.K_BOOTSTRAP_SH], variable_declarations=startup_vars))
        self.add_resource(self.kibana_launch_config)

        self.kibana_asg = autoscaling.AutoScalingGroup('Kibana' + 'AutoScalingGroup',
            AvailabilityZones=self.azs,
            LaunchConfigurationName=Ref(self.kibana_launch_config),
            MaxSize=1,
            MinSize=1,
            DesiredCapacity=1,
            VPCZoneIdentifier=self.subnets['public'][self.public_subnet_layer],
            TerminationPolicies=['OldestLaunchConfiguration', 'ClosestToNextInstanceHour', 'Default'],
            LoadBalancerNames=[Ref(self.kibana_elb)],
            Tags=[Tag('Name', 'kibana', True)],
            DependsOn='ElasticSearchersAutoScalingGroup')

        self.add_resource(self.kibana_asg)

        self.add_output([
            Output(
                "KibanaELBURL",
                Description="Kibana ELB URL",
                Value=GetAtt(self.kibana_elb, 'DNSName'),
            ),
        ])

class ElkStackController(NetworkBase):
    """
    Coordinates ELK stack actions (create and deploy)
    """

    # Override the default create hook to construct an ELK stack
    def create_hook(self):

        self.add_child_template(bastion.Bastion())

        # Load some settings from the config file
        elk_config = self.config.get('elk')
        env_name = self.globals.get('environment_name', 'environmentbase')

        # Create our ELK Template (defined above)
        elk_template = ElkTemplate(env_name,
            elk_config.get('elasticsearch_ami_id'),
            elk_config.get('logstash_ami_id'),
            elk_config.get('kibana_ami_id'))

        # Add the ELK template as a child of the top-level template
        # Note: This function modifies the incoming child template by attaching some standard inputs. For details
        # see ElkTemplate.build_hook() above.
        # After parameters are added to the template it is serialized to file and uploaded to S3 (s3_utility_bucket).
        # Finally a 'Stack' resource is added to the top-level template referencing the child template in S3 and
        # assigning values to each of the input parameters.
        self.add_child_template(elk_template)



def main():
    # This cli object takes the documentation comment at the top of this file (__doc__) and parses it against the
    # command line arguments (sys.argv).  Supported commands are init, create, deploy, delete. The deploy function works fine as
    # is. ElkStackController overrides the create hook to include an ELK stack as an additional template.
    cli = CLI(doc=__doc__)
    env_config = EnvConfig(config_handlers=[ElkTemplate])
    ElkStackController(env_config=env_config, view=cli)

if __name__ == '__main__':
    main()
