# elkstack
Elk Stack demo and deploy

## Getting Started


### Using a virtual environment to isolate dependencies:

```bash
git clone git@github.com:dualspark/ops-elkstack
cd ops-elkstack
pip install virtualenvwrapper
mkvirtualenv elkstack
python setup.py develop
```

Then when working on this project in the future, use `workon elkstack` to activate the configured environment and `deactivate` when you're finished.


### Configuring AWS authentication

If you have the AWS cli installed (`pip install awscli`), then you can run `aws configure` to set up your credentials. 
Otherwise you can manually create the following two files:  

**~/.aws/credentials**
```
[default]
aws_access_key_id = ACCESS_KEY
aws_secret_access_key = SECRET_KEY
```

**~/.aws/config**
```
[default]
output = json
region = us-west-2
```


## Creating your VPC

The creation of a basic VPC for use is automated within this process. The scripts included in this package include the process of creating:

* A VPC and Internet Gateway
* A Public and a Private subnet per AWS Availability Zone
* A NAT instance in each Public subnet along with the routing rules required to allow for egress to the public internet
* A common security group which is intended to allow for common egress rules (HTTP/S, NTP) and common ingress rules for SSH access from the bastion host

There is one last step within AWS' console to complete in order to continue. You will want to [generate an EC2 Key Pair](http://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-key-pairs.html) to use to access instances initially. The name of this key is arbitrary, but it is needed to configure the network deployment process.

Next, you'll need to set the configuration values within the file located at config.json. The following are the minimal set of items that are necessary to insert or validate:

* within the 'template' section:
  * Set the value of ec2_key_default to the key you created above.
  * Set the value of remote_access_cidr to a CIDR range that you want to be able to access the bastion host from. This is a single CIDR range (for now) and could be the network egress CIDR for the 23andMe corporate office, etc.
* within the 'network' section:
  * Set the values of the network size and CIDR base to your liking/needs. Note that this process will create a public and private subnet in each of the AWS Availability Zones configured (in order, up to 3).

From this point, you can simply open a terminal window at the location of this readme file and run the following commands to generate your VPC:

```bash
./elkstack.py create
./elkstack.py deploy
```
