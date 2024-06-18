import os.path

from aws_cdk.aws_s3_assets import Asset

from aws_cdk import (
    aws_ec2 as ec2,
    aws_iam as iam,
    App, Stack
)

from constructs import Construct

dirname = os.path.dirname(__file__)


class EC2InstanceStack(Stack):

    def __init__(self, scope: Construct, id: str, **kwargs) -> None:
        super().__init__(scope, id, **kwargs)

        # VPC
        vpc = ec2.Vpc(self, "VPC",
            nat_gateways=0,
            subnet_configuration=[ec2.SubnetConfiguration(name="public",subnet_type=ec2.SubnetType.PUBLIC)]
            )

        # AMI
        amzn_linux = ec2.MachineImage.latest_amazon_linux(
            generation=ec2.AmazonLinuxGeneration.AMAZON_LINUX_2,
            edition=ec2.AmazonLinuxEdition.STANDARD,
            virtualization=ec2.AmazonLinuxVirt.HVM,
            storage=ec2.AmazonLinuxStorage.GENERAL_PURPOSE
            )

        # Instance Role and SSM Managed Policy
        role = iam.Role(self, "InstanceSSM", assumed_by=iam.ServicePrincipal("ec2.amazonaws.com"))

        role.add_managed_policy(iam.ManagedPolicy.from_aws_managed_policy_name("AmazonSSMManagedInstanceCore"))

        # Instance
        # instance = ec2.Instance(self, "Instance",
        #     instance_type=ec2.InstanceType("t3.nano"),
        #     machine_image=amzn_linux,
        #     vpc = vpc,
        #     role = role
        #     )

        # # Script in S3 as Asset
        # asset = Asset(self, "Asset", path=os.path.join(dirname, "configure.sh"))
        # local_path = instance.user_data.add_s3_download_command(
        #     bucket=asset.bucket,
        #     bucket_key=asset.s3_object_key
        # )

        # # Userdata executes script from S3
        # instance.user_data.add_execute_file_command(
        #     file_path=local_path
        #     )
        # asset.grant_read(instance.role)


class CursoAwsExample(Stack):
       def __init__(self, scope: Construct, id: str, **kwargs) -> None:
        super().__init__(scope, id, **kwargs) 
                # VPC
         
        vpc = ec2.Vpc(self, 
            id="CDK-curso-aws",
            cidr="192.169.0.0/16",
            nat_gateways=1,
            subnet_configuration=[
                ec2.SubnetConfiguration(
                    name="public-curso",
                    subnet_type=ec2.SubnetType.PUBLIC,
                    cidr_mask=24),
                ec2.SubnetConfiguration(
                    name="private-curso",
                    subnet_type=ec2.SubnetType.PRIVATE_WITH_EGRESS,
                    cidr_mask=24
                ),
                ec2.SubnetConfiguration(
                    name="public-curso-2",
                    subnet_type=ec2.SubnetType.PUBLIC,
                    cidr_mask=24),
                ],
            nat_gateway_subnets={
                "subnet_group_name": "public-curso"
                },            
            )

        #Instance
        instance = ec2.Instance(self, 
            id="Public-Instance-cdk",
            #availability_zone="us-west-2a",
            instance_type=ec2.InstanceType("t2.micro"),
            machine_image=ec2.MachineImage.generic_linux(
                {"us-west-2": "ami-0cf2b4e024cdb6960"}  
            ),
            key_name="cursoAWS1",
            vpc=vpc,
            security_group=ec2.ISecurityGroup.add_ingress_rule(
                self=self,        
                peer=ec2.Peer.any_ipv4(),  # Permite conexiones desde cualquier IP pública
                connection=ec2.Port.tcp(22),  # Puerto 22 TCP para SSH
                description="Allow SSH access from any IP curso"),
            vpc_subnets={
                "subnet_group_name": "public-curso"
            }
            )

app = App()
EC2InstanceStack(app, "ec2-instance")
CursoAwsExample(app, "ejemplo-vpc-ec2")

app.synth()