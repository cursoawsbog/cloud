from os import path
import os.path
import json

from aws_cdk.aws_s3_assets import Asset
from aws_cdk import Size, Duration, RemovalPolicy
from aws_cdk import (
    aws_ec2 as ec2,
    aws_s3 as s3,
    aws_cloudfront as cf,
    aws_cloudfront_origins as origins,
    aws_lambda as lb,
    aws_dynamodb as table,
    aws_apigateway as api_g,
    aws_iam as iam,
    aws_wafv2 as waf,
    aws_secretsmanager as secrets,
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

class REST_API(Stack):

       def __init__(self, scope: Construct, id: str, **kwargs) -> None:
        super().__init__(scope, id, **kwargs) 
                # VPC

        dynamo_table = table.TableV2(
            self,
            id="table_aws_class",
            table_name="table_class_v3",
            billing=table.Billing.on_demand(),
            deletion_protection=False,
            partition_key=table.Attribute(name="id_curso", type=table.AttributeType.STRING),
        )

        fn = lb.Function(
                self,
                id = "MyLambda-v2",
                runtime=lb.Runtime.PYTHON_3_12,
                handler="lambda_code.lambda_handler",
                code=lb.Code.from_asset("./lambda"),
                ephemeral_storage_size=Size.mebibytes(512),
                timeout=Duration.seconds(2) 
        )
        
        fn_dynamo = lb.Function(
                self,
                id = "MyLambda-put-dynamo",
                runtime=lb.Runtime.PYTHON_3_12,
                handler="lambda_dynamo.lambda_handler",
                code=lb.Code.from_asset("./lambda"),
                ephemeral_storage_size=Size.mebibytes(512),
                timeout=Duration.seconds(2)           
        )
        
        fn_get_item_dynamo = lb.Function(
                self,
                id = "MyLambda-get-item-dynamo",
                runtime=lb.Runtime.PYTHON_3_12,
                handler="lambda_get_item.lambda_handler",
                code=lb.Code.from_asset("./lambda"),
                ephemeral_storage_size=Size.mebibytes(512),
                timeout=Duration.seconds(2)           
        )
        
        dynamo_table.grant_full_access(fn_dynamo)
        dynamo_table.grant_full_access(fn_get_item_dynamo)

        ap = api_g.RestApi(self,
                id="Curso-AWS-API-GW",
                rest_api_name="API-Curso",
                )
        consulta_resource = ap.root.add_resource("consulta")
        test_resource = ap.root.add_resource("test")
        # Create a Lambda integration
        lambda_integration = api_g.LambdaIntegration(fn)
        lambda_integration_dynamo = api_g.LambdaIntegration(fn_dynamo)
        lambda_integration_get_dynamo_item = api_g.LambdaIntegration(fn_get_item_dynamo)

        # Add GET method to the resource with Lambda integration
        consulta_resource.add_method("GET", lambda_integration_get_dynamo_item)
        consulta_resource.add_method("POST", lambda_integration_get_dynamo_item)
        test_resource.add_method("GET", lambda_integration)
        test_resource.add_method("POST", lambda_integration_dynamo)
        #Post 
        # curl -X POST https://j0hhglu7f1.execute-api.us-west-2.amazonaws.com/prod/consulta \
        # -H "Content-Type: application/json" \
        # -d '{"key1": "101", "key2": "Nicolas"}'
        
        #Consulta de un usuario con el id_curso
        # curl -X POST https://se4n9f4nb0.execute-api.us-west-2.amazonaws.com/prod/consulta \
        # -H "Content-Type: application/json"\
        # -d '{"key1": "103"}'

class Cloudfront(Stack):

       def __init__(self, scope: Construct, id: str, **kwargs) -> None:
        super().__init__(scope, id, **kwargs) 
                # VPC

        dynamo_table = table.TableV2(
            self,
            id="table_aws_class",
            table_name="table_class_v3",
            billing=table.Billing.on_demand(),
            deletion_protection=False,
            partition_key=table.Attribute(name="id_curso", type=table.AttributeType.STRING),
        )

        bucket = s3.Bucket(
            self,
            id = "website-cloudfront-curso-aws",
            block_public_access=s3.BlockPublicAccess.BLOCK_ALL,
            encryption=s3.BucketEncryption.S3_MANAGED, 
            removal_policy=RemovalPolicy.DESTROY,
        )
        
        source_bucket = bucket

        OAC = cf.CfnOriginAccessControl(
            self, 
            id = "CursoAwsMyCfnOriginAccessControl",
            origin_access_control_config=cf.CfnOriginAccessControl.OriginAccessControlConfigProperty(
                name="CursoAwsMyCfnOriginAccessControl",
                origin_access_control_origin_type="s3",
                signing_behavior="always",
                signing_protocol="sigv4",
                description="mi primer OAC origin access control aws class"
            )
        )
        

        
        distribution = cf.Distribution(
            self, 
            id="MyDistribution",
            default_root_object="index.html",
            default_behavior=cf.BehaviorOptions(
                origin=origins.S3Origin(
                    bucket=source_bucket
                )
            )
        )

        bucket.add_to_resource_policy(
            iam.PolicyStatement(
                sid='AllowCloudFrontServicePrincipal',
                actions=["s3:GetObject","s3:ListBucket","s3:*"],
                effect=iam.Effect.ALLOW,
                principals=[
                    iam.ServicePrincipal("cloudfront.amazonaws.com")
                ],
                resources=[
                    bucket.arn_for_objects("*"),
                    bucket.bucket_arn,
                ],
                conditions={
                    "StringEquals": {
                        "AWS:SourceArn": f"arn:aws:cloudfront::637423228695:distribution/{distribution.distribution_id}"
                    }
                }
            )
        )

        bucket_policy = source_bucket.policy
        bucket_policy_document = bucket_policy.document

        if isinstance(bucket_policy_document, iam.PolicyDocument):
            bucket_policy_document_json = bucket_policy_document.to_json()
            # create an updated policy without the OAI reference
            bucket_policy_updated_json = {'Version': '2012-10-17', 'Statement': []}
            for statement in bucket_policy_document_json['Statement']:
                if 'CanonicalUser' not in statement['Principal']:
                    bucket_policy_updated_json['Statement'].append(statement)


        # apply the updated bucket policy to the bucket
        bucket_policy_override = source_bucket.node.find_child("Policy").node.default_child
        bucket_policy_override.add_override('Properties.PolicyDocument', bucket_policy_updated_json)


        # remove the created OAI reference (S3 Origin property) for the distribution
        all_distribution_props = distribution.node.find_all()
        for child in all_distribution_props:
            if child.node.id == 'S3Origin':
                child.node.try_remove_child('Resource')

        # associate the created OAC with the distribution
        distribution_props = distribution.node.default_child
        distribution_props.add_override('Properties.DistributionConfig.Origins.0.S3OriginConfig.OriginAccessIdentity', '')
        distribution_props.add_property_override(
            "DistributionConfig.Origins.0.OriginAccessControlId",
            OAC.ref
        )


class Waf(Stack):
       def __init__(self, scope: Construct, id: str, **kwargs) -> None:
        super().__init__(scope, id, **kwargs) 

        bucket = s3.Bucket(
            self,
            id = "website-cloudfront-curso-aws",
            encryption=s3.BucketEncryption.S3_MANAGED, 
            removal_policy=RemovalPolicy.DESTROY,
        )

        cfn_iPSet = waf.CfnIPSet(
            self,
            id= "MyIpExampleClass",
            addresses=["45.238.183.187/32"],
            #addresses=["190.131.197.10/32","186.29.207.51/32"],
            scope="CLOUDFRONT",
            description="test bloqueo de ip Nicolas",
            name="BlockNicolasIp",
            ip_address_version="IPV4"
        )
        
        rule = waf.CfnWebACL.RuleProperty(
            name="BlockNicolasIpRule",
            priority=101,
            action=waf.CfnWebACL.RuleActionProperty(
                block={}
            ),
            statement=waf.CfnWebACL.StatementProperty(
                ip_set_reference_statement=waf.CfnWebACL.IPSetReferenceStatementProperty(
                    arn=cfn_iPSet.attr_arn
                )
            ),
            visibility_config=waf.CfnWebACL.VisibilityConfigProperty(
                cloud_watch_metrics_enabled=True,
                metric_name="BlockNicolasIpRule",
                sampled_requests_enabled=True
            )
        )     
        
        ruleGeoMatch = waf.CfnWebACL.RuleProperty(
            name     = 'GeoMatch',
            priority =  0,
            action   = waf.CfnWebACL.RuleActionProperty(
                block={} ## To disable, change to *count*
            ),
            statement = waf.CfnWebACL.StatementProperty(
                not_statement = waf.CfnWebACL.NotStatementProperty(
                statement = waf.CfnWebACL.StatementProperty(
                    geo_match_statement = waf.CfnWebACL.GeoMatchStatementProperty(
                    ##
                    ## block connection if source not in the below country list
                    ##
                    country_codes = [
                        "AR", ## Argentina
                        "BO", ## Bolivia
                        "BR", ## Brazil
                        "CL", ## Chile
                        "CO", ## Colombia
                        "EC", ## Ecuador
                        "FK", ## Falkland Islands
                        "GF", ## French Guiana
                        "GY", ## Guiana
                        "GY", ## Guyana
                        "PY", ## Paraguay
                        "PE", ## Peru
                        "SR", ## Suriname
                        "UY", ## Uruguay
                        "VE", ## Venezuela
                    ] ## country_codes
                    ) ## geo_match_statement
                ) ## statement
                ) ## not_statement
            ), ## statement
            visibility_config = waf.CfnWebACL.VisibilityConfigProperty(
                cloud_watch_metrics_enabled = True,
                metric_name                 = 'GeoMatch',
                sampled_requests_enabled    = True
            ) ## visibility_config
        ) ## GeoMatch

        acl = waf.CfnWebACL(
            self,
            id="MyACL",
            default_action=waf.CfnWebACL.DefaultActionProperty(
                allow={}
            ),
            scope="CLOUDFRONT",
            visibility_config=waf.CfnWebACL.VisibilityConfigProperty(
                cloud_watch_metrics_enabled=False,
                metric_name="metricName",
                sampled_requests_enabled=False
            ),
            description="test ACL de Nicolas",
            rules=[rule, ruleGeoMatch]
        )

        distribution = cf.Distribution(
            self, 
            id="MyDistribution",
            default_root_object="index.html",
            default_behavior=cf.BehaviorOptions(
                origin=origins.S3Origin(
                    bucket=bucket
                )
            ),
            web_acl_id=acl.attr_arn,
        )
        bucket.add_to_resource_policy(iam.PolicyStatement(
            actions=["s3:*"],
            resources=[bucket.arn_for_objects("*")],
            principals=[iam.ServicePrincipal("cloudfront.amazonaws.com")],
            conditions={
                "StringEquals": {
                    "AWS:SourceArn": f"arn:aws:cloudfront::{self.account}:distribution/{distribution.distribution_id}"
                }
            }
        ))

class Environment_Variables(Stack):
       def __init__(self, scope: Construct, id: str, **kwargs) -> None:
        super().__init__(scope, id, **kwargs) 
        
        user = "Edwin12"
        access_key = "123456789"
         
        secreto_edwin = secrets.Secret(
            self,
            id= "Secreto de Edwin",
            description= "CDK deploy secret from Edwin",
            generate_secret_string=secrets.SecretStringGenerator(
                    secret_string_template=json.dumps({"username": "Edwin12"}),
                    generate_string_key="password",
                    exclude_characters="/@\"",
                    exclude_lowercase=True,
                    exclude_punctuation=True,
                    exclude_numbers=True
                )
        )
        
        secreto_paula =secrets.Secret(
            self,
            id= "secreto de Paula",
            description= "CDK deploy secret from Paula",
            generate_secret_string=secrets.SecretStringGenerator(
                    secret_string_template=json.dumps({"username": "Paula12"}),
                    generate_string_key="password",
                    exclude_characters="/@\""
                )
        )
        
        variable = secreto_paula.secret_name
        secreto = secreto_paula.secret_value
        print(variable)
        print(secreto)
        
                  
app = App()
EC2InstanceStack(app, "ec2-instance")
CursoAwsExample(app, "ejemplo-vpc-ec2")
REST_API(app, "mi-primera-api")
Cloudfront(app, "cloudfront")
Waf(app, "waf")
Environment_Variables (app, "env-var")


app.synth()