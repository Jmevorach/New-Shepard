#!/usr/bin/env python3

#  ______   __                                                      __  __
# /      \ |  \                                                    |  \|  \
#|  $$$$$$\| $$____    ______    ______    ______    ______    ____| $$| $$
#| $$___\$$| $$    \  /      \  /      \  |      \  /      \  /      $$| $$
# \$$    \ | $$$$$$$\|  $$$$$$\|  $$$$$$\  \$$$$$$\|  $$$$$$\|  $$$$$$$| $$
# _\$$$$$$\| $$  | $$| $$    $$| $$  | $$ /      $$| $$   \$$| $$  | $$ \$$
#|  \__f| $$| $$  | $$| $$$$$$$$| $$__/ $$|  $$$$$$$| $$      | $$__| $$ __
# \$$    $$| $$  | $$ \$$     \| $$    $$ \$$    $$| $$       \$$    $$|  \
#  \$$$$$$  \$$   \$$  \$$$$$$$| $$$$$$$   \$$$$$$$ \$$        \$$$$$$$ \$$
#                              | $$
#                              | $$
#                               \$$

#Now with more CDK!!! By Jacob Mevorach -- 2023

from constructs import Construct
from aws_cdk import App, Stack, Environment, CfnOutput, RemovalPolicy, PhysicalName, Tags, Tag
from aws_cdk import (
    aws_ec2 as ec2,
    aws_s3 as s3,
    aws_efs as efs,
    aws_iam as iam,
    aws_sqs as sqs,
    aws_lambda as _lambda,
    aws_ecr as ecr,
    aws_secretsmanager as secretsmanager,
    aws_fsx as fsx,
    aws_dynamodb as dynamodb,
    aws_lambda_event_sources,
    aws_batch as batch
)
import os

class ShepardStack(Stack):
    def __init__(self, scope: Construct, id: str, **kwargs) -> None:
        super().__init__(scope, id, **kwargs)

        #################################VPC SETUP STARTS HERE#################################
        #Create a new VPC for our worker subnets if requested
        if (self.node.try_get_context("CreateNewVPC") == "True"):
            shepard_vpc = ec2.Vpc(
                self, "VPC",
                # We are choosing to spread our VPC across 3 availability zones
                max_azs=3,
                cidr=self.node.try_get_context("VPCCidr"),
                subnet_configuration=[
                    # 3 x Public Subnets (1 per AZ) with 16 IPs each for our NATs (by default it's a /28).
                    ec2.SubnetConfiguration(
                        subnet_type=ec2.SubnetType.PUBLIC,
                        name="Public",
                        cidr_mask=self.node.try_get_context("VPCCidrMaskPublic")
                    ),
                    # 3 x Private Subnets (1 per AZ) with 256 IPs each for our Shepard workers (by default it's a /24).
                    ec2.SubnetConfiguration(
                        subnet_type=ec2.SubnetType.PRIVATE_WITH_NAT,
                        name="Private",
                        cidr_mask=self.node.try_get_context("VPCCidrMaskPrivate")
                    )
                ]
            )
            shepard_vpc_cidr = self.node.try_get_context("VPCCidr")

            # attach tags if requested to new infrastructure
            if self.node.try_get_context("ResourceTags"):
                for key, value in self.node.try_get_context("ResourceTags").items():
                    Tags.of(shepard_vpc).add(key, value)
        else:
            shepard_vpc = self.node.try_get_context("ExistingVPC")
            shepard_vpc_cidr = self.node.try_get_context("ExistingVPCCidr")


        #################################VPC SETUP ENDS HERE#################################

        #################################ECR REPO SETUP STARTS HERE#################################
        #create ECR repo
        if self.node.try_get_context("ECRRepoName"):
            ecr_repo = ecr.Repository(
                "ShepardECRRepo",
                encryption=ecr.RepositoryEncryption.KMS,
                repository_name=self.node.try_get_context("ECRRepoName"),
                removal_policy=RemovalPolicy.DESTROY
            )
        else:
            ecr_repo = ecr.Repository(
                "ShepardECRRepo",
                encryption=ecr.RepositoryEncryption.KMS,
                removal_policy=RemovalPolicy.DESTROY
            )

        # attach tags if requested to new infrastructure
        if self.node.try_get_context("ResourceTags"):
            for key, value in self.node.try_get_context("ResourceTags").items():
                Tags.of(ecr_repo).add(key, value)
        #################################ECR REPO SETUP ENDS HERE#################################

        #################################SECRETS MANAGER SETUP STARTS HERE#################################
        if self.node.try_get_context("SecretsManagerName"):
            secret_store = secretsmanager.Secret(
                "ShepardSecretManagerStore",
                secret_name=self.node.try_get_context("SecretsManagerName"),
            )
        else:
            secret_store = secretsmanager.Secret(
                "ShepardSecretManagerStore"
            )

        # attach tags if requested to new infrastructure
        if self.node.try_get_context("ResourceTags"):
            for key, value in self.node.try_get_context("ResourceTags").items():
                Tags.of(secret_store).add(key, value)
        #################################SECRETS MANAGER SETUP ENDS HERE#################################

        #################################EFS SETUP STARTS HERE#################################
        #create EFS system if requested
        if self.node.try_get_context("CreateEFS") == 'True':
            #Create EFS security group
            efs_security_group = ec2.SecurityGroup(
                "EFSMountTargetSecurityGroup",
                vpc=shepard_vpc,
                allow_all_outbound=True,
                description='Shepard EFS Security Group'
            )
            efs_security_group.add_ingress_rule(
                ec2.Peer.ipv4(shepard_vpc_cidr),
                ec2.Port.tcp(2049),
                'EFS port ingress'
            )

            #Create EFS file system
            if self.node.try_get_context("EFSThroughput"):
                #EFSthroughput is set to a value
                if self.node.try_get_context("EFSName"):
                    system_efs = efs.FileSystem(self, "ProjectEFSSystem",
                                                vpc=shepard_vpc,
                                                file_system_name=self.node.try_get_context("EFSName"),
                                                lifecycle_policy=efs.LifecyclePolicy.AFTER_14_DAYS,
                                                performance_mode=efs.PerformanceMode.maxIO,
                                                provisioned_throughput_per_second=self.node.try_get_context(
                                                    "EFSThroughput"),
                                                throughput_mode=efs.ThroughputMode.PROVISIONED,
                                                out_of_infrequent_access_policy=efs.OutOfInfrequentAccessPolicy.AFTER_1_ACCESS,
                                                security_group=efs_security_group,
                                                removal_policy=RemovalPolicy.DESTROY
                                                )
                else:
                    system_efs = efs.FileSystem(self, "ProjectEFSSystem",
                            vpc=shepard_vpc,
                            lifecycle_policy=efs.LifecyclePolicy.AFTER_14_DAYS,
                            performance_mode=efs.PerformanceMode.maxIO,
                            provisioned_throughput_per_second= self.node.try_get_context("EFSThroughput"),
                            throughput_mode=efs.ThroughputMode.PROVISIONED,
                            out_of_infrequent_access_policy=efs.OutOfInfrequentAccessPolicy.AFTER_1_ACCESS,
                            security_group=efs_security_group,
                            removal_policy=RemovalPolicy.DESTROY
                        )
            else:
                if self.node.try_get_context("EFSName"):
                    system_efs = efs.FileSystem(self, "ProjectEFSSystem",
                            vpc=shepard_vpc,
                            file_system_name=self.node.try_get_context("EFSName"),
                            lifecycle_policy=efs.LifecyclePolicy.AFTER_14_DAYS,
                            performance_mode=efs.PerformanceMode.maxIO,
                            out_of_infrequent_access_policy=efs.OutOfInfrequentAccessPolicy.AFTER_1_ACCESS,
                            security_group=efs_security_group,
                            removal_policy=RemovalPolicy.DESTROY
                        )
                else:
                    system_efs = efs.FileSystem(self, "ProjectEFSSystem",
                            vpc=shepard_vpc,
                            lifecycle_policy=efs.LifecyclePolicy.AFTER_14_DAYS,
                            performance_mode=efs.PerformanceMode.maxIO,
                            out_of_infrequent_access_policy=efs.OutOfInfrequentAccessPolicy.AFTER_1_ACCESS,
                            security_group=efs_security_group,
                            removal_policy=RemovalPolicy.DESTROY
                        )

            # attach tags if requested to new infrastructure
            if self.node.try_get_context("ResourceTags"):
                for key, value in self.node.try_get_context("ResourceTags").items():
                    Tags.of(system_efs).add(key, value)
                    Tags.of(efs_security_group).add(key, value)
        else:
            pass
        #################################EFS SETUP ENDS HERE#################################

        #################################LUSTRE SETUP STARTS HERE#################################
        #create Lustre file system if requested
        if self.node.try_get_context("CreateLustre") == 'True':
            #Create EFS security group
            lustre_security_group = ec2.SecurityGroup(
                "LustreSecurityGroup",
                vpc=shepard_vpc,
                allow_all_outbound=True,
                description='Shepard EFS Security Group'
            )
            lustre_security_group.add_ingress_rule(
                ec2.Peer.ipv4(shepard_vpc_cidr),
                ec2.Port.tcp(988),
                'Lustre port ingress on port 988'
            )
            lustre_security_group.add_ingress_rule(
                ec2.Peer.ipv4(shepard_vpc_cidr),
                ec2.Port.tcp(1021),
                'Lustre port ingress on port 1021'
            )
            lustre_security_group.add_ingress_rule(
                ec2.Peer.ipv4(shepard_vpc_cidr),
                ec2.Port.tcp(1022),
                'Lustre port ingress on port 1022'
            )
            lustre_security_group.add_ingress_rule(
                ec2.Peer.ipv4(shepard_vpc_cidr),
                ec2.Port.tcp(1023),
                'Lustre port ingress on port 1023'
            )

            # attach tags if requested to new infrastructure
            if self.node.try_get_context("ResourceTags"):
                for key, value in self.node.try_get_context("ResourceTags").items():
                    Tags.of(lustre_security_group).add(key, value)

            #Create lustre S3 bucket if an existing lustre bucket is not specified
            if not self.node.try_get_context("ExistingLustreBucket"):
                if self.node.try_get_context("LustreBucketName"):
                    lustre_bucket = s3.Bucket(self, "ShepardLustreBucket",
                                              access_control=s3.BucketAccessControl.PRIVATE,
                                              block_public_access=s3.BlockPublicAccess.BLOCK_ALL,
                                              bucket_name=self.node.try_get_context("LustreBucketName"),
                                              encryption=s3.BucketEncryption.S3_MANAGED,
                                              intelligent_tiering_configurations=[s3.IntelligentTieringConfiguration(
                                                  name="IntelligentTieringConfiguration")],
                                              removal_policy=RemovalPolicy.DESTROY,
                                              auto_delete_objects=True
                                              )
                else:
                    lustre_bucket = s3.Bucket(self, "ShepardLustreBucket",
                                              access_control=s3.BucketAccessControl.PRIVATE,
                                              block_public_access=s3.BlockPublicAccess.BLOCK_ALL,
                                              bucket_name=PhysicalName.GENERATE_IF_NEEDED,
                                              encryption=s3.BucketEncryption.S3_MANAGED,
                                              intelligent_tiering_configurations=[s3.IntelligentTieringConfiguration(
                                                  name="IntelligentTieringConfiguration")],
                                              removal_policy=RemovalPolicy.DESTROY,
                                              auto_delete_objects=True
                                              )

                #Create Lustre file system configuration
                lustre_configuration = fsx.LustreConfiguration(
                    deployment_type=fsx.LustreDeploymentType.SCRATCH_2,
                    export_path="s3://" + lustre_bucket.bucket_name,
                    import_path="s3://" + lustre_bucket.bucket_name,
                )

                # attach tags if requested to new infrastructure
                if self.node.try_get_context("ResourceTags"):
                    for key, value in self.node.try_get_context("ResourceTags").items():
                        Tags.of(lustre_bucket).add(key, value)
            else:
                #Create Lustre file system configuration
                lustre_configuration = fsx.LustreConfiguration(
                    deployment_type=fsx.LustreDeploymentType.SCRATCH_2,
                    export_path="s3://" + self.node.try_get_context("ExistingLustreBucket"),
                    import_path="s3://" + self.node.try_get_context("ExistingLustreBucket"),
                )

            #create file system
            if self.node.try_get_context("CreateNewVPC") == 'False':
                system_lustre_file_system = fsx.LustreFileSystem(self, "ProjectEFSSystem",
                                            vpc=shepard_vpc,
                                            lustre_configuration=lustre_configuration,
                                            storage_capacity_gi_b=self.node.try_get_context("LustreStorageCapacity"),
                                            security_group=lustre_security_group,
                                            vpc_subnet=self.node.try_get_context("ExistingSubnetID1"),
                                            removal_policy=RemovalPolicy.DESTROY
                                            )
            else:
                system_lustre_file_system = fsx.LustreFileSystem(self, "ProjectEFSSystem",
                                            vpc=shepard_vpc,
                                            lustre_configuration=lustre_configuration,
                                            storage_capacity_gi_b=self.node.try_get_context("LustreStorageCapacity"),
                                            security_group=lustre_security_group,
                                            vpc_subnet=shepard_vpc.private_subnets[0],
                                            removal_policy=RemovalPolicy.DESTROY
                                            )

            # attach tags if requested to new infrastructure
            if self.node.try_get_context("ResourceTags"):
                for key, value in self.node.try_get_context("ResourceTags").items():
                    Tags.of(system_lustre_file_system).add(key, value)
        else:
            pass
        #################################LUSTRE SETUP ENDS HERE#################################

        #################################DYNAMODB SETUP STARTS HERE#################################
        if self.node.try_get_context("TableName"):
            table = dynamodb.Table(self, "ShepardDynamoDB",
                                   partition_key=dynamodb.Attribute(name="UUID", type=dynamodb.AttributeType.STRING),
                                   billing_mode=dynamodb.BillingMode.PAY_PER_REQUEST,
                                   encryption=dynamodb.TableEncryption.AWS_MANAGED,
                                   time_to_live_attribute='END_TIME',
                                   table_name=self.node.try_get_context("TableName")
                                   )
        else:
            table = dynamodb.Table(self, "ShepardDynamoDB",
                                   partition_key=dynamodb.Attribute(name="UUID", type=dynamodb.AttributeType.STRING),
                                   billing_mode=dynamodb.BillingMode.PAY_PER_REQUEST,
                                   encryption=dynamodb.TableEncryption.AWS_MANAGED,
                                   time_to_live_attribute='END_TIME'
                                   )

        # attach tags if requested to new infrastructure
        if self.node.try_get_context("ResourceTags"):
            for key, value in self.node.try_get_context("ResourceTags").items():
                Tags.of(table).add(key, value)
        #################################DYNAMODB SETUP ENDS HERE#################################

        #################################INITIAL S3 BUCKET SETUP STARTS HERE#################################
        # Inputs bucket
        if self.node.try_get_context("InputsBucket"):
            inputs_bucket = s3.Bucket(self, "ShepardInputsBucket",
                    access_control=s3.BucketAccessControl.PRIVATE,
                    block_public_access=s3.BlockPublicAccess.BLOCK_ALL,
                    bucket_name=self.node.try_get_context("InputsBucket"),
                    encryption=s3.BucketEncryption.S3_MANAGED,
                    intelligent_tiering_configurations=[s3.IntelligentTieringConfiguration(name="IntelligentTieringConfiguration")],
                    removal_policy=RemovalPolicy.DESTROY,
                    auto_delete_objects=True
                    )
        else:
            inputs_bucket = s3.Bucket(self, "ShepardInputsBucket",
                    access_control=s3.BucketAccessControl.PRIVATE,
                    block_public_access=s3.BlockPublicAccess.BLOCK_ALL,
                    bucket_name=PhysicalName.GENERATE_IF_NEEDED,
                    encryption=s3.BucketEncryption.S3_MANAGED,
                    intelligent_tiering_configurations=[s3.IntelligentTieringConfiguration(name="IntelligentTieringConfiguration")],
                    removal_policy=RemovalPolicy.DESTROY,
                    auto_delete_objects=True
                    )

        # Quick deploy bucket
        if self.node.try_get_context("QuickDeployBucket"):
            quick_deploy_bucket = s3.Bucket(self, "ShepardQuickDeployBucket",
                                            access_control=s3.BucketAccessControl.PRIVATE,
                                            block_public_access=s3.BlockPublicAccess.BLOCK_ALL,
                                            bucket_name=self.node.try_get_context("QuickDeployBucket"),
                                            encryption=s3.BucketEncryption.S3_MANAGED,
                                            intelligent_tiering_configurations=[s3.IntelligentTieringConfiguration(
                                                name="IntelligentTieringConfiguration")],
                                            removal_policy=RemovalPolicy.DESTROY,
                                            auto_delete_objects=True
                                            )
        else:
            quick_deploy_bucket = s3.Bucket(self, "ShepardQuickDeployBucket",
                                            access_control=s3.BucketAccessControl.PRIVATE,
                                            block_public_access=s3.BlockPublicAccess.BLOCK_ALL,
                                            bucket_name=PhysicalName.GENERATE_IF_NEEDED,
                                            encryption=s3.BucketEncryption.S3_MANAGED,
                                            intelligent_tiering_configurations=[s3.IntelligentTieringConfiguration(
                                                name="IntelligentTieringConfiguration")],
                                            removal_policy=RemovalPolicy.DESTROY,
                                            auto_delete_objects=True
                                            )

        # Output bucket
        if self.node.try_get_context("OutputsBucket"):
            outputs_bucket = s3.Bucket(self, "ShepardOutputsBucket",
                                       access_control=s3.BucketAccessControl.PRIVATE,
                                       block_public_access=s3.BlockPublicAccess.BLOCK_ALL,
                                       bucket_name=self.node.try_get_context("OutputsBucket"),
                                       encryption=s3.BucketEncryption.S3_MANAGED,
                                       intelligent_tiering_configurations=[
                                           s3.IntelligentTieringConfiguration(name="IntelligentTieringConfiguration")],
                                       removal_policy=RemovalPolicy.DESTROY,
                                       auto_delete_objects=True
                                       )
        else:
            outputs_bucket = s3.Bucket(self, "ShepardOutputsBucket",
                                       access_control=s3.BucketAccessControl.PRIVATE,
                                       block_public_access=s3.BlockPublicAccess.BLOCK_ALL,
                                       bucket_name=PhysicalName.GENERATE_IF_NEEDED,
                                       encryption=s3.BucketEncryption.S3_MANAGED,
                                       intelligent_tiering_configurations=[
                                           s3.IntelligentTieringConfiguration(name="IntelligentTieringConfiguration")],
                                       removal_policy=RemovalPolicy.DESTROY,
                                       auto_delete_objects=True
                                       )

        # attach tags if requested to new infrastructure
        if self.node.try_get_context("ResourceTags"):
            for key, value in self.node.try_get_context("ResourceTags").items():
                Tags.of(inputs_bucket).add(key, value)
                Tags.of(quick_deploy_bucket).add(key, value)
                Tags.of(outputs_bucket).add(key, value)
        #################################INITIAL S3 BUCKET SETUP ENDS HERE#################################

        #################################BATCH SETUP STARTS HERE#################################

        #create ecs instance role
        ecs_instance_role = iam.Role(self,
            'EcsInstanceRole',
            assumed_by=iam.CompositePrincipal(
                iam.ServicePrincipal('ec2.amazonaws.com')
            ),
            managed_policies=[
                iam.ManagedPolicy.from_aws_managed_policy_name("service-role/AmazonEC2ContainerServiceforEC2Role"),
            ])

        #create spot fleet role role
        spot_fleet_role = iam.Role(self,
            'BatchSpotFleetRole',
            assumed_by=iam.CompositePrincipal(
                iam.ServicePrincipal('spotfleet.amazonaws.com')
            ),
            managed_policies=[
                iam.ManagedPolicy.from_aws_managed_policy_name("service-role/AmazonEC2SpotFleetTaggingRole"),
            ])

        #create container runtime role
        if self.node.try_get_context("ExtraIAMPolicyForContainerRole"):
            container_runtime_role = iam.Role(self,
                'ContainerRuntimeRole',
                assumed_by=iam.CompositePrincipal(
                    iam.ServicePrincipal('ec2.amazonaws.com'),
                    iam.ServicePrincipal('ecs.amazonaws.com'),
                    iam.ServicePrincipal('ecs-tasks.amazonaws.com')
                ),
                managed_policies=[
                    iam.ManagedPolicy.from_managed_policy_arn(self.node.try_get_context("ExtraIAMPolicyForContainerRole")),
                ])
        else:
            container_runtime_role = iam.Role(self,
                'ContainerRuntimeRole',
                assumed_by=iam.CompositePrincipal(
                    iam.ServicePrincipal('ec2.amazonaws.com'),
                    iam.ServicePrincipal('ecs.amazonaws.com'),
                    iam.ServicePrincipal('ecs-tasks.amazonaws.com')
                ))

        # attach tags if requested to new infrastructure
        if self.node.try_get_context("ResourceTags"):
            for key, value in self.node.try_get_context("ResourceTags").items():
                Tags.of(ecs_instance_role).add(key, value)
                Tags.of(spot_fleet_role).add(key, value)
                Tags.of(container_runtime_role).add(key, value)

        #initialize compute resources
        compute_resources = compute_resources = batch.ComputeResources(
            vpc=shepard_vpc,
            apply_removal_policy=RemovalPolicy.DESTROY
         )

        #toggle between spot and not spot for batch workloads
        if self.node.try_get_context("SpotBidPricePercent"):

            # set bid percentage if specified
            setattr(compute_resources, "bid_percentage", self.node.try_get_context("SpotBidPricePercent"))

            # set compute resource type to spot
            setattr(compute_resources, "type", batch.ComputeResourceType.SPOT)

            #toggle allocation strategy if requested
            if self.node.try_get_context("ToggleAllocationStrategy") == 'True':
                setattr(compute_resources, "allocation_strategy", batch.AllocationStrategy.BEST_FIT_PROGRESSIVE)
            else:
                setattr(compute_resources, "allocation_strategy", batch.AllocationStrategy.BEST_FIT)

        else:

            #toggle allocation strategy if requested
            if self.node.try_get_context("ToggleAllocationStrategy") == 'True':
                setattr(compute_resources, "allocation_strategy", batch.AllocationStrategy.SPOT_CAPACITY_OPTIMIZED)
            else:
                setattr(compute_resources, "allocation_strategy", batch.AllocationStrategy.BEST_FIT)

        #append specific user specified subnets to list if requested
        specific_subnets_to_launch_jobs_in = []
        if self.node.try_get_context("ExistingSubnetID1"):
            specific_subnets_to_launch_jobs_in.append(
                ec2.Subnet.from_subnet_id(
                    scope=self,
                    id=f"subnet1",
                    subnet_id=self.node.try_get_context("ExistingSubnetID1")
                )
            )

        if self.node.try_get_context("ExistingSubnetID2"):
            specific_subnets_to_launch_jobs_in.append(
                ec2.Subnet.from_subnet_id(
                    scope=self,
                    id=f"subnet2",
                    subnet_id=self.node.try_get_context("ExistingSubnetID2")
                )
            )

        if self.node.try_get_context("ExistingSubnetID3"):
            specific_subnets_to_launch_jobs_in.append(
                ec2.Subnet.from_subnet_id(
                    scope=self,
                    id=f"subnet3",
                    subnet_id=self.node.try_get_context("ExistingSubnetID3")
                )
            )

        #append vpc subnets if requested
        if specific_subnets_to_launch_jobs_in:
            setattr(compute_resources, "vpc_subnets", ec2.SubnetSelection(subnets=specific_subnets_to_launch_jobs_in))

        #set instance types if requested
        if self.node.try_get_context("InstanceTypes"):

            #take out all whitespace and then split along comma to get list
            instance_types_as_list = ''.join(self.node.try_get_context("InstanceTypes").split()).split(",")

            #turn into list of instance types
            instance_types_list = []
            for instance_type in instance_types_as_list:
                instance_types_list.append(ec2.InstanceType(instance_type))

            #set value
            setattr(compute_resources, "instance_types", instance_types_list)

        #set ec2_key_pair if requested
        if self.node.try_get_context("Ec2KeyPair"):
            setattr(compute_resources, "ec2_key_pair", self.node.try_get_context("Ec2KeyPair"))

        #set compute_resource_tags for name

        #set desired and maximum vcpu
        if self.node.try_get_context("MaxCPU"):
            setattr(compute_resources, "maxv_cpus", self.node.try_get_context("MaxCPU"))

        if self.node.try_get_context("DefaultCapacity"):
            setattr(compute_resources, "DefaultCapacity", self.node.try_get_context("DefaultCapacity"))

        #create and set spot fleet role if requested
        if self.node.try_get_context("SpotBidPricePercent"):
            setattr(compute_resources, "spot_fleet_role", spot_fleet_role.role_arn)

        #set instance role
        setattr(compute_resources, "instance_role", ecs_instance_role)

        #create security group for batch instances
        batch_security_group = ec2.SecurityGroup(self, "BatchSecGroup",
                                       description="Security group for Shepard instances.",
                                       allow_all_outbound=True,
                                       vpc=shepard_vpc
                                       )

        #add SSH access to extra CIDR if requested
        if self.node.try_get_context("CIDRToAllowSSHAccessTo"):
            batch_security_group.add_ingress_rule(self.node.try_get_context("CIDRToAllowSSHAccessTo"), ec2.Port.tcp(22))
            batch_security_group.add_ingress_rule(shepard_vpc_cidr, ec2.Port.tcp(22))
            batch_security_group.add_ingress_rule(shepard_vpc_cidr, ec2.Port.tcp(988))
            batch_security_group.add_ingress_rule(shepard_vpc_cidr, ec2.Port.tcp(1021))
            batch_security_group.add_ingress_rule(shepard_vpc_cidr, ec2.Port.tcp(1022))
            batch_security_group.add_ingress_rule(shepard_vpc_cidr, ec2.Port.tcp(1023))
        else:
            batch_security_group.add_ingress_rule(shepard_vpc_cidr, ec2.Port.tcp(22))
            batch_security_group.add_ingress_rule(shepard_vpc_cidr, ec2.Port.tcp(988))
            batch_security_group.add_ingress_rule(shepard_vpc_cidr, ec2.Port.tcp(1021))
            batch_security_group.add_ingress_rule(shepard_vpc_cidr, ec2.Port.tcp(1022))
            batch_security_group.add_ingress_rule(shepard_vpc_cidr, ec2.Port.tcp(1023))

        #set security groups property
        security_groups = []
        security_groups.append(batch_security_group)
        setattr(compute_resources, "security_groups", security_groups)

        # make launch template

        # initialize setup commands
        setup_commands = ec2.UserData.for_linux()

        #make root directory
        setup_commands.add_commands("mkdir -p /mnt/root")

        #mount efs
        if self.node.try_get_context("CreateEFS") == 'True':
            setup_commands.add_commands("mkdir -p /mnt/efs")
            setup_commands.add_commands('echo "'+system_efs.file_system_id+':/ /mnt/efs efs tls,_netdev" >> /etc/fstab')
            setup_commands.add_commands('mount -a -t efs defaults')

        #mount lustre
        if self.node.try_get_context("CreateLustre") == 'True':
            setup_commands.add_commands('mkdir -p /mnt/fsx')
            setup_commands.add_commands('echo "'+system_lustre_file_system.file_system_id+'.fsx.'+self.region+'.amazonaws.com@tcp:/'+system_lustre_file_system.mount_name+' /mnt/fsx lustre defaults,noatime,_netdev 0 0" >> /etc/fstab')
            setup_commands.add_commands('mount -a -t lustre defaults')

        #remove limits
        setup_commands.add_commands('echo "* soft sigpending -1" >> /etc/security/limits.conf')
        setup_commands.add_commands('echo "* hard sigpending -1" >> /etc/security/limits.conf')
        setup_commands.add_commands('echo "* soft memlock -1" >> /etc/security/limits.conf')
        setup_commands.add_commands('echo "* hard memlock -1" >> /etc/security/limits.conf')
        setup_commands.add_commands('echo "* soft msgqueue -1" >> /etc/security/limits.conf')
        setup_commands.add_commands('echo "* hard msgqueue -1" >> /etc/security/limits.conf')

        #set nofiles maximum to user specified value
        setup_commands.add_commands('echo "* soft nofile '+\
                                    str(self.node.try_get_context("UlimitsNoFilesOpen"))+'" >> /etc/security/limits.conf')
        setup_commands.add_commands('echo "* hard nofile '+\
                                    str(self.node.try_get_context("UlimitsNoFilesOpen"))+'" >> /etc/security/limits.conf')
        setup_commands.add_commands('sed -i '+"'s/OPTIONS="+\
                                    '"--default-ulimit nofile=1024:4096"/OPTIONS="--default-ulimit nofile='+\
                                    str(self.node.try_get_context("UlimitsNoFilesOpen"))+':'+\
                                    str(self.node.try_get_context("UlimitsNoFilesOpen"))+'"/g'+\
                                    "'"+' /etc/sysconfig/docker')

        #initialize multipart user data object
        multipart_user_data = ec2.MultipartUserData()

        #change storage size for docker image if an alternate size docker image storage volume is specified by the user
        if self.node.try_get_context("SizeOfContainerStorageDisk"):
            boot_hook_conf = ec2.UserData.for_linux()
            boot_hook_conf.add_commands("cloud-init-per once docker_options echo '"+\
                                        'OPTIONS="${OPTIONS} --storage-opt dm.basesize='+\
                                        'G'+'"'+"'"+ ' >> /etc/sysconfig/docker')
            # The docker has to be configured at early stage, so content type is overridden to boothook
            multipart_user_data.add_part(
                ec2.MultipartBody.from_user_data(boot_hook_conf, 'text/cloud-boothook; charset="us-ascii"')
            )

        # Add the rest of setup
        multipart_user_data.add_part(ec2.MultipartBody.from_user_data(setup_commands))

        #configure block devices

        #initialize block device mappings
        block_device_mappings = []

        #configure mapping for container storage disk if requested. this ebs volume stores the docker containers that
        #are being run. If you'd like to run a really large container you should adjust this value.
        if self.node.try_get_context("SizeOfContainerStorageDisk"):
            block_device_mappings.append(
                ec2.BlockDevice(
                    device_name="/dev/xvda",
                    volume=ec2.BlockDeviceVolume.ebs(volume_size=int(self.node.try_get_context("SizeOfContainerStorageDisk")),
                                                     encrypted=True,
                                                     delete_on_termination=True,
                                                     volume_type=ec2.EbsDeviceVolumeType.GP2),
                )
            )

        #configure mapping for root storage disk if requested. this ebs volume supports the root file system for the
        #instance that runs jobs. If you'd like a really large root file system you shouuld adjust this value.
        if self.node.try_get_context("SizeOfRootDisk"):
            block_device_mappings.append(
                ec2.BlockDevice(
                    device_name="/dev/xvdcz",
                    volume=ec2.BlockDeviceVolume.ebs(volume_size=int(self.node.try_get_context("SizeOfRootDisk")),
                                                     encrypted=True,
                                                     delete_on_termination=True,
                                                     volume_type=ec2.EbsDeviceVolumeType.GP2),
                )
            )

        #create launch template

        #configure block device mappings if requested
        if block_device_mappings:

            #configure launch template name if requested
            if self.node.try_get_context("LaunchTemplateName"):
                shepard_launch_template = ec2.LaunchTemplate(self, "ShepardLaunchTemplate",
                                   user_data=multipart_user_data,
                                   block_devices=block_device_mappings,
                                   launch_template_name=self.node.try_get_context("LaunchTemplateName")
                                   )
            else:
                shepard_launch_template = ec2.LaunchTemplate(self, "ShepardLaunchTemplate",
                                   user_data=multipart_user_data,
                                   block_devices=block_device_mappings
                                   )
        else:

            # configure launch template name if requested
            if self.node.try_get_context("LaunchTemplateName"):
                shepard_launch_template = ec2.LaunchTemplate(self, "ShepardLaunchTemplate",
                                   user_data=multipart_user_data,
                                   launch_template_name=self.node.try_get_context("LaunchTemplateName")
                                   )
            else:
                shepard_launch_template = ec2.LaunchTemplate(self, "ShepardLaunchTemplate",
                                   user_data=multipart_user_data,
                                   )

        #set launch template specification
        setattr(compute_resources, "launch_template", batch.LaunchTemplateSpecification(
            launch_template_name=shepard_launch_template.launch_template_name
        ))

        if self.node.try_get_context("ComputeEnvironmentName"):
            batch_compute_environment = batch.ComputeEnvironment(self, "BatchCompute",
                                                                compute_resources=compute_resources,
                                                                compute_environment_name=self.node.try_get_context("ComputeEnvironmentName")
                                                               )
        else:
            batch_compute_environment = batch.ComputeEnvironment(self, "BatchCompute",
                                                                compute_resources=compute_resources
                                                               )

        #define batch job definition
        if self.node.try_get_context("JobDefinitionName"):
            batch_job_definition = batch.JobDefinition(self,
                "BatchJobDefinition",
                job_definition_name=self.node.try_get_context("JobDefinitionName"),
                container=batch.JobDefinitionContainer(
                    job_role_arn=container_runtime_role.role_arn,
                    image=ecr_repo.repository_uri+':latest',
                    vcpus=self.node.try_get_context("DesiredCPU"),
                    memory=self.node.try_get_context("DesiredRam"),
                    privileged=True,
                    ulimits=[batch.CfnJobDefinition.UlimitProperty(
                        hard_limit=self.node.try_get_context("UlimitsNoFilesOpen"),
                        name="nofile",
                        soft_limit=self.node.try_get_context("UlimitsNoFilesOpen")
                    )]),
                    mount_points=[
                        batch.CfnJobDefinition.MountPointsProperty(
                            container_path="/mnt/root",
                            read_only=False,
                            source_volume="root"
                        ),
                        batch.CfnJobDefinition.MountPointsProperty(
                            container_path="/mnt/fsx",
                            read_only=False,
                            source_volume="fsx"
                        ),
                        batch.CfnJobDefinition.MountPointsProperty(
                            container_path="/mnt/efs",
                            read_only=False,
                            source_volume="efs"
                        ),
                        batch.CfnJobDefinition.MountPointsProperty(
                            container_path="/var/run/docker.sock",
                            read_only=False,
                            source_volume="docker"
                        )
                    ],
                    volumes=[
                        batch.CfnJobDefinition.VolumesProperty(
                           host=batch.CfnJobDefinition.VolumesHostProperty(
                               source_path="/mnt/root"
                           ),
                           name="root"
                        ),
                        batch.CfnJobDefinition.VolumesProperty(
                            host=batch.CfnJobDefinition.VolumesHostProperty(
                                source_path="/mnt/fsx"
                            ),
                            name="fsx"
                        ),
                        batch.CfnJobDefinition.VolumesProperty(
                            host=batch.CfnJobDefinition.VolumesHostProperty(
                                source_path="/mnt/efs"
                            ),
                            name="efs"
                        ),
                        batch.CfnJobDefinition.VolumesProperty(
                            host=batch.CfnJobDefinition.VolumesHostProperty(
                                source_path="/var/run/docker.sock"
                            ),
                            name="docker"
                        )
                    ],
                    environment=[
                        batch.CfnJobDefinition.EnvironmentProperty(
                        name="role_arn",
                        value=container_runtime_role.role_arn
                        ),
                        batch.CfnJobDefinition.EnvironmentProperty(
                            name="role_session_name",
                            value="access_session"
                        ),
                        batch.CfnJobDefinition.EnvironmentProperty(
                            name="SECRET_STORE",
                            value=secret_store.secret_arn
                        ),
                        batch.CfnJobDefinition.EnvironmentProperty(
                            name="USES_EFS",
                            value=self.node.try_get_context("CreateEFS")
                        ),
                        batch.CfnJobDefinition.EnvironmentProperty(
                            name="USES_LUSTRE",
                            value=self.node.try_get_context("CreateLustre")
                        ),
                        batch.CfnJobDefinition.EnvironmentProperty(
                            name="region",
                            value=self.region
                        ),
                        batch.CfnJobDefinition.EnvironmentProperty(
                            name="outputs_bucket",
                            value=outputs_bucket.bucket_name
                        ),
                        batch.CfnJobDefinition.EnvironmentProperty(
                            name="quick_deploy_bucket",
                            value=quick_deploy_bucket.bucket_name
                        ),
                        batch.CfnJobDefinition.EnvironmentProperty(
                            name="inputs_bucket",
                            value=inputs_bucket.bucket_name
                        ),
                        batch.CfnJobDefinition.EnvironmentProperty(
                            name="table_name",
                            value=table.table_name
                        ),
                        batch.CfnJobDefinition.EnvironmentProperty(
                            name="ULIMIT_FILENO",
                            value=str(self.node.try_get_context("UlimitsNoFilesOpen"))
                        ),
                        batch.CfnJobDefinition.EnvironmentProperty(
                            name="ALLOW_DOCKER_ACCESS",
                            value=self.node.try_get_context("AllowJobsToAccessDockerDaemon")
                        )
                    ],
            )
        else:
            batch_job_definition = batch.JobDefinition(self,
                "BatchJobDefinition",
                container=batch.JobDefinitionContainer(
                    job_role_arn=container_runtime_role.role_arn,
                    image=ecr_repo.repository_uri+':latest',
                    vcpus=self.node.try_get_context("DesiredCPU"),
                    memory=self.node.try_get_context("DesiredRam"),
                    privileged=True,
                    ulimits=[batch.CfnJobDefinition.UlimitProperty(
                        hard_limit=self.node.try_get_context("UlimitsNoFilesOpen"),
                        name="nofile",
                        soft_limit=self.node.try_get_context("UlimitsNoFilesOpen")
                    )]),
                    mount_points=[
                        batch.CfnJobDefinition.MountPointsProperty(
                            container_path="/mnt/root",
                            read_only=False,
                            source_volume="root"
                        ),
                        batch.CfnJobDefinition.MountPointsProperty(
                            container_path="/mnt/fsx",
                            read_only=False,
                            source_volume="fsx"
                        ),
                        batch.CfnJobDefinition.MountPointsProperty(
                            container_path="/mnt/efs",
                            read_only=False,
                            source_volume="efs"
                        ),
                        batch.CfnJobDefinition.MountPointsProperty(
                            container_path="/var/run/docker.sock",
                            read_only=False,
                            source_volume="docker"
                        )
                    ],
                    volumes=[
                        batch.CfnJobDefinition.VolumesProperty(
                           host=batch.CfnJobDefinition.VolumesHostProperty(
                               source_path="/mnt/root"
                           ),
                           name="root"
                        ),
                        batch.CfnJobDefinition.VolumesProperty(
                            host=batch.CfnJobDefinition.VolumesHostProperty(
                                source_path="/mnt/fsx"
                            ),
                            name="fsx"
                        ),
                        batch.CfnJobDefinition.VolumesProperty(
                            host=batch.CfnJobDefinition.VolumesHostProperty(
                                source_path="/mnt/efs"
                            ),
                            name="efs"
                        ),
                        batch.CfnJobDefinition.VolumesProperty(
                            host=batch.CfnJobDefinition.VolumesHostProperty(
                                source_path="/var/run/docker.sock"
                            ),
                            name="docker"
                        )
                    ],
                    environment=[
                        batch.CfnJobDefinition.EnvironmentProperty(
                        name="role_arn",
                        value=container_runtime_role.role_arn
                        ),
                        batch.CfnJobDefinition.EnvironmentProperty(
                            name="role_session_name",
                            value="access_session"
                        ),
                        batch.CfnJobDefinition.EnvironmentProperty(
                            name="SECRET_STORE",
                            value=secret_store.secret_arn
                        ),
                        batch.CfnJobDefinition.EnvironmentProperty(
                            name="USES_EFS",
                            value=self.node.try_get_context("CreateEFS")
                        ),
                        batch.CfnJobDefinition.EnvironmentProperty(
                            name="USES_LUSTRE",
                            value=self.node.try_get_context("CreateLustre")
                        ),
                        batch.CfnJobDefinition.EnvironmentProperty(
                            name="region",
                            value=self.region
                        ),
                        batch.CfnJobDefinition.EnvironmentProperty(
                            name="outputs_bucket",
                            value=outputs_bucket.bucket_name
                        ),
                        batch.CfnJobDefinition.EnvironmentProperty(
                            name="quick_deploy_bucket",
                            value=quick_deploy_bucket.bucket_name
                        ),
                        batch.CfnJobDefinition.EnvironmentProperty(
                            name="inputs_bucket",
                            value=inputs_bucket.bucket_name
                        ),
                        batch.CfnJobDefinition.EnvironmentProperty(
                            name="table_name",
                            value=table.table_name
                        ),
                        batch.CfnJobDefinition.EnvironmentProperty(
                            name="ULIMIT_FILENO",
                            value=str(self.node.try_get_context("UlimitsNoFilesOpen"))
                        ),
                        batch.CfnJobDefinition.EnvironmentProperty(
                            name="ALLOW_DOCKER_ACCESS",
                            value=self.node.try_get_context("AllowJobsToAccessDockerDaemon")
                        )
                    ],
            )

        if self.node.try_get_context("RetryAttempts"):
            #set value
            setattr(batch_job_definition, "retry_attempts", self.node.try_get_context("RetryAttempts"))

        if self.node.try_get_context("QueueName"):
            job_queue = batch.JobQueue(self,
                "ShepardJobQueue",
                job_queue_name=self.node.try_get_context("QueueName"),
                priority=1000,
                state="ENABLED",
                compute_environments=[
                    batch.JobQueueComputeEnvironment(
                        compute_environment=batch_compute_environment,
                        order=1)
                ])
        else:
            job_queue = batch.JobQueue(self,
                "ShepardJobQueue",
                priority=1000,
                state="ENABLED",
                compute_environments=[
                    batch.JobQueueComputeEnvironment(
                        compute_environment=batch_compute_environment,
                        order=1)
                ])

        # attach tags if requested to new infrastructure
        if self.node.try_get_context("ResourceTags"):
            for key, value in self.node.try_get_context("ResourceTags").items():
                Tags.of(job_queue).add(key, value)
                Tags.of(batch_job_definition).add(key, value)
                Tags.of(batch_compute_environment).add(key, value)
                Tags.of(batch_security_group).add(key, value)
                Tags.of(shepard_launch_template).add(key, value)
        #################################BATCH SETUP ENDS HERE#################################

        #################################LAMBDA FOR BATCHING ENDPOINT SETUP STARTS HERE#################################
        # Defines an AWS Lambda resource
        batching_endpoint_lambda = _lambda.Function(
            self, 'HelloHandler',
            runtime=_lambda.Runtime.PYTHON_3_10,
            code=_lambda.Code.from_asset('arbitrary_job_batching_endpoint_code'),
            index='arbitrary_job_batching_endpoint_code.py',
            handler='lambda_handler',
        )
        # attach tags if requested to new infrastructure
        if self.node.try_get_context("ResourceTags"):
            for key, value in self.node.try_get_context("ResourceTags").items():
                Tags.of(batching_endpoint_lambda).add(key, value)
        #################################LAMBDA FOR BATCHING ENDPOINT SETUP ENDS HERE#################################

        #################################LAMBDA FOR JOB SCHEDULER SETUP STARTS HERE#################################
        # Defines an AWS Lambda resource
        job_scheduler_lambda = _lambda.Function(
            self, 'HelloHandler',
            runtime=_lambda.Runtime.PYTHON_3_10,
            code=_lambda.Code.from_asset('arbitrary_scheduler_code'),
            index='arbitrary_scheduler_code.py',
            handler='lambda_handler'
        )
        # attach tags if requested to new infrastructure
        if self.node.try_get_context("ResourceTags"):
            for key, value in self.node.try_get_context("ResourceTags").items():
                Tags.of(job_scheduler_lambda).add(key, value)
        #################################LAMBDA FOR JOB SCHEDULER SETUP ENDS HERE#################################

        #################################SUBSEQUENT S3 BUCKET SETUP STARTS HERE#################################
        #IAM policy and SQS notification setup

        #create SQS queue for S3 bucket events from the input S3 bucket.
        if self.node.try_get_context("SQSName"):
            shepard_receive_queue = sqs.Queue(self, "SQSShepardReceiveQueue",
                                              queue_name=self.node.try_get_context("SQSName"),
                                              retention_period=1209600,
                                              visibility_timeout=43200,
                                              encryption=sqs.QueueEncryption.KMS_MANAGED
                                              )
        else:
            shepard_receive_queue = sqs.Queue(self, "SQSShepardReceiveQueue",
                                              retention_period=1209600,
                                              visibility_timeout=43200,
                                              encryption=sqs.QueueEncryption.KMS_MANAGED
                                              )
        # create DLQ
        shepard_receive_queue_DLQ = sqs.DeadLetterQueue(self, "SQSShepardReceiveQueueDLQ",
                                                        encryption=sqs.QueueEncryption.KMS_MANAGED,
                                                        max_receive_count=1,
                                                        queue=shepard_receive_queue,
                                                        retention_period=1209600,
                                                        visibility_timeout=0,
                                                        )

        # attach tags if requested to new infrastructure
        if self.node.try_get_context("ResourceTags"):
            for key, value in self.node.try_get_context("ResourceTags").items():
                Tags.of(shepard_receive_queue).add(key, value)
                Tags.of(shepard_receive_queue_DLQ).add(key, value)

        #add event notification from s3 bucket to SQS queue
        inputs_bucket.add_event_notification(s3.EventType.OBJECT_CREATED,s3.SqsDestination(shepard_receive_queue))

        #add trigger from SQS queue to lambda
        sqs_event_source = aws_lambda_event_sources.SqsEventSource(shepard_receive_queue)
        job_scheduler_lambda.add_event_source(sqs_event_source)

        # Allow access to lambda so scheduler lambda can read inputs.txt from inputs
        result = inputs_bucket.grant_read(job_scheduler_lambda)
        #################################SUBSEQUENT S3 BUCKET SETUP ENDS HERE#################################

        #################################EXTRA PERMISSIONS FOR IAM ROLES STARTS HERE#################################
        ##Lambda batching endpoint permissions

        # add logging permissions
        batching_endpoint_lambda.add_to_role_policy(iam.PolicyStatement(
            effect=iam.Effect.ALLOW,
            policy_name='AllowLogGroupCreationAndStreaming',
            actions=[
                'logs:CreateLogGroup',
                'logs:CreateLogStream',
                'logs:PutLogEvents'
            ],
            resources=[
                'arn:aws:logs:*:*:*',
            ],
        ))

        # add input s3 bucket permissions
        batching_endpoint_lambda.add_to_role_policy(iam.PolicyStatement(
            effect=iam.Effect.ALLOW,
            policy_name='AllowS3ListBucketToInputsBucket',
            actions=[
                "s3:ListBucket"
            ],
            resources=[
                inputs_bucket.bucket_arn,
            ],
        ))
        batching_endpoint_lambda.add_to_role_policy(iam.PolicyStatement(
            effect=iam.Effect.ALLOW,
            policy_name='AllowS3GetObjectsToInputBucketObjects',
            actions=[
                "s3:GetObject",
                "s3:GetObjectVersion"
            ],
            resources=[
                inputs_bucket.bucket_arn+'/*',
            ],
        ))

        # add sqs queue permissions
        batching_endpoint_lambda.add_to_role_policy(iam.PolicyStatement(
            effect=iam.Effect.ALLOW,
            policy_name='AllowSQSReadWritePermissions',
            actions=[
                "sqs:DeleteMessage",
                "sqs:GetQueueUrl",
                "sqs:ListQueues",
                "sqs:ChangeMessageVisibility",
                "sqs:SendMessageBatch",
                "sqs:ReceiveMessage",
                "sqs:SendMessage",
                "sqs:GetQueueAttributes",
                "sqs:ListQueueTags",
                "sqs:ListDeadLetterSourceQueues",
                "sqs:DeleteMessageBatch",
                "sqs:ChangeMessageVisibilityBatch",
                "sqs:SetQueueAttributes"
            ],
            resources=[
                shepard_receive_queue.queue_arn,
            ],
        ))

        # add sqs DLQ queue permissions
        batching_endpoint_lambda.add_to_role_policy(iam.PolicyStatement(
            effect=iam.Effect.ALLOW,
            policy_name='AllowSQSDLQReadWritePermissions',
            actions=[
                "sqs:DeleteMessage",
                "sqs:GetQueueUrl",
                "sqs:ListQueues",
                "sqs:ChangeMessageVisibility",
                "sqs:SendMessageBatch",
                "sqs:ReceiveMessage",
                "sqs:SendMessage",
                "sqs:GetQueueAttributes",
                "sqs:ListQueueTags",
                "sqs:ListDeadLetterSourceQueues",
                "sqs:DeleteMessageBatch",
                "sqs:ChangeMessageVisibilityBatch",
                "sqs:SetQueueAttributes"
            ],
            resources=[
                shepard_receive_queue_DLQ.queue_arn,
            ],
        ))

        #add DynamoDB permissions
        batching_endpoint_lambda.add_to_role_policy(iam.PolicyStatement(
            effect=iam.Effect.ALLOW,
            policy_name='AllowDynamoDBReadWritePermissions',
            actions=[
                "dynamodb:BatchGet*",
                "dynamodb:DescribeStream",
                "dynamodb:DescribeTable",
                "dynamodb:Get*",
                "dynamodb:Query",
                "dynamodb:Scan",
                "dynamodb:BatchWrite*",
                "dynamodb:CreateTable",
                "dynamodb:Delete*",
                "dynamodb:Update*",
                "dynamodb:PutItem"
            ],
            resources=[
                table.table_arn,
            ],
        ))

        #add batch job queue permissions
        batching_endpoint_lambda.add_to_role_policy(iam.PolicyStatement(
            effect=iam.Effect.ALLOW,
            policy_name='BatchAllowSubmitJobPermissions',
            actions=[
                "batch:SubmitJob"
            ],
            resources=[
                job_queue.job_queue_arn,
                batch_job_definition.job_definition_arn+'/*',
                batch_job_definition.job_definition_arn

            ],
        ))

        ##Lambda scheduler permissions

        # add logging permissions
        batching_endpoint_lambda.add_to_role_policy(iam.PolicyStatement(
            effect=iam.Effect.ALLOW,
            policy_name='AllowLogGroupCreationAndStreaming',
            actions=[
                'logs:CreateLogGroup',
                'logs:CreateLogStream',
                'logs:PutLogEvents'
            ],
            resources=[
                'arn:aws:logs:*:*:*',
            ],
        ))

        # add input s3 bucket permissions
        batching_endpoint_lambda.add_to_role_policy(iam.PolicyStatement(
            effect=iam.Effect.ALLOW,
            policy_name='AllowS3ListBucketToInputsBucket',
            actions=[
                "s3:ListBucket"
            ],
            resources=[
                inputs_bucket.bucket_arn,
            ],
        ))
        batching_endpoint_lambda.add_to_role_policy(iam.PolicyStatement(
            effect=iam.Effect.ALLOW,
            policy_name='AllowS3GetObjectsToInputBucketObjects',
            actions=[
                "s3:GetObject",
                "s3:GetObjectVersion"
            ],
            resources=[
                inputs_bucket.bucket_arn+'/*',
            ],
        ))

        # add sqs queue permissions
        batching_endpoint_lambda.add_to_role_policy(iam.PolicyStatement(
            effect=iam.Effect.ALLOW,
            policy_name='AllowSQSReadWritePermissions',
            actions=[
                "sqs:DeleteMessage",
                "sqs:GetQueueUrl",
                "sqs:ListQueues",
                "sqs:ChangeMessageVisibility",
                "sqs:SendMessageBatch",
                "sqs:ReceiveMessage",
                "sqs:SendMessage",
                "sqs:GetQueueAttributes",
                "sqs:ListQueueTags",
                "sqs:ListDeadLetterSourceQueues",
                "sqs:DeleteMessageBatch",
                "sqs:ChangeMessageVisibilityBatch",
                "sqs:SetQueueAttributes"
            ],
            resources=[
                shepard_receive_queue.queue_arn,
            ],
        ))

        # add sqs DLQ queue permissions
        batching_endpoint_lambda.add_to_role_policy(iam.PolicyStatement(
            effect=iam.Effect.ALLOW,
            policy_name='AllowSQSDLQReadWritePermissions',
            actions=[
                "sqs:DeleteMessage",
                "sqs:GetQueueUrl",
                "sqs:ListQueues",
                "sqs:ChangeMessageVisibility",
                "sqs:SendMessageBatch",
                "sqs:ReceiveMessage",
                "sqs:SendMessage",
                "sqs:GetQueueAttributes",
                "sqs:ListQueueTags",
                "sqs:ListDeadLetterSourceQueues",
                "sqs:DeleteMessageBatch",
                "sqs:ChangeMessageVisibilityBatch",
                "sqs:SetQueueAttributes"
            ],
            resources=[
                shepard_receive_queue_DLQ.queue_arn,
            ],
        ))

        #add DynamoDB permissions
        batching_endpoint_lambda.add_to_role_policy(iam.PolicyStatement(
            effect=iam.Effect.ALLOW,
            policy_name='AllowDynamoDBReadWritePermissions',
            actions=[
                "dynamodb:BatchGet*",
                "dynamodb:DescribeStream",
                "dynamodb:DescribeTable",
                "dynamodb:Get*",
                "dynamodb:Query",
                "dynamodb:Scan",
                "dynamodb:BatchWrite*",
                "dynamodb:CreateTable",
                "dynamodb:Delete*",
                "dynamodb:Update*",
                "dynamodb:PutItem"
            ],
            resources=[
                table.table_arn,
            ],
        ))

        #add batch job queue permissions
        batching_endpoint_lambda.add_to_role_policy(iam.PolicyStatement(
            effect=iam.Effect.ALLOW,
            policy_name='BatchAllowSubmitJobPermissions',
            actions=[
                "batch:SubmitJob"
            ],
            resources=[
                job_queue.job_queue_arn,
                batch_job_definition.job_definition_arn+'/*',
                batch_job_definition.job_definition_arn

            ],
        ))

        ##Container runtime permissions

        #add logging permissions
        container_runtime_role.add_to_role_policy(iam.PolicyStatement(
            effect=iam.Effect.ALLOW,
            policy_name='AllowLogGroupCreationAndStreaming',
            actions=[
                'logs:CreateLogGroup',
                'logs:CreateLogStream',
                'logs:PutLogEvents'
            ],
            resources=[
                'arn:aws:logs:*:*:*',
            ],
        ))

        #add secret store access permissions
        container_runtime_role.add_to_role_policy(iam.PolicyStatement(
            effect=iam.Effect.ALLOW,
            policy_name='AllowAccessToSecretsStore',
            actions=[
                "secretsmanager:GetResourcePolicy",
                "secretsmanager:GetSecretValue",
                "secretsmanager:DescribeSecret",
                "secretsmanager:ListSecretVersionIds"
            ],
            resources=[
                secret_store.secret_arn,
            ],
        ))

        #add input s3 bucket permissions
        container_runtime_role.add_to_role_policy(iam.PolicyStatement(
            effect=iam.Effect.ALLOW,
            policy_name='AllowS3ListBucketToInputsBucket',
            actions=[
                "s3:ListBucket"
            ],
            resources=[
                inputs_bucket.bucket_arn,
            ],
        ))
        container_runtime_role.add_to_role_policy(iam.PolicyStatement(
            effect=iam.Effect.ALLOW,
            policy_name='AllowS3GetObjectsToInputBucketObjects',
            actions=[
                "s3:GetObject",
                "s3:GetObjectVersion"
            ],
            resources=[
                inputs_bucket.bucket_arn+'/*',
            ],
        ))

        #add quick deploy s3 bucket permissions
        container_runtime_role.add_to_role_policy(iam.PolicyStatement(
            effect=iam.Effect.ALLOW,
            policy_name='AllowS3ListBucketToQuickDeployBucket',
            actions=[
                "s3:ListBucket"
            ],
            resources=[
                quick_deploy_bucket.bucket_arn,
            ],
        ))
        container_runtime_role.add_to_role_policy(iam.PolicyStatement(
            effect=iam.Effect.ALLOW,
            policy_name='AllowS3GetObjectsToQuickDeployBucketObjects',
            actions=[
                "s3:GetObject",
                "s3:GetObjectVersion"
            ],
            resources=[
                quick_deploy_bucket.bucket_arn+'/*',
            ],
        ))

        #add output s3 bucket permissions
        container_runtime_role.add_to_role_policy(iam.PolicyStatement(
            effect=iam.Effect.ALLOW,
            policy_name='AllowS3ListBucketToOutputBucket',
            actions=[
                "s3:ListBucket"
            ],
            resources=[
                outputs_bucket.bucket_arn,
            ],
        ))
        container_runtime_role.add_to_role_policy(iam.PolicyStatement(
            effect=iam.Effect.ALLOW,
            policy_name='AllowS3PutObjectsToOutputBucketObjects',
            actions=[
                "s3:PutObject"
            ],
            resources=[
                outputs_bucket.bucket_arn+'/*',
            ],
        ))

        #add DynamoDB permissions
        container_runtime_role.add_to_role_policy(iam.PolicyStatement(
            effect=iam.Effect.ALLOW,
            policy_name='AllowDynamoDBReadWritePermissions',
            actions=[
                "dynamodb:BatchGet*",
                "dynamodb:DescribeStream",
                "dynamodb:DescribeTable",
                "dynamodb:Get*",
                "dynamodb:Query",
                "dynamodb:Scan",
                "dynamodb:BatchWrite*",
                "dynamodb:CreateTable",
                "dynamodb:Delete*",
                "dynamodb:Update*",
                "dynamodb:PutItem"
            ],
            resources=[
                table.table_arn,
            ],
        ))
        #################################EXTRA PERMISSIONS FOR IAM ROLES ENDS HERE#################################

        #################################LAMBDA ENVIRONMENT VARIABLE SETUP STARTS HERE#################################
        #create environment variable dictionary for lambdas
        reserved_keywords = "['UUID','START_TIME','END_TIME','JOB_STATUS',\
                            'EFS_INPUT_NAME','EFS_OUTPUT_NAME','LUSTRE_INPUT_NAME',\
                            'LUSTRE_OUTPUT_NAME','ROOT_INPUT_NAME','ROOT_OUTPUT_NAME','INPUTS_BUCKET',\
                            'OUTPUTS_BUCKET','ERROR_BUCKET','INPUT_ZIP_NAME','PATH','HOSTNAME','USES_EFS',\
                            'USES_LUSTRE','LUSTRE_READ_ONLY_PATH','EFS_READ_ONLY_PATH','ULIMIT_FILENO',\
                            'IS_INVOKED','ALLOW_DOCKER_ACCESS']"
        lambda_environment_variables = {
        "dynamodb_table_name": table.table_name,
        "job_queue_name": job_queue.job_queue_name,
        "job_definition_arn": batch_job_definition.job_definition_arn,
        "days_to_keep_failed_launch_indexes":str(self.node.try_get_context("DaysToKeepFailedLaunchIndexes")),
        "reserved_keywords":reserved_keywords
        }

        # add environment variables to batching endpoint lambda and scheduler lambda
        setattr(batching_endpoint_lambda,'environment',lambda_environment_variables)
        setattr(job_scheduler_lambda,'environment',lambda_environment_variables)
        #################################LAMBDA ENVIRONMENT VARIABLE SETUP ENDS HERE#################################

        #################################CFN OUTPUT/EXPORT SETUP STARTS HERE#################################
        #get stack name from supplied context
        stack_name = self.node.try_get_context("StackName")

        #export VPC ID
        if self.node.try_get_context("ExistingVPC"):
            CfnOutput(self, "VPC_ID",
                      value=shepard_vpc,
                      description='VPC ID used by this architecture. \
                      This stack used an existing VPC so one was not created from scratch.',
                      export_name=stack_name + "VPC_ID",)
        else:
            CfnOutput(self, "VPC_ID",
                      value=shepard_vpc.id,
                      description='VPC ID used by this architecture. \
                      This stack created a new VPC from scratch.',
                      export_name=stack_name + "VPC_ID",)

        #export VPC CIDR
        CfnOutput(self, "VPC_CIDR",
                  value=shepard_vpc,
                  description='CIDR of the VPC used by this architecture.',
                  export_name=stack_name + "VPC_CIDR",)

        #export ECR Repo name
        CfnOutput(self, "EcrRepoRepositoryName",
                  value=ecr_repo.repository_name,
                  description='Name of the ECR repository used by this architecture',
                  export_name=stack_name + "EcrRepoRepositoryName",)

        #export ECR Repo URI
        CfnOutput(self, "EcrRepoRepositoryURI",
                  value=ecr_repo.repository_uri,
                  description='URI of the ECR repository used by this architecture',
                  export_name=stack_name + "EcrRepoRepositoryURI",)

        #export ECR Repo ARN
        CfnOutput(self, "EcrRepoRepositoryARN",
                  value=ecr_repo.repository_arn,
                  description='ARN of the ECR repository used by this architecture',
                  export_name=stack_name + "EcrRepoRepositoryARN",)

        #export Secrets Manager Store Name
        CfnOutput(self, "SecretsManagerName",
                  value=secret_store.secret_name,
                  description='Name of the secrets manager secrets store used by this architecture.',
                  export_name=stack_name + "SecretsManagerName",)

        #export Secrets Manager Store ARN
        CfnOutput(self, "SecretsManagerARN",
                  value=secret_store.secret_arn,
                  description='ARN of the secrets manager secrets store used by this architecture.',
                  export_name=stack_name + "SecretsManagerARN",)

        ##export EFS Attributes
        if self.node.try_get_context("CreateEFS") == 'True':

            #export security group ID
            CfnOutput(self, "EFSSecurityGroupID",
                      value=efs_security_group.security_group_id,
                      description='ID of the security group for the EFS.',
                      export_name=stack_name + "EFSSecurityGroupID",)

            #export EFS file system ID
            CfnOutput(self, "EFSFileSystemID",
                      value=system_efs.file_system_id,
                      description='ID of the EFS created for this architecture',
                      export_name=stack_name + "EFSFileSystemID",)

        ##export LUSTRE Attributes
        if self.node.try_get_context("CreateLustre") == 'True':

            #export security group ID
            CfnOutput(self, "LustreSecurityGroupID",
                      value=lustre_security_group.security_group_id,
                      description='ID of the security group for the LUSTRE.',
                      export_name=stack_name + "LustreSecurityGroupID",)

            #export LUSTRE file system ID
            CfnOutput(self, "LustreFileSystemID",
                      value=system_lustre_file_system.file_system_id,
                      description='ID of the LUSTRE created for this architecture',
                      export_name=stack_name + "LustreFileSystemID",)

            if not self.node.try_get_context("ExistingLustreBucket"):
                #export LUSTRE s3 bucket
                CfnOutput(self, "LustreS3BucketName",
                          value=self.node.try_get_context("ExistingLustreBucket"),
                          description='Name of the Lustre S3 bucket that already existed that was used for this architecture.',
                          export_name=stack_name + "LustreS3BucketName",)
            else:
                #export LUSTRE s3 bucket
                CfnOutput(self, "LustreS3BucketName",
                          value=lustre_bucket.bucket_name,
                          description='Name of the Lustre S3 bucket created for this architecture.',
                          export_name=stack_name + "LustreS3BucketName",)

        ##export S3 bucket names

        # export inputs bucket name
        CfnOutput(self, "InputsS3BucketName",
                  value=inputs_bucket.bucket_name,
                  description='Name of the inputs S3 bucket created for this architecture.',
                  export_name=stack_name + "InputsS3BucketName", )

        # export output bucket name
        CfnOutput(self, "OutputsS3BucketName",
                  value=outputs_bucket.bucket_name,
                  description='Name of the outputs S3 bucket created for this architecture.',
                  export_name=stack_name + "OutputsS3BucketName", )

        # export quick deploy bucket name
        CfnOutput(self, "QuickDeployS3BucketName",
                  value=quick_deploy_bucket.bucket_name,
                  description='Name of the quick deploy S3 bucket created for this architecture.',
                  export_name=stack_name + "QuickDeployS3BucketName", )

        ##export batch infrastructure descriptions

        # export ecs instance role ARN.
        CfnOutput(self, "ECSInstanceRoleARN",
                  value=ecs_instance_role.role_arn,
                  description='ARN of the ECS instance role created for this architecture.',
                  export_name=stack_name + "ECSInstanceRoleARN", )

        # export spot fleet role ARN.
        CfnOutput(self, "SpotFleetRoleARN",
                  value=spot_fleet_role.role_arn,
                  description='ARN of the spot fleet role created for this architecture.',
                  export_name=stack_name + "SpotFleetRoleARN", )

        if self.node.try_get_context("ExtraIAMPolicyForContainerRole"):
            # export extra policy appended to container role
            CfnOutput(self, "ExtraIAMPolicyForContainerRole",
                      value=self.node.try_get_context("ExtraIAMPolicyForContainerRole"),
                      description='Extra policy that was attached to the container runtime role.',
                      export_name=stack_name + "ExtraIAMPolicyForContainerRole", )

        # export container runtime role ARN.
        CfnOutput(self, "ContainerRuntimeRoleARN",
                  value=container_runtime_role.role_arn,
                  description='ARN of the container runtime role created for this architecture.',
                  export_name=stack_name + "ContainerRuntimeRoleARN", )

        # export batch security group id
        CfnOutput(self, "BatchSecurityGroupID",
                  value=batch_security_group.security_group_id,
                  description='ID of the Batch security group created for this architecture.',
                  export_name=stack_name + "BatchSecurityGroupID", )

        # export launch template name
        CfnOutput(self, "LaunchTemplateName",
                  value=shepard_launch_template.launch_template_name,
                  description='Name of the launch template created for this architecture.',
                  export_name=stack_name + "LaunchTemplateName", )

        # export batch compute environment ARN
        CfnOutput(self, "BatchComputeEnvironmentARN",
                  value=batch_compute_environment.compute_environment_arn,
                  description='ARN of the Batch compute environment created for this architecture.',
                  export_name=stack_name + "BatchComputeEnvironmentARN", )

        # export batch job definition ARN
        CfnOutput(self, "BatchJobDefinitionARN",
                  value=batch_job_definition.job_definition_arn,
                  description='ARN of the Batch job definition created for this architecture.',
                  export_name=stack_name + "BatchJobDefinitionARN", )

        # export batch job queue ARN
        CfnOutput(self, "BatchJobQueueARN",
                  value=job_queue.job_queue_arn,
                  description='ARN of the Batch job queue created for this architecture.',
                  export_name=stack_name + "BatchJobQueueARN", )

        ##export lambda infrastructure descriptions

        # export job scheduler lambda ARN
        CfnOutput(self, "JobSchedulerLambdaARN",
                  value=job_scheduler_lambda.function_arn,
                  description='ARN of the job scheduler lambda created for this architecture.',
                  export_name=stack_name + "JobSchedulerLambdaARN", )

        # export job scheduler lambda name
        CfnOutput(self, "JobSchedulerLambdaName",
                  value=job_scheduler_lambda.function_name,
                  description='Name of the job scheduler lambda created for this architecture.',
                  export_name=stack_name + "JobSchedulerLambdaName", )

        # export job scheduler lambda role ARN
        CfnOutput(self, "JobSchedulerLambdaRoleARN",
                  value=job_scheduler_lambda.role.role_arn,
                  description='ARN of the role of the job scheduler lambda created for this architecture.',
                  export_name=stack_name + "JobSchedulerLambdaRoleARN", )

        # export job scheduler lambda ARN
        CfnOutput(self, "BatchingEndpointLambdaARN",
                  value=batching_endpoint_lambda.function_arn,
                  description='ARN of the batching endpoint lambda created for this architecture.',
                  export_name=stack_name + "JobSchedulerLambdaARN", )

        # export job scheduler lambda name
        CfnOutput(self, "BatchingEndpointLambdaName",
                  value=batching_endpoint_lambda.function_name,
                  description='Name of the batching endpoint lambda created for this architecture.',
                  export_name=stack_name + "JobSchedulerLambdaName", )

        # export job scheduler lambda role ARN
        CfnOutput(self, "BatchingEndpointLambdaRoleARN",
                  value=batching_endpoint_lambda.role.role_arn,
                  description='ARN of the role of the batching endpoint lambda created for this architecture.',
                  export_name=stack_name + "JobSchedulerLambdaRoleARN", )

        # export DynamoDB ARN
        CfnOutput(self, "DynamoDBTableARN",
                  value=table.table_arn,
                  description='ARN of the dynamoDB table created for this architecture.',
                  export_name=stack_name + "DynamoDBTableARN", )

        # export DynamoDB name
        CfnOutput(self, "DynamoDBTableName",
                  value=table.table_name,
                  description='Name of the dynamoDB table created for this architecture.',
                  export_name=stack_name + "DynamoDBTableName", )

        ##export SQS infrastructure descriptions

        #for regular receive queue
        CfnOutput(self, "NormalReceiveSQSQueueARN",
                  value=shepard_receive_queue.queue_arn,
                  description='ARN of the normal receive SQS queue created for this architecture',
                  export_name=stack_name + "NormalReceiveSQSQueueARN", )
        CfnOutput(self, "NormalReceiveSQSQueueName",
                  value=shepard_receive_queue.queue_name,
                  description='Name of the normal receive SQS queue created for this architecture',
                  export_name=stack_name + "NormalReceiveSQSQueueName", )
        CfnOutput(self, "NormalReceiveSQSQueueURL",
                  value=shepard_receive_queue.queue_url,
                  description='URL of the normal receive SQS queue created for this architecture',
                  export_name=stack_name + "NormalReceiveSQSQueueURL", )
        #for DLQ
        CfnOutput(self, "DLQSQSQueueARN",
                  value=shepard_receive_queue_DLQ.queue_arn,
                  description='ARN of the DLQ SQS queue created for this architecture',
                  export_name=stack_name + "DLQSQSQueueARN", )
        CfnOutput(self, "DLQSQSQueueName",
                  value=shepard_receive_queue_DLQ.queue_name,
                  description='Name of the DLQ SQS queue created for this architecture',
                  export_name=stack_name + "DLQSQSQueueName", )
        CfnOutput(self, "DLQSQSQueueURL",
                  value=shepard_receive_queue_DLQ.queue_url,
                  description='URL of the DLQ SQS queue created for this architecture',
                  export_name=stack_name + "DLQSQSQueueURL", )


        #################################CFN OUTPUT/EXPORT SETUP ENDS HERE#################################


##deployment script to execute

#instantiate App() object
app = App()

#Attempt to get account id from CDK environment variable or from hardcoded variable in cdk.json
if app.node.try_get_context("account"):
    account = app.node.try_get_context("account")
else:
    account = os.environ.get("CDK_DEPLOY_ACCOUNT",os.environ["CDK_DEFAULT_ACCOUNT"])

#Attempt to get region from CDK environment variable or from hardcoded variable in cdk.json
if app.node.try_get_context("region"):
    region = app.node.try_get_context("region")
else:
    region = os.environ.get("CDK_DEPLOY_REGION",os.environ["CDK_DEFAULT_REGION"])

#Attempt to get stack name from context and if not there throw error
if app.node.try_get_context("StackName"):
    stack_name = app.node.try_get_context("StackName")
else:
    raise ValueError('Your specified CloudFormation stack name must be a string that is not a null string or "".')

#define shepard stack
shepard_stack = ShepardStack(app, stack_name, env=Environment(account=account, region=region))

#attach tags if requested to new infrastructure
if app.node.try_get_context("ResourceTags"):
    for key, value in app.node.try_get_context("ResourceTags").items():
        Tags.of(shepard_stack).add(key, value)
        shepard_stack.node.apply(Tag(key, value))

#run app synth() method
app.synth()