package vircleamazonec2

import (
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/endpoints"
	"github.com/aws/aws-sdk-go/aws/session"

	log "github.com/sirupsen/logrus"
)

type EC2Client struct {
	*ec2.EC2
}

func NewEc2Client(region string, profile string) (*EC2Client, error) {
	// Initialize a session in us-west-2 that the SDK will use to load
	// credentials from the shared credentials file ~/.aws/credentials.
	sess, err := session.NewSession(&aws.Config{
		Region:      aws.String(region),
		Credentials: credentials.NewSharedCredentials("", profile)},
	)

	// Create an EC2 service client.
	c := new(EC2Client)

	c.EC2 = ec2.New(sess)

	return c, err
}

func (c *EC2Client) CreateInstances(imageId string, instanceType string, keyName string, securityGroupId string) (string, error) {
	// Specify the details of the instance that you want to create.
	if len(imageId) == 0 {
		imageId = "ami-0d5d9d301c853a04a"
	}

	if len(instanceType) == 0 {
		instanceType = "t2.micro"
	}

	if len(keyName) == 0 {
		keyName = "myaws"
	}

	log.Info("Create instance for ", imageId, " of ", instanceType)

	result, err := c.RunInstances(&ec2.RunInstancesInput{
		// An Amazon Linux AMI ID for t2.micro instances in the us-west-2 region
		ImageId:          aws.String(imageId),
		InstanceType:     aws.String(instanceType),
		MinCount:         aws.Int64(1),
		MaxCount:         aws.Int64(1),
		KeyName:          aws.String(keyName),
		SecurityGroupIds: []*string{aws.String(securityGroupId)},
	})

	if err != nil {
		log.Error("Could not create instance,", err)
		return "", err
	}
	log.Info("Success create instance ", *result.Instances[0].InstanceId)
	return *result.Instances[0].InstanceId, nil
}

func (c *EC2Client) TerminateInstance(instanceId string) ([]*ec2.InstanceStateChange, error) {
	log.Info("Terminate instance ", instanceId)
	input := &ec2.TerminateInstancesInput{
		InstanceIds: []*string{
			aws.String(instanceId),
		},
		DryRun: aws.Bool(true),
	}
	result, err := c.TerminateInstances(input)
	awsErr, ok := err.(awserr.Error)

	// If the error code is `DryRunOperation` it means we have the necessary
	// permissions to Start this instance
	if ok && awsErr.Code() == "DryRunOperation" {
		input.DryRun = aws.Bool(false)
		result, err = c.TerminateInstances(input)
		if err == nil {
			log.Info("Success terminate instance ", instanceId)
			return result.TerminatingInstances, nil
		}
	}
	log.Error("Unable to terminate instance ", err)
	return nil, err
}

func (c *EC2Client) StartInstance(instanceId string) ([]*ec2.InstanceStateChange, error) {
	log.Info("Start instance ", instanceId)
	input := &ec2.StartInstancesInput{
		InstanceIds: []*string{
			aws.String(instanceId),
		},
		DryRun: aws.Bool(true),
	}
	result, err := c.StartInstances(input)
	awsErr, ok := err.(awserr.Error)

	// If the error code is `DryRunOperation` it means we have the necessary
	// permissions to Start this instance
	if ok && awsErr.Code() == "DryRunOperation" {
		// Let's now set dry run to be false. This will allow us to start the instances
		input.DryRun = aws.Bool(false)
		result, err = c.StartInstances(input)
		if err == nil {
			log.Info("Success start instance ", instanceId)
			return result.StartingInstances, nil
		}
	}
	log.Info("Unable to start instance ", instanceId)
	return nil, err
}

func (c *EC2Client) StopInstance(instanceId string) ([]*ec2.InstanceStateChange, error) {
	log.Info("stop instance ", instanceId)
	input := &ec2.StopInstancesInput{
		InstanceIds: []*string{
			aws.String(instanceId),
		},
		DryRun: aws.Bool(true),
	}
	result, err := c.StopInstances(input)
	awsErr, ok := err.(awserr.Error)
	if ok && awsErr.Code() == "DryRunOperation" {
		input.DryRun = aws.Bool(false)
		result, err = c.StopInstances(input)
		if err == nil {
			log.Info("Success stop instance ", instanceId)
			return result.StoppingInstances, nil
		}
	}
	log.Info("Unable to stop instance ", instanceId)
	return nil, err
}

func (c *EC2Client) RebootInstance(instanceId string) (*ec2.RebootInstancesOutput, error) {
	// We set DryRun to true to check to see if the instance exists and we have the
	// necessary permissions to monitor the instance.
	log.Info("reboot instance ", instanceId)
	input := &ec2.RebootInstancesInput{
		InstanceIds: []*string{
			aws.String(instanceId),
		},
		DryRun: aws.Bool(true),
	}
	result, err := c.RebootInstances(input)
	awsErr, ok := err.(awserr.Error)

	// If the error code is `DryRunOperation` it means we have the necessary
	// permissions to Start this instance
	if ok && awsErr.Code() == "DryRunOperation" {
		// Let's now set dry run to be false. This will allow us to reboot the instances
		input.DryRun = aws.Bool(false)
		result, err = c.RebootInstances(input)
		if err == nil {
			log.Info("Success reboot instance ", instanceId)
			return result, nil
		}
	}
	log.Info("Unable to reboot instance ", instanceId)
	return nil, err
}

/*
func (c *EC2Client) UpdateSecurityGroupOfInstance(networkInterfaceId string, groupId string, vpcId string) (*ec2.ModifyNetworkInterfaceAttributeOutput, error) {
	return c.ModifyNetworkInterfaceAttribute(&ec2.ModifyNetworkInterfaceAttributeInput{
		NetworkInterfaceId: aws.String(networkInterfaceId),
		SecurityGroupIds:   aws.String(groupId),
	})
}
*/

func (c *EC2Client) GetDescribeInstance(instanceIds []string) (*ec2.DescribeInstancesOutput, error) {
	if len(instanceIds) == 0 {
		return c.DescribeInstances(nil)
	}
	return c.DescribeInstances(&ec2.DescribeInstancesInput{
		InstanceIds: aws.StringSlice(instanceIds),
	})
}

func (c *EC2Client) CreateSecurityGroups(name string, desc string, ipPermission []*ec2.IpPermission) (string, error) {
	// If the VPC ID wasn't provided in the CLI retrieve the first in the account.
	// Get a list of VPCs so we can associate the group with the first VPC.
	log.Info("Create security group ", name)
	result, err := c.DescribeVpcs(nil)
	if err != nil {
		log.Error("Unable to describe VPCs ", err)
		return "", err
	}
	if len(result.Vpcs) == 0 {
		log.Error("No VPCs found to associate security group with.")
		return "", err
	}
	vpcID := aws.StringValue(result.Vpcs[0].VpcId)

	// Create the security group with the VPC, name and description.
	createRes, err := c.CreateSecurityGroup(&ec2.CreateSecurityGroupInput{
		GroupName:   aws.String(name),
		Description: aws.String(desc),
		VpcId:       aws.String(vpcID),
	})
	if err != nil {
		if aerr, ok := err.(awserr.Error); ok {
			switch aerr.Code() {
			case "InvalidVpcID.NotFound":
				log.Error("Unable to find VPC with ID ", vpcID)
				return "", err
			case "InvalidGroup.Duplicate":
				log.Error("Security group ", name, " already exists.")
				return "", err
			}
		}
		log.Error("Unable to create security group ", name, ",", err)
		return "", err
	}

	if len(ipPermission) > 0 {
		// Add permissions to the security group
		_, err = c.AuthorizeSecurityGroupIngress(&ec2.AuthorizeSecurityGroupIngressInput{
			GroupName:     aws.String(name),
			IpPermissions: ipPermission,
		})
		if err != nil {
			log.Error("Unable to set security group ", name, " ingress, ", err)
			return "", err
		}
	}
	log.Info("Successfully set security group ingress")
	return aws.StringValue(createRes.GroupId), nil
}

func (c *EC2Client) SetSecurityGroups(name string, ipPermission []*ec2.IpPermission) (string, error) {
	log.Info("Set security group ", name, " ingress")
	// Add permissions to the security group
	_, err := c.AuthorizeSecurityGroupIngress(&ec2.AuthorizeSecurityGroupIngressInput{
		GroupName:     aws.String(name),
		IpPermissions: ipPermission,
	})
	if err != nil {
		log.Error("Unable to set security group ", name, " ingress, ", err)
		return "", err
	}
	log.Info("Successfully set security group ", name, " ingress")
	return name, nil
}

func (c *EC2Client) UpdateSecurityGroups(groupId string, ipPermission []*ec2.IpPermission) (string, error) {
	log.Info("Update security group ", groupId)
	_, err := c.UpdateSecurityGroupRuleDescriptionsIngress(&ec2.UpdateSecurityGroupRuleDescriptionsIngressInput{
		GroupId:       aws.String(groupId),
		IpPermissions: ipPermission,
	})
	if err != nil {
		log.Error("Unable to update security group ", groupId, " ingress, ", err)
		return "", err
	}
	log.Info("Success update security group ", groupId)
	return groupId, nil
}

func (c *EC2Client) DeleteSecurityGroups(groupId string) (string, error) {
	// Delete the security group.
	log.Info("Delete security group ", groupId)
	_, err := c.DeleteSecurityGroup(&ec2.DeleteSecurityGroupInput{
		GroupId: aws.String(groupId),
	})
	if err != nil {
		if aerr, ok := err.(awserr.Error); ok {
			switch aerr.Code() {
			case "InvalidGroupId.Malformed":
				fallthrough
			case "InvalidGroup.NotFound":
				log.Error(groupId, ":", aerr.Message())
				return "", err
			}
		}
		log.Error("Unable to get descriptions for security groups, %v.", err)
		return "", err
	}
	log.Info("Successfully delete security group ", groupId)
	return groupId, nil
}

func (c *EC2Client) GetDescribeSecurityGroups(groupIds []string) (*ec2.DescribeSecurityGroupsOutput, error) {
	if len(groupNames) == 0 {
		return c.DescribeSecurityGroups(nil)
	}
	return c.DescribeSecurityGroups(&ec2.DescribeSecurityGroupsInput{
		GroupIds: aws.StringSlice(groupIds),
	})
}

func (c *EC2Client) CreateKeyPairs(pairName string) (*ec2.CreateKeyPairOutput, error) {
	log.Info("Create key pair ", pairName)
	// Creates a new  key pair with the given name
	result, err := c.CreateKeyPair(&ec2.CreateKeyPairInput{
		KeyName: aws.String(pairName),
	})
	if err != nil {
		if aerr, ok := err.(awserr.Error); ok && aerr.Code() == "InvalidKeyPair.Duplicate" {
			log.Error("Keypair ", pairName, " already exists.")
			return nil, err
		}
		log.Error("Unable to create key pair: ", pairName, ",", err)
	}
	log.Info("Successfully create key pair ", pairName)
	return result, nil
}

func (c *EC2Client) DeleteKeyPairs(pairName string) (string, error) {
	log.Info("delete key pair ", pairName)
	_, err := c.DeleteKeyPair(&ec2.DeleteKeyPairInput{
		KeyName: aws.String(pairName),
	})
	if err != nil {
		if aerr, ok := err.(awserr.Error); ok && aerr.Code() == "InvalidKeyPair.Duplicate" {
			log.Error("Key pair ", pairName, " does not exist.")
		}
		log.Error("Unable to delete key pair: ", pairName, " ", err)
	}
	log.Info("Successfully delete key pair ", pairName)
	return pairName, nil
}

func (c *EC2Client) GetDescribeKeyPairs(pairNames []string) (*ec2.DescribeKeyPairsOutput, error) {
	if len(pairNames) == 0 {
		return c.DescribeKeyPairs(nil)
	}
	return c.DescribeKeyPairs(&ec2.DescribeKeyPairsInput{
		KeyNames: aws.StringSlice(pairNames),
	})
}

func (c *EC2Client) AllocateAddresss(instanceId string) (string, string, error) {
	log.Info("Allocate Ip address for ", instanceId)
	// Attempt to allocate the Elastic IP address.
	allocRes, err := c.AllocateAddress(&ec2.AllocateAddressInput{
		Domain: aws.String("vpc"),
	})
	if err != nil {
		log.Error("Unable to allocate IP address, ", err)
		return "", "", err
	}

	// Associate the new Elastic IP address with an existing EC2 instance.
	assocRes, err := c.AssociateAddress(&ec2.AssociateAddressInput{
		AllocationId: allocRes.AllocationId,
		InstanceId:   aws.String(instanceId),
	})
	if err != nil {
		log.Error("Unable to associate IP address with ", instanceId, ", ", err)
		return "", *allocRes.AllocationId, err
	}
	log.Info("Successfully allocated ", *allocRes.PublicIp, " with instance ", instanceId, ". allocation id: ", *allocRes.AllocationId, " association id: ", *assocRes.AssociationId)
	return *allocRes.PublicIp, *allocRes.AllocationId, nil
}

func (c *EC2Client) AssociateAddresss(instanceId string, allocationId string) (string, error) {
	log.Info("Allocate Ip address for ", instanceId)
	// Associate the new Elastic IP address with an existing EC2 instance.
	_, err := c.AssociateAddress(&ec2.AssociateAddressInput{
		AllocationId: aws.String(allocationId),
		InstanceId:   aws.String(instanceId),
	})
	if err != nil {
		log.Error("Unable to associate IP address with ", instanceId, ", ", err)
		return allocationId, err
	}
	log.Info("Successfully Associate address allocation id: ", allocationId)
	return allocationId, nil
}

func (c *EC2Client) ReleaseAddresss(allocationId string) (string, error) {
	log.Info("Release Ip address for ", allocationId)
	_, err := c.ReleaseAddress(&ec2.ReleaseAddressInput{
		AllocationId: aws.String(allocationId),
	})
	if err != nil {
		if aerr, ok := err.(awserr.Error); ok && aerr.Code() == "InvalidAllocationID.NotFound" {
			log.Error("Allocation ID ", allocationId, " does not exist")
			return "", err
		}
		log.Error("Unable to release IP address for allocation ", allocationId, " ", err)
		return "", err
	}
	log.Info("Successfully released allocation ID ", allocationId)
	return allocationId, nil
}

func (c *EC2Client) GetDescribeAddresss() (*ec2.DescribeAddressesOutput, error) {
	log.Info("get describe ip address ")
	return c.DescribeAddresses(&ec2.DescribeAddressesInput{
		Filters: []*ec2.Filter{
			{
				Name:   aws.String("domain"),
				Values: aws.StringSlice([]string{"vpc"}),
			},
		},
	})
}

func (c *EC2Client) CreateVolumes(zone string, size int64) (string, error) {
	log.Info("create volume ", size, "GB in ", zone)
	result, err := c.CreateVolume(&ec2.CreateVolumeInput{
		AvailabilityZone: aws.String(zone),
		Size:             aws.Int64(size),
	})
	if err != nil {
		log.Error("Unable to release IP address for allocation ", " ", err)
		return "", err
	}
	log.Info("Successfully create volume ", aws.StringValue(result.VolumeId))
	return aws.StringValue(result.VolumeId), nil
}

func (c *EC2Client) AttachVolumes(instanceId string, volumeId string, deviceName string) (*ec2.VolumeAttachment, error) {
	return c.AttachVolume(&ec2.AttachVolumeInput{
		Device:     aws.String(deviceName),
		InstanceId: aws.String(instanceId),
		VolumeId:   aws.String(volumeId),
	})

}

func (c *EC2Client) DetachVolumes(instanceId string, volumeId string, deviceName string) (*ec2.VolumeAttachment, error) {
	return c.DetachVolume(&ec2.DetachVolumeInput{
		Device:     aws.String(deviceName),
		InstanceId: aws.String(instanceId),
		VolumeId:   aws.String(volumeId),
	})
}

func (c *EC2Client) ModifyVolumes(volumeId string, size int64) (*ec2.ModifyVolumeOutput, error) {
	return c.ModifyVolume(&ec2.ModifyVolumeInput{
		Size:     aws.Int64(size),
		VolumeId: aws.String(volumeId),
	})
}

func (c *EC2Client) DeleteVolumes(volumeId string) (*ec2.DeleteVolumeOutput, error) {
	return c.DeleteVolume(&ec2.DeleteVolumeInput{
		VolumeId: aws.String(volumeId),
	})
}

func (c *EC2Client) GetDescribeVolumes(volumeIds []string) (*ec2.DescribeVolumesOutput, error) {
	if len(volumeIds) == 0 {
		return c.DescribeVolumes(nil)
	}
	return c.DescribeVolumes(&ec2.DescribeVolumesInput{
		VolumeIds: aws.StringSlice(volumeIds),
	})
}

func (c *EC2Client) CreateNetworkInterfaces(desc string, groupId string, privateAddress string, subnetId string) (*ec2.CreateNetworkInterfaceOutput, error) {
	return c.CreateNetworkInterface(&ec2.CreateNetworkInterfaceInput{
		Description: aws.String(desc),
		Groups: []*string{
			aws.String(groupId),
		},
		PrivateIpAddress: aws.String(privateAddress),
		SubnetId:         aws.String(subnetId),
	})
}

func (c *EC2Client) DeleteNetworkInterfaces(networkInterfaceId string) (*ec2.DeleteNetworkInterfaceOutput, error) {
	return c.DeleteNetworkInterface(&ec2.DeleteNetworkInterfaceInput{
		NetworkInterfaceId: aws.String(networkInterfaceId),
	})
}

func (c *EC2Client) GetDescribeNetworkInterfaces(networkInterfaceId string) (*ec2.DescribeNetworkInterfacesOutput, error) {
	if len(networkInterfaceId) == 0 {
		return c.DescribeNetworkInterfaces(nil)
	}
	return c.DescribeNetworkInterfaces(&ec2.DescribeNetworkInterfacesInput{
		NetworkInterfaceIds: []*string{
			aws.String(networkInterfaceId),
		},
	})
}

func (c *EC2Client) CreateSubnets(cidrBlock string, vpcId string) (*ec2.CreateSubnetOutput, error) {
	return c.CreateSubnet(&ec2.CreateSubnetInput{
		CidrBlock: aws.String(cidrBlock),
		VpcId:     aws.String(vpcId),
	})
}

func (c *EC2Client) DeleteSubnets(subnetId string) (*ec2.DeleteSubnetOutput, error) {
	return c.DeleteSubnet(&ec2.DeleteSubnetInput{
		SubnetId: aws.String(subnetId),
	})
}

func (c *EC2Client) GetDescribeSubnets(subnetIds []string) (*ec2.DescribeSubnetsOutput, error) {
	if len(subnetIds) == 0 {
		return c.DescribeSubnets(nil)
	}
	return c.DescribeSubnets(&ec2.DescribeSubnetsInput{
		Filters: []*ec2.Filter{
			{
				Name:   aws.String("vpc-id"),
				Values: aws.StringSlice(subnetIds),
			},
		},
	})
}

func GetRegions() []endpoints.Partition {
	resolver := endpoints.DefaultResolver()
	partitions := resolver.(endpoints.EnumPartitions).Partitions()
	return partitions
}
