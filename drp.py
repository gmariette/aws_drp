import boto3
import logging
import json
import sys
import concurrent.futures
import pandas as pd
import matplotlib.pyplot as plt
from datetime import datetime

#################################################################
#                                                               #
#   Title: drp_testing                                          #
#   Author: gmariette                                           #
#   Date: 17/03/2021                                            #
#   Language: Python3                                           #
#   Purpose: Fall AWS AZ of one region one by one               #
#   Scenario:                                                   #
#      - Identify and modify all ASG to remove an AZ            #
#      - Terminate all EC2 of an AZ                             #
#      - Failover a db if needed                                #
#      - Create an NACL which deny all [in|e]gress of our AZ    #
#      - Rollback                                               #
#                                                               #
#################################################################

# Setting the default log to info
# Configuring the output formatter
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')

def waitUserInput():
    answer = input('Do you want to continue ? (Y/N) \n')
    if answer in ['y', 'Y']:
        return True
    elif answer in ['n', 'N']:
        print('Exiting !')
        sys.exit(0)
    else:
        waitUserInput()

class DRP:
    def __init__(self, env):
        self.aws_accounts = {
            "MY_ACCOUNT": { "id": "xxxx", "role": "iam-role-name", "region": "eu-west-3" }
        }
        self.env = env
        self.logger = logging.getLogger('DRP')
        self.asg_backup = {}
        self.nacl_backup = {}
        self.df = pd.DataFrame()

    def dumpConfigToDisk(self, comp, az):
        '''
        DOCSTRING: Dump config file to disk as backup
        INPUT: Composant to backup
        OUTPUT: None
        '''
        filename = self.env + '_backup_' + comp + '_' + az + '.json'
        self.logger.info('Dumping backuped %ss config to file %s',comp.upper(), filename)
        with open(filename, 'w+') as f:
            if comp == 'asg':
                f.write(json.dumps(self.asg_backup))
            if comp == 'nacl':
                f.write(json.dumps(self.nacl_backup))

    def addActionToDf(self, action):
        '''
        DOCSTRING: Add action to DataFrame
        INPUT: Action
        OUTPUT: None
        '''
        changes = {
            "action": action,
            "timestamp": datetime.now().strftime("%d/%m/%Y %H:%M:%S")
        }
        self.df = self.df.append(changes, ignore_index=True)
        self.logger.debug('Action %s has been added to the df', action)

    def dumpDfToDisk(self):
        self.df.to_json(self.env + '_df.json')

    def graphPlots(self):
        '''
        DOCSTRING: Graph plot with our DF
        INPUT: None
        OUTPUT: None
        '''
        self.df.plot(kind="scatter", x="timestamp", y="action")
        self.logger.info('Saving the plots to disk')
        plt.savefig(self.env + 'timeline.jpg', bbox_inches='tight')

    def assumeRole(self, action):
        client = self.initStsClient()

        assumedRoleObject = client.assume_role(
        RoleArn="arn:aws:iam::"+self.aws_accounts[self.env]["id"]+":role/"+self.aws_accounts[self.env]["role"],
        RoleSessionName="Drp-" + action
            )

        credentials=assumedRoleObject['Credentials']

        ACCESS_KEY=credentials.get("AccessKeyId")
        SECRET_KEY=credentials.get("SecretAccessKey")
        SESSION_TOKEN=credentials.get("SessionToken")
        
        return ACCESS_KEY, SECRET_KEY, SESSION_TOKEN

    def initec2client(self, action):
        '''
        DOCSTRING: Return the ec2 client
        INPUT: None
        OUTPUT: boto3.client('ec2')
        '''
        ACCESS_KEY, SECRET_KEY, SESSION_TOKEN = self.assumeRole(action)

        self.logger.debug('Launching ec2 client with role %s on the account %s', self.aws_accounts[self.env]["role"], self.aws_accounts[self.env]["id"])
        return boto3.Session(
            region_name=self.aws_accounts[self.env]["region"],
            aws_access_key_id=ACCESS_KEY,
            aws_secret_access_key=SECRET_KEY,
            aws_session_token=SESSION_TOKEN
        ).client('ec2')

    def initStsClient(self):
        return boto3.client('sts')

    def initeRdsClient(self, action):
        '''
        DOCSTRING: Return the rds client
        INPUT: None
        OUTPUT: boto3.client('rds')
        '''
        ACCESS_KEY, SECRET_KEY, SESSION_TOKEN = self.assumeRole(action)

        self.logger.debug('Launching rds client with role %s on the account %s', self.aws_accounts[self.env]["role"], self.aws_accounts[self.env]["id"])
        return boto3.Session(
            region_name=self.aws_accounts[self.env]["region"],
            aws_access_key_id=ACCESS_KEY,
            aws_secret_access_key=SECRET_KEY,
            aws_session_token=SESSION_TOKEN
        ).client('rds')

    def initeASGClient(self, action):
        '''
        DOCSTRING: Return the autoscaling client
        INPUT: None
        OUTPUT: boto3.client('autoscaling')
        '''
        ACCESS_KEY, SECRET_KEY, SESSION_TOKEN = self.assumeRole(action)
        self.logger.debug('Launching asg client with role %s on the account %s', self.aws_accounts[self.env]["role"], self.aws_accounts[self.env]["id"])
        return boto3.Session(
            region_name=self.aws_accounts[self.env]["region"],
            aws_access_key_id=ACCESS_KEY,
            aws_secret_access_key=SECRET_KEY,
            aws_session_token=SESSION_TOKEN
        ).client('autoscaling')

    def describeAZ(self):
        '''
        DOCSTRING: Return the AZ list for a region
        INPUT: None
        OUTPUT: AZ list
        '''
        # Client init
        client = self.initec2client("DescribeAZ")
        response = client.describe_availability_zones()['AvailabilityZones']
        return [ x['ZoneName'] for x in response ]

    def describeInstances(self, az=None):
        '''
        DOCSTRING: List instances running in an AZ
        INPUT: Optionnal: az
        OUTPUT: Instances id
        '''
        # Client init
        client = self.initec2client("DescribeEC2")
        # Put some filters ON
        filters = []
        filters.append( { 'Name': 'instance-state-name', 'Values': ['running' ] } )
        if az is not None:
            self.logger.info('Identifying ec2 instances running on az: %s', az)
            filters.append( { 'Name': 'availability-zone', 'Values': [ az ] } )
        else:
            self.logger.info('Identifying ec2 instances running')
        # Init our return list
        instance_id_list = []
        response = client.describe_instances(
            Filters=filters,
        )['Reservations']
        for item in response:
            for instance in item['Instances']:
                instance_id_list.append(instance['InstanceId'])
                for tag in instance['Tags']:
                    if tag['Key'] == 'Name':
                        self.logger.info('Instance id %s (%s) running on az %s', instance['InstanceId'], tag['Value'], az)

        if instance_id_list:
            self.logger.info('Found %s ec2 instances running on az: %s', len(instance_id_list), az)
            return instance_id_list
        
        self.logger.info('No ec2 instances running !')

        return False

    def terminateInstance(self, instances_list):
        '''
        DOCSTRING: Terminate ec2 instances
        INPUT: instance_list
        OUTPUT: None
        '''
        # Client init
        client = self.initec2client("DescribeEC2")
        if not instances_list:
            self.logger.error('instance_list parameter not set !')
        self.logger.info('Killing instances %s', ', '.join(instances_list))
        response = client.terminate_instances(
            InstanceIds=instances_list,
        )['TerminatingInstances']

    def describeASG(self):
        '''
        DOCSTRING: List available ASGs
        INPUT: None
        OUTPUT: ASGs available
        '''
        # Client init
        client = self.initeASGClient("DescribeASG")
        return client.describe_auto_scaling_groups()['AutoScalingGroups']

    def saveASGConfig(self):
        '''
        DOCSTRING: Backup the ASGs configs
        INPUT: None
        OUTPUT: None
        '''
        self.logger.info('Backuping the current ASG state')
        for asg in self.describeASG():
            if self.asg_backup.get(asg['AutoScalingGroupName']) is None:
                self.asg_backup[asg['AutoScalingGroupName']] = {}
            self.asg_backup[asg['AutoScalingGroupName']]['AvailabilityZones'] = asg['AvailabilityZones'] 
            self.asg_backup[asg['AutoScalingGroupName']]['VPCZoneIdentifier'] = asg['VPCZoneIdentifier']
            self.asg_backup[asg['AutoScalingGroupName']]['Modified'] = False

    def restoreASGConfig(self):
        '''
        DOCSTRING: Restore the asg configs
        INPUT: None
        OUTPUT: None
        '''
        self.logger.info('Restoring initial ASG config')
        for asg in self.asg_backup:
            if self.asg_backup[asg]['Modified']:
                self.logger.info('Restoring ASG %s', asg)
                self.updateASGAZ(asg, self.asg_backup[asg]['AvailabilityZones'], self.asg_backup[asg]['VPCZoneIdentifier'])

    def updateASGAZ(self, asg, azs, vpc_zone_identifier):
        '''
        DOCSTRING: Update AZ for an asg
        INPUT: None
        OUTPUT: None
        '''
        # Client init
        client = self.initeASGClient("UpdateASG")
        self.logger.info('Modifying ASG %s - Setting new AZs: %s', asg, azs)
        response = client.update_auto_scaling_group(
            AutoScalingGroupName=asg,
            AvailabilityZones=azs,
            VPCZoneIdentifier=vpc_zone_identifier
        )
        self.asg_backup[asg]['Modified'] = True
        return response

    def describeSubnets(self, az):
        '''
        DOCSTRING: Describe subnets based on an az
        INPUT: None
        OUTPUT: Subnets
        '''
        # Client init
        client = self.initec2client("DescribeSubnets")
        subnet_list = []
        response = client.describe_subnets(
            Filters=[
                {
                    'Name': 'availabilityZone',
                    'Values': [
                        az,
                    ]
                }
            ]
        )['Subnets']
        for item in response:
            subnet_list.append(item['SubnetId'])
        return subnet_list

    def describeVPC(self):
        '''
        DOCSTRING: Describe VPC
        INPUT: None
        OUTPUT: VPCID
        '''
        # Client init
        client = self.initec2client("DescribeVPC")
        response = client.describe_vpcs()['Vpcs'][0]['VpcId']
        return response

    def describeNACL(self, subnets_list):
        '''
        DOCSTRING: Create an NACL
        INPUT: None
        OUTPUT: None
        '''
        # Client init
        client = self.initec2client("DescribeNACL")   
        nacl_association_ids = []     
        response = client.describe_network_acls(    
            Filters=[
            {
                'Name': 'association.subnet-id',
                'Values': subnets_list
            },
        ]
        )['NetworkAcls'][0]['Associations']

        self.nacl_backup = response
        initial_nacl_id = ""

        for item in response:
            if item['SubnetId'] in subnets_list:
                nacl_association_ids.append({"NetworkAclAssociationId" : item['NetworkAclAssociationId'], "NetworkAclId": item['NetworkAclId'], 'SubnetId': item['SubnetId']})
                if initial_nacl_id == "":
                    initial_nacl_id = item['NetworkAclId']
                if initial_nacl_id == item['NetworkAclId']:
                    continue
                if initial_nacl_id != item['NetworkAclId']:
                    self.logger.error('More than one NACL found !')

        return initial_nacl_id, nacl_association_ids

    def createNACL(self, vpc_id, az):
        '''
        DOCSTRING: Create an NACL
        INPUT: None
        OUTPUT: None
        '''
        # Client init
        client = self.initec2client("CreateNACL")
        response = client.create_network_acl(
            VpcId=vpc_id,
            TagSpecifications=[
                {
                    'ResourceType': 'network-acl',
                    'Tags': [
                        {
                            'Key': 'Name',
                            'Value': 'DRP-NACL-FOR-AZ-'+ az.upper()
                        },
                    ]
                }
            ]
        )['NetworkAcl']['NetworkAclId']
        self.logger.info('NACL created: %s', response)
        return response

    def decribeNACLEntries(self, nacl_id):
        '''
        DOCSTRING: Describe NACL entries
        INPUT: None
        OUTPUT: None
        '''
        # Client init
        client = self.initec2client("decribeNACLEntries")
        response = client.describe_network_acls(
            NetworkAclIds=[nacl_id]
        )['NetworkAcls']
        return response

    def createDenyAllNACLEntry(self, nacl_id, egress=False):
        '''
        DOCSTRING: Create a NACL entry
        INPUT: None
        OUTPUT: None
        '''
        # Client init
        client = self.initec2client("createDenyAllNACLEntry")
        if egress:
            self.logger.info('Creating a DENY ALL rule (INGRESS) on nacl: %s', nacl_id)
        else:
            self.logger.info('Creating a DENY ALL rule (EGRESS) on nacl: %s', nacl_id)
        response = client.create_network_acl_entry(
            CidrBlock='0.0.0.0/0',
            Egress=egress,
            NetworkAclId=nacl_id,
            PortRange={
                'From': 0,
                'To': 65535
            },
            Protocol='-1',
            RuleAction='deny',
            RuleNumber=100
        )
        if response['ResponseMetadata']['HTTPStatusCode'] == 200:
            self.logger.info('Rule created successfully')
            return True
        else:
            self.logger.error('Problem while creating rule')
            return False

    def replaceNACLAssociation(self, nacl_id, association_id):
        '''
        DOCSTRING: Replace NACL association
        INPUT: nacl_id, association_id
        OUTPUT: None
        '''
        # Client init
        client = self.initec2client("ReplaceNACLAssociation")
        self.logger.info('Changing NACL association id %s to the NACL id %s', association_id, nacl_id)
        response = client.replace_network_acl_association(
            AssociationId=association_id,
            NetworkAclId=nacl_id
        )['NewAssociationId']
        self.logger.info('New association id: %s', response)
        return response

    def deleteNACL(self, nacl_id):
        '''
        DOCSTRING: Delete an NACL
        INPUT: None
        OUTPUT: None
        '''
        # Client init
        client = self.initec2client("createDenyAllNACLEntry")
        response = client.delete_network_acl(
            NetworkAclId=nacl_id
        )
        if response['ResponseMetadata']['HTTPStatusCode'] == 200:
            self.logger.info('Deleted NACL %s', nacl_id)
        else:
            self.logger.error('Problem while deleting NACL %s', nacl_id)

    def describeRDSinstances(self):
        '''
        DOCSTRING: List available rds instances
        INPUT: None
        OUTPUT: RDS db available
        '''
        # Client init
        client = self.initeRdsClient("Describe")
        self.logger.info('Describe RDS instance for env %s requested', self.env)
        response = client.describe_db_instances()['DBInstances']
        env_filter = ''.join(self.env.split('-')).lower()
        db_list = { x['DBInstanceIdentifier'] : { 'MultiAZ': x['MultiAZ'], 'Subnet': x['AvailabilityZone'] } for x in response if env_filter in x['DBInstanceIdentifier'] }
        return db_list

    def restartRDSinstance(self, db_identifier, failover):
        '''
        DOCSTRING: Restart a db instance and force AZ failover
        INPUT: None
        OUTPUT: RDS db available
        '''
        # Client init
        client = self.initeRdsClient("Restart")
        self.logger.info('Restarting the RDS instance %s', db_identifier)
        response = client.reboot_db_instance(
            DBInstanceIdentifier=db_identifier,
            ForceFailover=failover
        )

    def waitRDSavailable(self, db_identifier):
        # Client init
        client = self.initeRdsClient("Waiter")
        waiter = client.get_waiter('db_instance_available')   
        self.logger.info('Waiting the good start of %s', db_identifier)
        waiter.wait(
            DBInstanceIdentifier=db_identifier
        )

if __name__ == "__main__":
    c = DRP("MY_ACCOUNT")
    for az in c.describeAZ():
        main_logger = logging.getLogger('MAIN')
        main_logger.info('Begin of the operations on az: %s', az)

        waitUserInput()
        c.addActionToDf("[{} / {}] Begin of the operations".format(c.env, az))

        # 0) Create a new az_list without our AZ

        remaining_az = [ x for x in c.describeAZ() if x != az]

        # 1) Identify the subnets from the az

        subnet_list = c.describeSubnets(az)
        main_logger.info('Following subnets (%s) will be removed from ASGs: %s',len(subnet_list), ' - '.join(subnet_list))

        # 2) Create a NACL
        # 2a) Identify VPC id

        vpc_id = c.describeVPC()

        # 2b) Creation of the network ACL
        main_logger.info('Creating a network ACL to block all trafic from %s', az)
        c.addActionToDf("[{} / {}] NACL creation".format(c.env, az))
        drp_network_acl = c.createNACL(vpc_id, az)

        # 2c) Get the current list of network ACL associations for these subnets
        initial_nacl_id, initial_nacl_association_ids = c.describeNACL(subnet_list)
        c.dumpConfigToDisk('nacl', az)
        
        # 2d) Associate desirated subnets with new network ACL

        new_nacl_association = []
        for nacl_association_id in initial_nacl_association_ids:
            new_nacl_association.append({"NetworkAclAssociationId" : c.replaceNACLAssociation(drp_network_acl, nacl_association_id['NetworkAclAssociationId']), "NetworkAclId": drp_network_acl, 'SubnetId': nacl_association_id['SubnetId']})

        
        if c.createDenyAllNACLEntry(drp_network_acl):
            main_logger.info('Ingress rule DENY all created for NACL %s', drp_network_acl)
            if c.createDenyAllNACLEntry(drp_network_acl, egress=True):
                main_logger.info('Egress rule DENY all created for NACL %s', drp_network_acl)

        # 3a) Saving the ASGs configs

        c.saveASGConfig()
        c.addActionToDf("[{} / {}] Save of ASGs configs".format(c.env, az))
        c.dumpConfigToDisk('asg', az)

        # 3b) Update the ASGs by removing the subnets

        for item in c.describeASG():
            if c.env.replace('-','') in item['AutoScalingGroupName']:
                asg_subnets = (item['VPCZoneIdentifier'].split(','))
                common_subnet = ''.join([ x for x in asg_subnets if x in subnet_list])
                new_subnet_list = ','.join([ x for x in asg_subnets if x not in subnet_list])
                main_logger.info('The subnet %s will be removed from ASG %s', item['AutoScalingGroupName'], common_subnet)
                c.updateASGAZ(item['AutoScalingGroupName'], remaining_az, new_subnet_list)
                c.addActionToDf("[{} / {}] Update of ASG {} config".format(c.env, az, item['AutoScalingGroupName']))

        # 4) Terminating instances on our AZ (force kill in case they are not part of an ASG !)

        instances_list = c.describeInstances(az)

        if instances_list:
            c.terminateInstance(instances_list)
            for instance in instances_list:
                c.addActionToDf("[{} / {}] Terminating instance {}".format(c.env, az, instance))

        # 5) Trigger DBs failovers which are in the AZ we want to stop (multithreaded)

        db_list = c.describeRDSinstances()
        restarted_dbs = []
        with concurrent.futures.ThreadPoolExecutor() as executor:
            for db in db_list:
                if db_list[db]['Subnet'] == az:
                    main_logger.info('Database %s is in fall AZ !', db)
                    if db_list[db]['MultiAZ']:
                        main_logger.info('Triggering a db failover.')
                        c.addActionToDf("[{} / {}] Failover DB {}".format(c.env, az, db))
                        threadStartRDS = executor.submit(c.restartRDSinstance, db, True)
                        restarted_dbs.append(db)
                    else:
                        main_logger.error('This database is not multi AZ !')
        if restarted_dbs:
            with concurrent.futures.ThreadPoolExecutor() as executor:
                for db in restarted_dbs:
                    threadWaitRDS = executor.submit(c.waitRDSavailable, db)

        ### ROLLBACK AZ

        main_logger.info('Begin rollback of operations made on az: %s', az)

        waitUserInput()
        c.addActionToDf("[{} / {}] Begin rollback of the operations".format(c.env, az))

        # 1) Restore NACL parameters

        c.addActionToDf("[{} / {}] NACL rollback".format(c.env, az))
        for nacl_association_id in new_nacl_association:
            main_logger.info('Restoring subnet %s to main NACL (%s)', nacl_association_id['SubnetId'], initial_nacl_id)
            c.replaceNACLAssociation(initial_nacl_id, nacl_association_id['NetworkAclAssociationId'])

        # 2) Delete DRP_NACL

        c.deleteNACL(drp_network_acl)

        # 3) Restore ASG config

        c.restoreASGConfig()
        c.addActionToDf("[{} / {}] Restore ASGs configs".format(c.env, az))
        c.dumpDfToDisk()



    # Dump the DF thing
    c.graphPlots()
