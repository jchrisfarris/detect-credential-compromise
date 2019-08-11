import boto3
from botocore.exceptions import ClientError
import json
import os
import datetime

import logging
logger = logging.getLogger()
logger.setLevel(logging.INFO)
logging.getLogger('botocore').setLevel(logging.WARNING)
logging.getLogger('boto3').setLevel(logging.WARNING)


def handler(event, context):

    output_json = {}
    output_json['instances'] = {}
    output_json['all_ips'] = []
    output_json['nat_gateways'] = {}

    try:
        ec2_client = boto3.client('ec2')

        interfaces = get_all_interfaces(ec2_client)
        for eni in interfaces:
            if eni['InterfaceType'] != 'nat_gateway':
                continue
            if 'PublicIp' not in eni['Association']:
                continue

            if eni['VpcId'] not in output_json['nat_gateways']:  # make it an array
                output_json['nat_gateways'][eni['VpcId']] = []

            output_json['nat_gateways'][eni['VpcId']].append(eni['Association']['PublicIp'])
            output_json['all_ips'].append(eni['Association']['PublicIp'])

        for reservation in get_all_instances(ec2_client):
            for instance in reservation['Instances']:
                instance_id = instance['InstanceId']
                vpc_id = instance['VpcId']
                output_json['instances'][instance_id] = []

                if 'PublicIpAddress' in instance:
                    public_ip = instance['PublicIpAddress']
                    output_json['instances'][instance_id].append(public_ip)
                    output_json['all_ips'].append(public_ip)

                if vpc_id in output_json['nat_gateways']:
                    output_json['instances'][instance_id] += output_json['nat_gateways'][vpc_id]

        output_json['data_collected'] = str(datetime.datetime.now())

    except ClientError as e:
        logger.critical("AWS Error getting info: {}".format(e))
        raise
    except Exception as e:
        logger.critical("{}".format(e))
        raise

    s3client = boto3.client('s3')
    try:
        s3client.put_object(
            Body=json.dumps(output_json, sort_keys=True, default=str, indent=2),
            Bucket=os.environ['BUCKET'],
            ContentType='application/json',
            Key=os.environ['OBJECT'],
        )
        return(event)
    except ClientError as e:
        logger.error("Unable to save object {}: {}".format(os.environ['OBJECT'], e))
        raise

def get_all_instances(ec2_client):
    output = []
    filters = [{'Name': 'instance-state-name', 'Values': ['running']}]
    response = ec2_client.describe_instances(Filters=filters)
    while 'NextToken' in response:
        output += response['Reservations']
        response = ec2_client.describe_instances(Filters=filters, NextToken=response['NextToken'])
    output += response['Reservations']
    return(output)


def get_all_interfaces(ec2_client):
    interfaces = []
    response = ec2_client.describe_network_interfaces()
    while 'NextToken' in response:  # Gotta Catch 'em all!
        interfaces += response['NetworkInterfaces']
        response = ec2_client.describe_network_interfaces(NextToken=response['NextToken'])
    interfaces += response['NetworkInterfaces']
    return(interfaces)
### END OF CODE ###


#######################################################################################################################
# This exists for local testing
if __name__ == '__main__':

    # Process Arguments
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--debug", help="print debugging info", action='store_true')
    parser.add_argument("--error", help="print error info only", action='store_true')
    parser.add_argument("--bucket", help="Bucket with Instance Details", required=True)
    parser.add_argument("--object-key", help="Object Key with Instance Details", required=True)


    args = parser.parse_args()

    # Logging idea stolen from: https://docs.python.org/3/howto/logging.html#configuring-logging
    # create console handler and set level to debug
    ch = logging.StreamHandler()
    if args.debug:
        ch.setLevel(logging.DEBUG)
    elif args.error:
        ch.setLevel(logging.ERROR)
    else:
        ch.setLevel(logging.INFO)
    # create formatter
    # formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    formatter = logging.Formatter('%(name)s - %(levelname)s - %(message)s')
    # add formatter to ch
    ch.setFormatter(formatter)
    # add ch to logger
    logger.addHandler(ch)

    event = {}

    if args.debug:
        os.environ['DEBUG'] = str(args.debug)
    os.environ['BUCKET'] = args.bucket
    os.environ['OBJECT'] = args.object_key

    # Wrap in a handler for Ctrl-C
    try:
        rc = handler(event, None)
        print("Lambda returned {}".format(rc))
    except KeyboardInterrupt:
        exit(1)