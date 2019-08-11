import boto3
import re
import json
import os

import logging
logger = logging.getLogger()
logger.setLevel(logging.INFO)
logging.getLogger('botocore').setLevel(logging.WARNING)
logging.getLogger('boto3').setLevel(logging.WARNING)


def handler(event, context):
    if 'DEBUG' in os.environ and os.environ['DEBUG'] == "True":
        logger.setLevel(logging.DEBUG)
    re_principal = re.compile(r'AR[^\:]+\:i\-[0-9a-z]+')
    instance_data = []

    try:
        for record in event['Records']:
            cwevent = json.loads(record['body'])

            # Filter out stuff
            if (cwevent['detail']['userIdentity']['accessKeyId'] == os.environ['AWS_ACCESS_KEY_ID'] or
                    cwevent['detail']['userIdentity']['type'] == "AWSService" or
                    "amazonaws.com" in cwevent['detail']['sourceIPAddress']):
                if len(event['Records']) == 1:
                    return(200)
                else:
                    continue

            logger.debug("cwevent: {}".format(json.dumps(cwevent, sort_keys=True)))

            principal = cwevent['detail']['userIdentity']['principalId']
            if not re_principal.match(principal):
                logger.debug(f"Principal {principal} is not an instance profile role. Skipping")
                continue

            if instance_data is not None:  # Wait to get instance data till we need it
                instance_data = get_instance_data(os.environ['BUCKET'], os.environ['OBJECT'])

            # Extract the instance Id
            (role_id, instance_id) = principal.split(":")
            source_ip = cwevent['detail']['sourceIPAddress']
            region = cwevent['detail']['awsRegion']

            if instance_id not in instance_data['instances']:
                logger.info(f"Instance {instance_id} is not in my database of instances")
                send_event("InstanceMissing", cwevent, f"Instance {instance_id} is not in my database of instances", instance_id, source_ip, [])
                continue

            if source_ip in instance_data['instances'][instance_id]:
                logger.debug(f"Event is from expected IP: {cwevent}")
                continue

            if source_ip in instance_data['all_ips']:
                logger.info(f"Event is not from expected ip, but from an account IP: {cwevent}")
                continue

            logger.error(f"Event from IP {source_ip} for instance {instance_id} is not from expected addresses: {cwevent}")
            send_event("BadSource", cwevent, f"Event from IP {source_ip} for instance {instance_id} is not from expected addresses", instance_id, source_ip, instance_data['instances'][instance_id])

        logger.debug(f"Received {len(event['Records'])} events")
        return(200)
    except Exception as e:
        logger.critical(f"Exception {e} processing cwevent {cwevent}")
        return(200)  # Return for a good status so we purge the bad event


def send_event(eventtype, cwevent, message, instance_id, source_ip, expected_ips):
    try:
        client = boto3.client('sns', region_name=os.environ['TOPIC_REGION'])
        snsmessage = {
            'type': eventtype,
            'CloudTrailEvent': cwevent,
            'message': message,
            'expected_ips': expected_ips,
            'instance_id': instance_id,
            'uniq_id': f"{instance_id}-{source_ip}"     # We can dedup events on this later
        }
        response = client.publish(
            TopicArn=os.environ['TOPICARN'],
            Message=json.dumps(snsmessage),
            Subject=f'Potential Credential Compromise for {instance_id}',
        )
    except Exception as e:
        logger.critical(f"Unable to send message to SNS: {e} \n{snsmessage}")
        raise

def get_instance_data(bucket, obj_key):
    '''get the object to index from S3 and return the parsed json'''
    s3 = boto3.client('s3')
    response = s3.get_object(
        Bucket=bucket,
        Key=obj_key
    )
    return(json.loads(response['Body'].read()))
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
    parser.add_argument("--event-file", help="Test Event File", required=True)

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

    f = open(args.event_file, "r")
    contents = f.read()

    event = json.loads(contents)

    os.environ['DEBUG'] = str(args.debug)
    os.environ['BUCKET'] = args.bucket
    os.environ['OBJECT'] = args.object_key

    # Wrap in a handler for Ctrl-C
    try:
        rc = handler(event, None)
        print("Lambda returned {}".format(rc))
    except KeyboardInterrupt:
        exit(1)
