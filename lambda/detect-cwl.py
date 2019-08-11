import boto3
import re
import json
import os
import base64
import gzip

import logging
logger = logging.getLogger()
logger.setLevel(logging.INFO)
logging.getLogger('botocore').setLevel(logging.WARNING)
logging.getLogger('boto3').setLevel(logging.WARNING)


def handler(event, context):
  re_principal = re.compile(r'AR[^\:]+\:i\-[0-9a-z]+')
  instance_data = []
  logger.debug(f"Event: {event}")

  try:
    logger.info(f"Received {len(event['Records'])} kinesis events")
    for record in event['Records']:
      cwl_str = gzip.decompress(base64.b64decode(record["kinesis"]["data"]))
      logger.debug(f"Log String: {cwl_str}")
      cwl_records = json.loads(cwl_str)
      if cwl_records['messageType'] != "DATA_MESSAGE":
        continue

      logger.info(f"Received {len(cwl_records['logEvents'])} CW Log events")
      for log_event in cwl_records['logEvents']:
        cwevent = json.loads(log_event['message'])

      if cwevent['eventType'] != "AwsApiCall":
        logger.debug(f"Got Event type that should have been filtered: {cwevent}")
        continue

      # Filter out stuff
      if "amazonaws.com" in cwevent['sourceIPAddress']:
        continue

      logger.debug("cwevent: {}".format(json.dumps(cwevent, sort_keys=True)))

      principal = cwevent['userIdentity']['principalId']
      if not re_principal.match(principal):
        logger.debug(f"Principal {principal} is not an instance profile role. Skipping")
        continue

      if instance_data is not None:  # Wait to get instance data till we need it
        instance_data = get_instance_data(os.environ['BUCKET'], os.environ['OBJECT'])

        # Extract the instance Id
        (role_id, instance_id) = principal.split(":")
        source_ip = cwevent['sourceIPAddress']
        region = cwevent['awsRegion']

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
        return(200)
  except Exception as e:
    logger.critical(f"Exception {e} processing")
    raise

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
