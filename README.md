# Detecting Credential Compromise
CloudFormation Template and Lambda to detect if Instance Profile credentials are being used outside your AWS Account.

What's in your CloudTrail?


## Motivation
The running theory on the Capital One hack was the attacker exposed a SSRF in a Capital One instance, captured legitimate credentials from the EC2 MetaData service, and then used those credentials in another AWS account to exfiltrate 100m credit card applications from S3.

While AWS GuardDuty has a detection for when Instance Profile credentials are used outside of AWS, it does not detect if the credentials are used outside of _your_ AWS account.

## What is this?

This repo contains two CloudFormation Templates that will help to detect the usage of AWS IAM Instance profiles outside of the AWS Account to which they are assigned.

The first template leverages SQS and CloudWatch Events and is designed for a small install with minimal activity and cost. This solution is regional and CloudWatch Events doesn't monitor Get* List* and Describe* events (which is what the Capital One hacker used to exfil data).

The second template leverages Kinesis Streams and the CloudWatch Logs group that CloudTrail sends all events to. This template provides much greater coverage in that it covers all regions and read-only events (assuming CloudTrail is properly configured). The cost of the Kinesis stream starts at about $78/mo.

## How does it work

An Inventory Lambda runs every 10 minutes and gathers up all the EC2 Instance PublicIps and all the VPC NatGateways in the account. This is saved to S3 and becomes the known list of IPs we'd expect an Instance Profile's API calls to originate from.

The Kinesis Stream or SQS Queue invokes a Detection lambda that looks at the `sourceIPAddress` in the event and compares it to the list of expected IP addresses for the instance and in the AWS account.

When the Lambda flags an issue, it will publish the message to an SNS Topic you specify as a parameter of the CF Template. This allows for the centralized gathering of these detected events and provides an easy way to push them to Slack, Splunk or just email.

Events are filtered based on `userIdentity.type` being `AssumedRole`. `sourceIPAddress`es that are `*.amazonaws.com` are also excluded, as these are calls made by AWS on your behalf.


## Deployment



## Alerts
This is the json we send to the SNS Topic
```json
{
  "type": "BadSource",
  "message": "Event from IP 99.161.198.92 for instance i-088eFNORDBLAH is not from expected addresses",
  "expected_ips": [
    "52.204.226.45"
  ],
  "instance_id": "i-088eFNORDBLAH",
  "uniq_id": "i-088eFNORDBLAH-99.161.198.92",
  "CloudTrailEvent": {
    "eventVersion": "1.05",
    "userIdentity": {
      "type": "AssumedRole",
      "principalId": "AROAIFNORD:i-088eFNORDBLAH",
      "arn": "arn:aws:sts::123456789012:assumed-role/pacu-instance-InstanceIamInstanceRole-1RSL9E7QA5QCI/i-088eFNORDBLAH",
      "accountId": "123456789012",
      "accessKeyId": "ASIAQ2AHBLAH",
      "sessionContext": {
        "attributes": {
          "mfaAuthenticated": "false",
          "creationDate": "2019-08-10T20:39:26Z"
        },
        "sessionIssuer": {
          "type": "Role",
          "principalId": "AROAIFNORD",
          "arn": "arn:aws:iam::123456789012:role/pacu-instance-InstanceIamInstanceRole-1RSL9E7QA5QCI",
          "accountId": "123456789012",
          "userName": "pacu-instance-InstanceIamInstanceRole-1RSL9E7QA5QCI"
        }
      }
    },
    "eventTime": "2019-08-11T01:25:22Z",
    "eventSource": "sts.amazonaws.com",
    "eventName": "GetCallerIdentity",
    "awsRegion": "us-east-1",
    "sourceIPAddress": "99.161.198.92",
    "userAgent": "aws-cli/1.16.190 Python/3.7.3 Darwin/16.7.0 botocore/1.12.180",
    "requestParameters": null,
    "responseElements": {
    },
    "requestID": "e329713b-BLAH",
    "eventID": "5081622b-BLAH",
    "eventType": "AwsApiCall",
    "recipientAccountId": "123456789012"
  }
}
```

The `uniq_id` is created to allow you to deduplicate messages in your downstream processing engine.

### False Positives

- Perhaps EKS is doing something with these instance profiles from an AWS owned IP Space. I see a lot of `GetCallerIdentity` calls being flagged in EKS.


## Challenges

There are a few challenges with this approach. This stack itself generates events, and those events trigger this function.

The Kinesis solution requires that CloudTrail is delivering to a CloudWatch Logs group, and each CloudWatch Logs group can have only one subscription filter and Kinesis stream. So if you're already doing something with your CloudTrail Events in CloudWatch logs, this solution won't work out of the box.

When using CloudWatch Events, the pattern matching is not complex. I cannot use a regex to detect only Instance Profile credentials. As a result, there is less logging than would be desired, and the lambda will compare the event `accessKeyId` to it's own access key (via the AWS_ACCESS_KEY_ID environment variable), and stop processing the event without logging anything (because writing a log generates another event).

The Cloud Watch Event Pattern is:
```json
{
  "account": [
    "123456789012"
  ],
  "detail": {
    "userIdentity": {
      "type": [
        "AssumedRole"
      ]
    }
  }
}
```
Any advice on how to scope this down further to only capture Instance Profile triggered events would be desired (and would lower the invocation counts on Lambda)

The CloudWatch Logs Filter is better:
```
{($.userIdentity.type = AssumedRole) && ($.eventType = AwsApiCall) && ($.sourceIPAddress != *.amazonaws.com)}
```

For both solutions a default reserve concurrency limit of 100 to prevent this function from throttling other functions in the region.



## Credit

The initial idea for this tool was [Will Bengston](https://twitter.com/__muscles)'s 2018 post on [Detecting Credential Compromise in AWS](https://medium.com/netflix-techblog/netflix-cloud-security-detecting-credential-compromise-in-aws-9493d6fd373a)

This tool is non-intrusive and doesn't require any enterprise tooling. My initial attempt to address the Capital One breach was to leverage a bunch of centralized enterprise tools. Once I took a step back to figure out how I'd protect my own AWS accounts, I realized I was trying to protect _everything_ rather than protecting _anything_.