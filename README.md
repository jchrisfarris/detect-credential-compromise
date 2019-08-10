# Detecting Credential Compromise
CloudFormation Template and Lambda to detect if Instance Profile credentials are being used outside your AWS Account.

What's in your CloudTrail?


## Motivation
The running theory on the Capital One hack was the attacker exposed a SSRF in a Capital One instance, captured legitimate credentials from the EC2 MetaData service, and then used those credentials in another AWS account to exfiltrate 100m credit card applications from S3.

While AWS GuardDuty has a detection for when Instance Profile credentials are used outside of AWS, it does not detect if the credentials are used outside of _your_ AWS account.

## How does it work

An Inventory Lambda runs every 10 minutes and gathers up all the EC2 Instance PublicIps and all the VPC NatGateways in the account. This is saved to S3 and becomes the known list of IPs we'd expect an Instance Profile's API calls to originate from.

We leverage CloudWatch Events to forward all API Calls that match `userIdentity->type->AssumeRole` to an SQS Queue. A Lambda is polling that queue and processing events. If it sees an event from a `sourceIPAddress` that's not in the list of known addresses, it is raised as a security event.

When the Lambda flags an issue, it will publish the message to an SNS Topic you specify as a parameter of the CF Template. This allows for the centralized gathering of these detected events and provides an easy way to push them to Slack, Splunk or just email.

## Deployment



## Challenges

There are a few challenges with this approach. This stack itself generates events, and those events trigger this function. The CloudWatch Events pattern matching is not complex. I cannot use a regex to detect only Instance Profile credentials. As a result, there is less logging than would be desired, and the lambda will compare the event `accessKeyId` to it's own access key (via the AWS_ACCESS_KEY_ID environment variable), and stop processing the event without logging anything (because writing a log generates another event).

The Event Pattern is:
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

There is a default reserve concurrency limit of 100 to prevent this function from throttling other functions in the region.

## Credit

The initial idea for this tool was [Will Bengston](https://twitter.com/__muscles)'s 2018 post on [Detecting Credential Compromise in AWS](https://medium.com/netflix-techblog/netflix-cloud-security-detecting-credential-compromise-in-aws-9493d6fd373a)

This tool is non-intrusive and doesn't require any enterprise tooling. My initial attempt to address the Capital One breach was to leverage a bunch of centralized enterprise tools. Once I took a step back to figure out how I'd protect my own AWS accounts, I realized I was trying to protect _everything_ rather than protecting _anything_.