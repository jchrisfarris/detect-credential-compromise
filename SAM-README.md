# Detecting Credential Compromise
CloudFormation Template and Lambda to detect if Instance Profile credentials are being used outside your AWS Account.

What's in your CloudTrail?

## Motivation
The running theory on the Capital One hack was the attacker exposed a SSRF in a Capital One instance, captured legitimate credentials from the EC2 MetaData service, and then used those credentials in another AWS account to exfiltrate 100m credit card applications from S3.

While AWS GuardDuty has a detection for when Instance Profile credentials are used outside of AWS, it does not detect if the credentials are used outside of _your_ AWS account.

## What is this?

This serverless app deployes a kinesis stream and some lambda that will help to detect the usage of AWS IAM Instance profiles outside of the AWS Account to which they are assigned.

## How does it work

An Inventory Lambda runs every 10 minutes and gathers up all the EC2 Instance PublicIps and all the VPC NatGateways in the account. This is saved to S3 and becomes the list of known IPs we'd expect an Instance Profile's API calls to originate from.

The Kinesis Stream invokes a Detection lambda that looks at the `sourceIPAddress` in the event and compares it to the list of expected IP addresses for the instance and in the AWS account.

When the Lambda flags an issue, it will publish the message to an SNS Topic you specify as a parameter to the application. This allows for the centralized gathering of these detected events and provides an easy way to push them to Slack, Splunk or just email.

Events are filtered based on `userIdentity.type` being `AssumedRole`. Any `sourceIPAddress` that contains `*.amazonaws.com` are also excluded, as these are calls made by AWS on your behalf.

## Credit

The initial idea for this tool was [Will Bengston](https://twitter.com/__muscles)'s 2018 post on [Detecting Credential Compromise in AWS](https://medium.com/netflix-techblog/netflix-cloud-security-detecting-credential-compromise-in-aws-9493d6fd373a)

This tool is non-intrusive and doesn't require any enterprise tooling. My initial attempt to address the Capital One breach was to leverage a bunch of centralized enterprise tools. Once I took a step back to figure out how I'd protect my own AWS accounts, I realized I was trying to protect _everything_ rather than protecting _anything_.

