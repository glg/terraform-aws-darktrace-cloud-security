# terraform-aws-darktrace-cloud-security

**Please note: this module is not intended to be directly consumed. For usage instructions please consult your Darktrace/Cloud setup guide.**

## Introduction

This repository offers terraform modules for deploying various resources required by Darktrace/Cloud to enable DETECT and RESPOND features for your Amazon Web Services (AWS) Cloud environment:

- **Core**: allows Darktrace/Cloud to monitor your AWS Cloud environment
- **Costing**: allows Darktrace/Cloud to perform cost analysis of various resources within your AWS Cloud environment
- **Flow Logs**: allows Darktrace/Cloud to analyse network traffic within your AWS Cloud environment
- **RESPOND**: allows Darktrace/Cloud to perform RESPOND actions against misconfigured resources within your AWS Cloud environment

## Usage

### Before you start

You must be an active Darktrace/Cloud customer, and have relevant permissions on your AWS account(s) to apply the resources this terraform module will create

### Retrieving values

Follow the Account Setup guide on your Darktrace/Cloud UI. Upon completion, you will be provided with the necessary values required to use the relevant terraform module(s). Please do not modify the values provided to you by the Account Setup guide.
