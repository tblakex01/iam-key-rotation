import boto3

# Lazily initialized AWS clients
iam_client = None
ses_client = None
cloudwatch_client = None


def get_iam_client():
    """Return a boto3 IAM client, creating it if needed."""
    global iam_client
    if iam_client is None:
        iam_client = boto3.client("iam")
    return iam_client


def get_ses_client():
    """Return a boto3 SES client, creating it if needed."""
    global ses_client
    if ses_client is None:
        ses_client = boto3.client("ses")
    return ses_client


def get_cloudwatch_client():
    """Return a boto3 CloudWatch client, creating it if needed."""
    global cloudwatch_client
    if cloudwatch_client is None:
        cloudwatch_client = boto3.client("cloudwatch")
    return cloudwatch_client
