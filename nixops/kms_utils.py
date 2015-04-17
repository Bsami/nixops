# -*- coding: utf-8 -*-

import os
from boto import kms
import time
import random
import nixops.util

from kms.exceptions import *
from boto.exception import SQSError
from boto.exception import BotoServerError

def fetch_aws_secret_key(access_key_id):
    """
    Fetch the secret access key corresponding to the given access key ID from the environment or 
    from ~/.ec2-keys or from ~/.aws/credentials
    """
    secret_access_key = os.environ.get('EC2_SECRET_KEY') or os.environ.get('AWS_SECRET_ACCESS_KEY')
    path = os.path.expanduser("~/.ec2-keys")
    path2 = os.path.expanduser("~/.aws/credentials")
    if os.path.isfile(path):
        f = open(path, 'r')
        contents = f.read()
        f.close()
        for l in contents.splitlines():
            l = l.split("#")[0] # drop comments
            w = l.split()
            if len(w) < 2 or len(w) > 3: continue
            if len(w) == 3 and w[2] == access_key_id:
                access_key_id = w[0]
                secret_access_key = w[1]
                break
            if w[0] == access_key_id:
                secret_access_key = w[1]
                break
    elif os.path.isfile(path2):
        f = open(path2, 'r')
        contents = f.read()
        f.close()
        for l in contents.splitlines():
            l = l.split("#")[0] # drop comments
            w = l.split()
            if len(w) < 2 or len(w) > 3: continue
            if len(w) == 3 and w[2] == access_key_id:
                access_key_id = w[0]
                secret_access_key = w[1]
                break
            if w[0] == access_key_id:
                secret_access_key = w[1]
                break

    if not secret_access_key:
        raise Exception("please set $EC2_SECRET_KEY or $AWS_SECRET_ACCESS_KEY, or add the key for ‘{0}’ to '~/.ec2-keys' or to '~/.aws/credentials'"
                        .format(access_key_id))

    return (access_key_id, secret_access_key)


def connect(region, access_key_id):
    """Connect to the specified KMS region using the given access key."""
    kms_regions = []
    for i in kms.regions():
        kms_regions.append(i.name) # get the AWS KMS supported regions

    assert region in kms_regions
    (access_key_id, secret_access_key) = fetch_aws_secret_key(access_key_id)
    conn = boto.kms.connect_to_region(region_name=region, aws_access_key_id=access_key_id, aws_secret_access_key=secret_access_key)
    if not conn:
        raise Exception("invalid KMS region ‘{0}’ or AWS credentials".format(region))
    return conn


def get_access_key_id():
    return os.environ.get('EC2_ACCESS_KEY') or os.environ.get('AWS_ACCESS_KEY_ID')


def retry(f, error_codes=[], logger=None):
    """
        Retry function f up to 7 times. If error_codes argument is empty list, retry on all KMS response errors,
        otherwise, only on the specified error codes.
    """

    def handle_exception(e):
        if i == num_retries or (error_codes != [] and not e.error_code in error_codes):
            raise e
        if logger is not None:
            logger.log("got (possibly transient) KMS error code ‘{0}’, retrying...".format(e.error_code))

    i = 0
    num_retries = 7
    while i <= num_retries:
        i += 1
        next_sleep = 5 + random.random() * (2 ** i)

        try:
            return f()
        except KMSInternalException as e:
            handle_exception(e)
        except SQSError as e:
            handle_exception(e)
        except BotoServerError as e:
            if e.error_code == "RequestLimitExceeded":
                num_retries += 1
            else:
                handle_exception(e)
        except Exception as e:
            raise e

        time.sleep(next_sleep)


def get_kms_key_by_id(conn, key_id, allow_missing=False):
    """Get kms key object by key id."""
    try:
        all_keys = conn.list_keys()['Keys']
        for key in all_keys :
            if key['KeyId'] == key_id :
                return key
    except kms.exceptions.NotFoundException as e:
        if e : raise Exception("unable to find key ‘{0}’".format(key_id))
    return None


def wait_for_key_available(conn, key_id, logger, states=['Creating', 'Created']):
    """Wait for a KMS key to become available."""

    logger.log_start("waiting for key ‘{0}’ to become available... ".format(key_id))

    def check_available():
        key = get_kms_key_by_id(conn, key_id, allow_missing=True)
        self.logger.log_continue("[{0}] ".format('Processing'))

    nixops.util.check_wait(check_available, max_tries=90)

    logger.log_end('')
