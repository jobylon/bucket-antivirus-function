# -*- coding: utf-8 -*-
# Upside Travel, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import copy
import json
import os
from urllib.parse import unquote_plus

import boto3
import requests

import clamav
import metrics
from common import AV_DEFINITION_S3_BUCKET
from common import AV_DEFINITION_S3_PREFIX
from common import AV_DELETE_INFECTED_FILES
from common import AV_PROCESS_ORIGINAL_VERSION_ONLY
from common import AV_SCAN_START_METADATA
from common import AV_SCAN_START_SNS_ARN
from common import AV_SIGNATURE_METADATA
from common import AV_STATUS_CLEAN
from common import AV_STATUS_INFECTED
from common import AV_STATUS_METADATA
from common import AV_STATUS_SNS_ARN
from common import AV_STATUS_SNS_PUBLISH_CLEAN
from common import AV_STATUS_SNS_PUBLISH_INFECTED
from common import AV_TIMESTAMP_METADATA
from common import create_dir
from common import get_timestamp


def jobylon_event_object(event):
    s3_obj = event
    print(s3_obj)

    # Get the bucket name
    if "bucket" not in s3_obj:
        raise Exception("No bucket found in event!")
    bucket_name = s3_obj.get("bucket", None)

    # Get the key name
    if "key" not in s3_obj:
        raise Exception("No key found in event!")
    key_name = s3_obj.get("key", None)

    if key_name:
        key_name = unquote_plus(key_name.encode("utf8"))

    # Ensure both bucket and key exist
    if (not bucket_name) or (not key_name):
        raise Exception("Unable to retrieve object from event.\n{}".format(event))

    # Create and return the object
    s3 = boto3.resource("s3")
    return s3.Object(bucket_name, key_name)


def event_object(event, event_source="s3"):

    # SNS events are slightly different
    if event_source.upper() == "SNS":
        event = json.loads(event["Records"][0]["Sns"]["Message"])

    # Break down the record
    records = event["Records"]
    if len(records) == 0:
        raise Exception("No records found in event!")
    record = records[0]

    s3_obj = record["s3"]

    # Get the bucket name
    if "bucket" not in s3_obj:
        raise Exception("No bucket found in event!")
    bucket_name = s3_obj["bucket"].get("name", None)

    # Get the key name
    if "object" not in s3_obj:
        raise Exception("No key found in event!")
    key_name = s3_obj["object"].get("key", None)

    if key_name:
        key_name = unquote_plus(key_name)

    # Ensure both bucket and key exist
    if (not bucket_name) or (not key_name):
        raise Exception("Unable to retrieve object from event.\n{}".format(event))

    # Create and return the object
    s3 = boto3.resource("s3")
    return s3.Object(bucket_name, key_name)


def get_local_path(s3_object, local_prefix):
    return os.path.join(local_prefix, s3_object.bucket_name, s3_object.key)


def delete_s3_object(s3_object):
    try:
        s3_object.delete()
    except Exception:
        raise Exception(
            "Failed to delete infected file: %s.%s"
            % (s3_object.bucket_name, s3_object.key)
        )
    else:
        print("Infected file deleted: %s.%s" % (s3_object.bucket_name, s3_object.key))


def get_file_unique_key(s3_client, s3_object):
    return s3_object.key.split("/")[1]  # TODO: Check if tag with the same key exists


def set_av_tags(s3_client, s3_object, scan_result, scan_signature, timestamp):
    curr_tags = s3_client.get_object_tagging(
        Bucket=s3_object.bucket_name, Key=s3_object.key
    )["TagSet"]
    new_tags = copy.copy(curr_tags)
    for tag in curr_tags:
        if tag["Key"] in [
            AV_SIGNATURE_METADATA,
            AV_STATUS_METADATA,
            AV_TIMESTAMP_METADATA,
        ]:
            new_tags.remove(tag)
    new_tags.append({"Key": AV_SIGNATURE_METADATA, "Value": scan_signature})
    new_tags.append({"Key": AV_STATUS_METADATA, "Value": scan_result})
    new_tags.append({"Key": AV_TIMESTAMP_METADATA, "Value": timestamp})
    s3_client.put_object_tagging(
        Bucket=s3_object.bucket_name,
        Key=s3_object.key,
        Tagging={"TagSet": new_tags}
    )


def callback_server(s3_client, s3_object, event, scan_result, context):
    callback_domain = os.getenv("CALLBACK_DOMAIN", None)
    if not callback_domain:
        raise Exception('CALLBACK_DOMAIN not configured')

    callback_url = event['callback_url'].split(':8000/')[1]

    # fazer um build descente

    CALLBACK_URL = (
        u'{callback_domain}/{callback_url}'
        u'?scan_result={scan_result}'
        u'&log_stream={log_stream}'
        u'&request_id={request_id}'
    ).format(
        callback_domain=callback_domain,
        callback_url=callback_url,
        scan_result=scan_result,
        log_stream=context.log_stream_name,
        request_id=context.aws_request_id
    )
    print(CALLBACK_URL)
    try:
        requests.get(CALLBACK_URL, timeout=5)
    except requests.exceptions.ReadTimeout:
        pass


def lambda_handler(event, context):
    s3 = boto3.resource("s3")
    s3_client = boto3.client("s3")

    # Get some environment variables
    EVENT_SOURCE = os.getenv("EVENT_SOURCE", "S3")

    start_time = get_timestamp()
    print("Script starting at %s\n" % (start_time))
    s3_object = jobylon_event_object(event)
    # s3_object = event_object(event, event_source=EVENT_SOURCE)

    file_path = get_local_path(s3_object, "/tmp")
    create_dir(os.path.dirname(file_path))
    s3_object.download_file(file_path)

    to_download = clamav.update_defs_from_s3(
        s3_client, AV_DEFINITION_S3_BUCKET, AV_DEFINITION_S3_PREFIX
    )

    for download in to_download.values():
        s3_path = download["s3_path"]
        local_path = download["local_path"]
        print("Downloading definition file %s from s3://%s" % (local_path, s3_path))
        s3.Bucket(AV_DEFINITION_S3_BUCKET).download_file(s3_path, local_path)
        print("Downloading definition file %s complete!" % (local_path))
    scan_result, scan_signature = clamav.scan_file(file_path)
    result_time = get_timestamp()

    output = "Scan of s3://%s resulted in %s\n" % (os.path.join(s3_object.bucket_name, s3_object.key), scan_result)
    print(
        "Scan of s3://%s resulted in %s\n"
        % (os.path.join(s3_object.bucket_name, s3_object.key), scan_result)
    )

    # # Set the properties on the object with the scan results
    # if "AV_UPDATE_METADATA" in os.environ:
    #     set_av_metadata(s3_object, scan_result, scan_signature, result_time)
    set_av_tags(s3_client, s3_object, scan_result, scan_signature, result_time)

    callback_server(
        s3_client,
        s3_object,
        event,
        scan_result,
        context
    )

    return {
        'statusCode': 200,
        'body': json.dumps(output)
    }
