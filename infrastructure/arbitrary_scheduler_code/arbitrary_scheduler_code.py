# Arbitrary Scheduler Code by Jacob Mevorach

import datetime
import time
import json
import boto3
import logging
import os
from io import BytesIO
import zipfile
import zlib
import ast

#create logger for events
logger = logging.getLogger()
logger.setLevel(logging.INFO)

#get dynamoDB table name
table_name = os.getenv('dynamodb_table_name')

#helper function to check if two sets have a common item
def common_member(a, b):
    a_set = set(a)
    b_set = set(b)
    if len(a_set.intersection(b_set)) > 0:
        return (True)
    return (False)

#helpfer function to create a dynamoDB entry.
def create_item(table_name, data_loaded, UUID):
    # create boto3 DynamoDB resource for our table
    dynamodb_resource = boto3.resource('dynamodb')
    table = dynamodb_resource.Table(table_name)

    #make sure user doesn't attempt to use a reserved keyword in their job json
    if common_member(ast.literal_eval(os.getenv('reserved_keywords')),[x.upper() for x in data_loaded.keys()]):
        raise ValueError('You used a reserved keyword in this job json.')

    #initialize item to create
    item = {}
    item['UUID'] = UUID
    item['END_TIME'] = int((datetime.datetime.now()+datetime.timedelta(days=int(str(os.getenv('days_to_keep_failed_launch_indexes'))))).timestamp())
    item['START_TIME'] = 'not_yet_initiated'
    item['JOB_STATUS'] = 'not_yet_initiated'

    for k, v in data_loaded.items():
        item[k] = v

    #write item to table
    with table.batch_writer() as batch:
        response = batch.put_item(
            Item=item
        )

    return 0

#helper function to make new batch job
def submit_new_job(UUID, ZIP, sqs, queue_url, s3event):
    t_end = time.time() + 60 * 10 #try to submit a batch job successfully for 10 minutes

    #initialize job submission status
    submitted_successfully = False

    #attempt to submit a job for 10 minutes
    while time.time() < t_end:
        response = boto3.client('batch').submit_job(jobName=UUID, jobQueue=os.getenv('job_queue_name'),
                                                    jobDefinition=os.getenv('job_definition_arn'), containerOverrides={
                'environment': [{'name': 'UUID', 'value': UUID}, {'name': 'INPUT_ZIP_NAME', 'value': ZIP}, {'name': 'IS_INVOKED', 'value': 'False'}]})
        if response['ResponseMetadata']['HTTPStatusCode'] == 200:
            submitted_successfully = True
            break

    #if we can't submit a job submit the original SQS message back into the queue for processing
    if not submitted_successfully:
        t_end = time.time() + 60 * 2  # try to submit a sqs message succesfully for 2 minutes
        submitted_successfully = False
        while time.time() < t_end:
            response = sqs.send_message(QueueUrl=queue_url, MessageBody=s3event)
            if response['ResponseMetadata']['HTTPStatusCode'] == 200:
                submitted_successfully = True
                break
        if not submitted_successfully:
            raise ValueError('Failed to send SQS message back to queue!')

#helper function to fetch a specific byte range from an S3 object
def fetch(s3,bucket_name,key,start,len):
    end = start + len - 1
    return s3.get_object(Bucket=bucket_name,Key=key,Range='bytes={}-{}'.format(start, end))['Body'].read()

#helper function to parse integers out from byte string
def parse_int(bytes):
    val = bytes[0] + (bytes[1] << 8)
    if len(bytes) > 3:
        val += (bytes[2] << 16) + (bytes[3] << 24)
    return val

#main lambda handler
def lambda_handler(event, context):
    #log the incoming event
    logger.info(event)

    #create a boto3 sqs client
    sqs = boto3.client('sqs')

    #parse out the object key, sqs queue url and bucket name from the S3 --> SQS event that caused this lambda to invoke
    s3event = json.loads(event['Records'][0]['body'])
    key = s3event['Records'][0]['s3']['object']['key']
    bucket_name = s3event['Records'][0]['s3']['bucket']['name']
    queue_url = sqs.get_queue_url(QueueName=event['Records'][0]['eventSourceARN'].split(':')[-1])

    #get the input zip file as a boto3 s3 resource and the size of the object
    zip_obj = boto3.resource('s3').Object(bucket_name=bucket_name,key=key)
    size = zip_obj.content_length

    #create a boto3 s3 client
    s3 = boto3.client('s3')

    #get the content directory start and stop location from the zip file (works as long as the zip is not a zip64)
    eocd = fetch(s3,bucket_name,key, size - 22, 22)
    cd_start = parse_int(eocd[16:20])
    cd_size = parse_int(eocd[12:16])

    #fetch out the content directory
    cd = fetch(s3,bucket_name,key,cd_start, cd_size)

    #read out just the "inputs.txt" from the zip file
    zip = zipfile.ZipFile(BytesIO(cd + eocd))
    for zi in zip.filelist:
        if zi.filename == "inputs.json":
            file_head = fetch(s3,bucket_name,key,cd_start + zi.header_offset + 26, 4)
            name_len = parse_int(file_head[0:2])
            extra_len = parse_int(file_head[2:4])
            content = fetch(s3,bucket_name,key,cd_start + zi.header_offset + 30 + name_len + extra_len, zi.compress_size)
            if zi.compress_type == zipfile.ZIP_DEFLATED:
                data_loaded = json.loads(zlib.decompressobj(-15).decompress(content))
            else:
                data_loaded = json.loads(content)

    #create a UUID to associate with the job this lambda will create
    UUID = str(context.aws_request_id) + str(s3event['Records'][0]['responseElements']['x-amz-request-id']) + str(
        s3event['Records'][0]['s3']['object']['eTag'])

    #submit the job
    submit_new_job(UUID, key, sqs, queue_url, s3event)

    #create an item for the job in the DynamoDB
    create_item(table_name, data_loaded, UUID)

    #report successful status if Lambda executes without error
    return {
        'statusCode': 200,
        'body': json.dumps('Shepard scheduler executed successfully!')
    }
