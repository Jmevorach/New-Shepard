# Arbitrary Job Batching Endpoint Code by Jacob Mevorach

import datetime
import time
import json
import boto3
import logging
import os
import base64
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
def submit_new_job(UUID):
    t_end = time.time() + 60 * 10 #try to submit a batch job successfully for 10 minutes

    #initialize job submission status
    submitted_successfully = False

    #attempt to submit a job for 10 minutes
    while time.time() < t_end:
        response = boto3.client('batch').submit_job(jobName=UUID, jobQueue=os.getenv('job_queue_name'),
                                                    jobDefinition=os.getenv('job_definition_arn'), containerOverrides={
                'environment': [{'name': 'UUID', 'value': UUID}, {'name': 'INPUT_ZIP_NAME', 'value': 'None'}, {'name': 'IS_INVOKED', 'value': 'True'}]})
        if response['ResponseMetadata']['HTTPStatusCode'] == 200:
            submitted_successfully = True
            break

    #if we can't submit a job throw an error
    if not submitted_successfully:
        raise ValueError('Failed to submit job to batch queue!')

#main lambda handler
def lambda_handler(event, context):
    # log the incoming event
    logger.info(event)

    #load the event into a local variable
    data_loaded = event

    #create a UUID to associate with our job we will create
    UUID = str(context.aws_request_id) + str(base64.b16encode(str.encode(str(event))).decode("utf-8"))[:50]

    #create batch job
    submit_new_job(UUID)

    #create item in dynamoDB table
    create_item(table_name, data_loaded, UUID)

    #report successful status if Lambda executes without error
    return {
        'statusCode': 200,
        'body': json.dumps('Shepard scheduler executed successfully!')
    }
