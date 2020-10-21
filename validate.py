import json
import hmac
import hashlib
import base64
import logging
import traceback

logger = logging.getLogger()
logger.setLevel(logging.DEBUG)

HMAC_SECRET = "<Base64EncodedStringFromTeams>"

def validate_source(event):
    # Validate the message source based on HMAC secret
    if 'body' in event:
        body = json.loads(event['body'])
        if 'channelId' in body:
            if body['channelId'] == 'msteams':
                logger.debug(f"Headers: {event['headers']}")
                header = event['headers']['Authorization']
                msgDigest = hmac.new(HMAC_SECRET, event['body'].encode('utf-8'), hashlib.sha256).digest()
                msgHash = base64.b64encode(msgDigest).decode()
                msgHash = f"HMAC {msgHash}"
                return hmac.compare_digest(header, msgHash)

    logger.debug("Drop through in validate_source")
    return False

                             
def lambda_handler(event, context):
    try:
        logger.debug(f"Event was '{event}'")
        if not .validate_source(event):
            logger.error("Message Authentication failed")
            return {'statusCode': 403, 'body': json.dumps({"Text": f"Message Authentication failed"})}

        # Carry on happily
        logger.debug(event.get('body'))
        body = event.get('body')
        body = json.loads(body)
                             
        # Whatever
                             
    except Exception as err:
        logger.error(err)
        traceback.print_tb(err.__traceback__)
        body = {"type": "message",
            "text": f"Tell your friendly SysEng there was an error: {err}"
        }
                             
        return { 'statusCode': 200, 'body': json.dumps(body) }

                             
    body = {"type": "message",
            "text": "This is a response. I hope you like it."
        }

    return { 'statusCode': 200, 'body': json.dumps(body) }
