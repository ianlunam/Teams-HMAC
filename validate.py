import json
import hmac
import hashlib
import base64
import logging

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
