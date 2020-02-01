import logging
from datetime import *

logname = 'Logs/{}.log'.format(datetime.now().strftime('%Y-%m-%d-%H-%M-%S'))


logging.basicConfig(filename=logname,
                    format='%(asctime)s:%(levelname)s:%(name)s:%(message)s',
                    datefmt='%H:%M:%S',
                    level=logging.DEBUG)

loggerPhishing = logging.getLogger('Phishing')
loggerRepCheck = logging.getLogger('Reputation')
loggerMain = logging.getLogger('Main')

def logMsg(logger, msg):
    logger.debug(msg)
