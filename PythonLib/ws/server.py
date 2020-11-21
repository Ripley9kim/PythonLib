import os
import logging
import socket
import threading
import argparse
import re
import wslib

logging.basicConfig(
        level=logging.DEBUG, 
        format='%(asctime)s.%(msecs)03d - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S')

# Create the argument parser
parser = argparse.ArgumentParser(
    description="WebSocket Server",
    add_help=False
    )

# Add argument definition
parser.add_argument(
    '-h',
    '--host',
    metavar='text',
    type=str,
    default='localhost',
    help='Listening host name'
    )

# Add argument definition
parser.add_argument(
    '-p',
    '--port',
    metavar='N',
    type=int,
    default=8080,
    help='Listening port number',
)

# Add argument definition    
parser.add_argument(
    '-v',
    '--hosts',
    metavar='text',
    type=str,
    default=None,
    help='Verified host list ("," delimeted)',
)

# Add argument definition    
parser.add_argument(
    '-o',
    '--origins',
    metavar='text',
    type=str,
    default=None,
    help='Verified origin list ("," delimeted)',
)

# Parse the arguments on the command line
pargs = parser.parse_args()

logging.info('starting py...(%s)' % os.path.basename(__file__))
logging.info('host=%s, port=%d, hosts=%s' % 
            (pargs.host, pargs.port, pargs.hosts))

# Prepare Server Socket
py = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
py.bind((pargs.host, pargs.port))
py.listen()

# Build verified host list
if pargs.hosts:
    hosts = re.split('\\s*,\\s*', pargs.hosts)
else:
    hosts = None

# Build verified origin list
if pargs.origins:
    origins = re.split('\\s*,\\s*', pargs.origins)
else:
    origins = None

# Socket accept loop...
logging.info('listening...')
while True:
    sock, remote = py.accept()
    t = threading.Thread(target=wslib.svc, args=(sock, hosts, origins))
    t.start()
    logging.info('thread started: [%d]' % t.ident)