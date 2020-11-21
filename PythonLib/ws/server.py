import os
import logging
import argparse
import re
import threading

from wslib import WSServer

logging.basicConfig(
        level=logging.DEBUG, 
        format='%(asctime)s.%(msecs)03d - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S')

####################################################################
# handler
####################################################################

def handler(endpoint, sock):
    tid = threading.get_ident()
    try:
        while True:
            data = WSServer.ws_read(sock)
            if not data:
                logging.debug('[%s] [%s] handler end!' % (tid, endpoint))
                break
    except Exception as e:
        logging.debug('[%s] [%s] error=%s' % (tid, endpoint, e))
        sock.close()

####################################################################
# main
####################################################################

if __name__ == '__main__':   
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
    
    logging.info('starting server...(%s)' % os.path.basename(__file__))
    logging.info('host=%s, port=%d, hosts=%s' % 
                (pargs.host, pargs.port, pargs.hosts))
    
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

    wssvr = WSServer(pargs.host, pargs.port, hosts, origins)
    wssvr.set_handler(handler)
    wssvr.run_forever()