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

def handler(_, sock, wsdata):
	tid = threading.get_ident()
	tid = str(tid) + '-' + wsdata.endpoint
	
	opcodenm = WSServer.WS_OPCODE_MAP[wsdata.opcode]
	logging.debug('[%s] wsdata: endpoint=%s, opcode=%s, fin=%d' % 
				(tid, wsdata.endpoint, opcodenm, wsdata.fin))
	
	if wsdata.opcode == WSServer.WS_OPCODE_TEXT_1:
		textdata = wsdata.asText()
		logging.debug('[%s] wsdata: len=%d, payload32=[%s]' % 
					(tid, wsdata.length, textdata[:32]))
		WSServer.ws_write(sock, wsdata.opcode, wsdata.payload)
	else:
		logging.debug('[%s] wsdata: len=%d, payload32B=[%s]' %
					(tid, wsdata.length, wsdata.payload[:32]))
		WSServer.ws_write(sock, wsdata.opcode, wsdata.payload)

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

	# Add argument definition  
	parser.add_argument(
		'-e',
		'--endpoints',
		metavar='text',
		type=str,
		default=None,
		help='Verified endpoint list ("," delimeted)',
	)
		
	# Parse the arguments on the command line
	pargs = parser.parse_args()
	
	logging.info('starting server...(%s)' % os.path.basename(__file__))
	logging.info('host=%s, port=%d, hosts=%s, origins=%s' % 
				(pargs.host, pargs.port, pargs.hosts, pargs.origins))
	
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
		
	# Build verified endpoints list
	if pargs.endpoints:
		endpoints = re.split('\\s*,\\s*', pargs.endpoints)
	else:
		endpoints = None

	wssvr = WSServer(pargs.host, pargs.port, hosts, origins, endpoints)
	wssvr.set_handler(lambda sock, wsdata: handler(wssvr, sock, wsdata))
	wssvr.run_forever()