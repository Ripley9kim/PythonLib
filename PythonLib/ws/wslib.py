import logging
import threading
import hashlib
import base64
import httpmsg
	
from http import HTTPStatus

WS_GUID = '258EAFA5-E914-47DA-95CA-C5AB0DC85B11'
WS_VERSION = 13
WS_TEXT_ENCODING ='utf-8'
WS_OPCODE_CONT_0   = 0x0	# Continuation Frame
WS_OPCODE_TEXT_1   = 0x1	# Text Frame
WS_OPCODE_BINARY_2 = 0x2	# Binary Frame
WS_OPCODE_RES_3    = 0x3	# Reserved for further non-control frames
WS_OPCODE_RES_4    = 0x4	# Reserved for further non-control frames
WS_OPCODE_RES_5    = 0x5	# Reserved for further non-control frames
WS_OPCODE_RES_6    = 0x6	# Reserved for further non-control frames
WS_OPCODE_RES_7    = 0x7	# Reserved for further non-control frames
WS_OPCODE_CLOSE_8  = 0x8	# Connection Close
WS_OPCODE_PING_9   = 0x9	# Ping
WS_OPCODE_PONG_A   = 0xa	# Pong
WS_OPCODE_RES_B    = 0xb	# Reserved for further control frames
WS_OPCODE_RES_C    = 0xc	# Reserved for further control frames
WS_OPCODE_RES_D    = 0xd	# Reserved for further control frames
WS_OPCODE_RES_E    = 0xe	# Reserved for further control frames
WS_OPCODE_RES_F    = 0xf	# Reserved for further control frames

####################################################################
# svc
####################################################################

def svc(sock, hosts, origins):
	tid = threading.get_ident()
	logging.info('[%s] accepted from %s' % (tid, str(sock.getpeername())))

	#
	# Handshake Received
	#
	req = httpmsg.message_from_socket(sock)
	logging.debug('[%s] ReqLine> [%s] [%s]' % (tid, req.method, req.requesturi))
	for name, value in req.all():
		logging.debug('[%s] HdrLine> %s: %s' % (tid, name, value))

	#
	# Verify host header
	#
	if hosts:
		host = req.header('host')
		if host:
			hostonly = host.split(':')[0] # ':' 가 없어도 작동함
			if not hostonly in hosts:
				# Host not verified
				error_response(sock, HTTPStatus.FORBIDDEN)
				return

	#
	# Verify host header
	#
	if origins:
		origin = req.header('origin')
		if origin and (not origin in origins):
			# Origin not verified
			error_response(sock, HTTPStatus.FORBIDDEN)
			return

	#
	# Check service endpoint
	#
	endpoint = req.parseduri.path
	
	logging.debug('[%s] URI> %s' % (tid, req.parseduri))
	
	if endpoint not in ['/echo']:
		# Invalid (Not found) endpoint
		error_response(sock, HTTPStatus.NOT_FOUND)
		return

	#
	# Handshake Response
	#
	_, b64str = ws_handshake_calckey(req.header('sec-websocket-key'), WS_GUID)
	acceptProtos = ws_handshake_protocol(req.header('sec-websocket-protocol'))
	
	resp = httpmsg.HTTPResp(status=101, phrase='Switching Protocols')
	resp.addHeader('Upgrade', 'websocket')
	resp.addHeader('Connection', 'Upgrade')
	resp.addHeader('Sec-WebSocket-Version', WS_VERSION)
	resp.addHeader('Sec-WebSocket-Accept', b64str)
	resp.addHeader('Sec-WebSocket-Protocol', acceptProtos)
	resp_encoded = resp.encode()
	logging.debug('[%s] resp_encoded=[%s]', tid, resp_encoded)
	sock.sendall(resp_encoded)
	
	if endpoint == '/echo':
		# Route request to Echo Service
		echo_handler(sock)

####################################################################
# error_response
####################################################################

def error_response(sock, status: HTTPStatus):
	resp = httpmsg.HTTPResp(status.value, status.phrase)
	resp.addHeader('Server', 'WSS/1.1.7 (jupiter; rev569)')
	resp.addHeader('Content-Type', 'text/html')
	sock.sendall(resp.encode())

####################################################################
# ws_handshake_*
####################################################################

def ws_handshake_calckey(keystr, guidstr):
	tid = threading.get_ident()
	hashobj = hashlib.sha1((keystr + guidstr).encode('ascii')) # bytes -> hash object
	hashbytes = bytes.fromhex(hashobj.hexdigest()) # str -> bytes
	b64str = base64.b64encode(hashbytes).decode('ascii')
	logging.debug("[%s] ws_handshake_calckey(): key=[%s]", tid, keystr)
	logging.debug("[%s] ws_handshake_calckey(): guid=[%s]", tid, guidstr)
	logging.debug("[%s] ws_handshake_calckey(): hash/base64=[%s]", tid, b64str)
	return (guidstr, b64str)

def ws_handshake_protocol(proto):
	if not proto:
		return
	# 현재는 정의된 것이 없음.
	return None

def ws_sockread_all(sock, remain):
	received= b''
	nlength = remain
	nread = 0
	while nread < nlength:
		data = sock.recv(nlength - nread)
		if not data:
			break
		nread += len(data)
		received += data
	return received

def ws_read(sock):
	tid = threading.get_ident()
	b = sock.recv(1)
	if not b: return None
	n = ord(b)
	fin = (n & 0x80) == 0x80
	rsv1 = (n & 0x40) == 0x40
	rsv2 = (n & 0x20) == 0x20
	rsv3 = (n & 0x10) == 0x10
	opcode = n & 0x0f
	logging.debug('[%s] [frameRecv] <<<< frame start >>>>' % tid)
	#logging.debug('[%s] [frameRecv] 0x%x' % (tid, n) + ' | {0:08b}'.format(n))
	logging.debug('[%s] [frameRecv] fin=%d, rsv1/2/3=%d/%d/%d, opcode=%d' % 
				(tid, fin, rsv1, rsv2, rsv3, opcode))
	
	b = sock.recv(1)
	if not b: return None
	n = ord(b)
	mask = (n & 0x80) == 0x80
	plen = n & 0x07f
	#logging.debug('[%s] [frameRecv] 0x%x' % (tid, n) + ' | {0:08b}'.format(n))
	logging.debug('[%s] [frameRecv] mask=%d, plen=%d' % (tid, mask, plen))
	
	if mask == 1:
		maskbytes = ws_sockread_all(sock, 4)
		if not maskbytes: return None
		logging.debug('[%s] [frameRecv] maskbytes=[%s]' % (tid, maskbytes))
	
	payload = None
	if plen > 0:
		payload = ws_sockread_all(sock, plen)
		if not payload: return None
		logging.debug('[%s] [frameRecv] payload-32B=[%s]' % (tid, payload[:32]))
		if mask == 1:
			# 마스킹된 데이터는 의미가 없으므로 변수를 덮어쓴다.
			payload = ws_masking(maskbytes, payload)
				
	try:
		if opcode == WS_OPCODE_TEXT_1:
			textdata = payload.decode(WS_TEXT_ENCODING, errors='replace')
			logging.debug('[%s] [frameRecv] payload-txt=[%s]' % (tid, textdata))
			return (opcode, textdata)
		elif opcode == WS_OPCODE_CLOSE_8:
			logging.debug('[%s] [frameRecv] closing...' % tid)
			sock.close()
			return None
	finally:
		logging.debug('[%s] [frameRecv] frame end.' % tid)

def ws_write(sock):
	raise Exception('Not implemented')

def ws_masking(mask, data):
	dlen = len(data)
	unmasked = bytearray(dlen)
	for i in range(dlen):
		j = i % 4
		unmasked[i] = data[i] ^ mask[j]
	return unmasked

####################################################################
# echo_handler
####################################################################

def echo_handler(sock):
	tid = threading.get_ident()
	try:
		while True:
			data = ws_read(sock)
			if not data:
				logging.debug('[%s] handler end!' % tid)
				break
	except Exception as e:
		logging.debug('[%s] error=%s' % (tid, e))
		sock.close()

####################################################################
# Self-Test
####################################################################

if __name__ == '__main__':
	#
	# Initializing.... Self-Test
	#
	test_key = 'dGhlIHNhbXBsZSBub25jZQ=='
	test_guidstr = '258EAFA5-E914-47DA-95CA-C5AB0DC85B11'
	(guidstr, b64str) = ws_handshake_calckey(test_key, test_guidstr)
	assert b64str == 's3pPLMBiTxaQ9kYGzzhZRbK+xOo='