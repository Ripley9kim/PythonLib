import logging
import threading
import hashlib
import base64
import httpmsg
import socket
	
from http import HTTPStatus

####################################################################
# WSServer
####################################################################

class WSServer:
	WS_GUIDSTR = '258EAFA5-E914-47DA-95CA-C5AB0DC85B11'
	WS_USERAGENT = 'WSS/1.1.15 jupiter'
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
	
	# 
	# Constructor
	#
	def __init__(self, host='', port=8080, hosts=None, origins=None, endpoints=None):
		self.host = host
		self.port = int(port)
		self.hosts = hosts if hosts != None else []
		self.origins = origins if origins != None else []
		self.endpoints = endpoints if endpoints != None else []
		
		server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		server.bind((host, port))
		server.listen()
		self.server = server
		self.sockets = []

	#
	# set_handler
	#
	def set_handler(self, handler):
		"""
		handler: def handler(endpoint, sock): ...
		"""
		self.handler = handler

	# 
	# start
	#
	def start(self):
		t = threading.Thread(target=lambda: self.__server_loop(), args=())
		t.start()
	
	# 
	# run_forever
	#
	def run_forever(self):
		self.__server_loop()
	
	# 
	# shutdown
	#
	def shutdown(self):
		self.server.close()
		for sock in self.sockets:
			try:
				sock.close()
			except:
				pass
		self.sockets.clear()

	#
	# __server_loop
	#
	def __server_loop(self):
		while True:
			logging.debug('waiting on %s...', self.server.getsockname())
			sock, remote = self.server.accept()
			self.sockets.append(sock)
			try:
				logging.info('accepted from %s' % str(remote))
				t = threading.Thread(target=lambda s: self.__ws_handshake_wrap(s), args=(sock,))
				t.start()
				logging.info('thread started: tid=%d, remote=%s' % (t.ident, str(remote)))
			except Exception:
				self.sockets.remove(sock)

	#
	# __ws_handshake
	#
	def __ws_handshake(self, sock):
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
		# RFC6455 1.3. Opening Handshake
		# The client includes the hostname in the |Host| header field of its
		# handshake as per [RFC2616], so that both the client and the server
		# can verify that they agree on which host is in use.
		if self.hosts:
			host = req.header('host')
			if host:
				hostonly = host.split(':')[0] # port 제거, ':' 가 없어도 작동함
				if not hostonly in self.hosts:
					self.__ws_error_response(sock, HTTPStatus.FORBIDDEN)
					return
	
		#
		# Verify protocol
		#
		# RFC6455 1.3. Opening Handshake
		# ... The |Sec-WebSocket-Protocol| request-header field can be
		# used to indicate what subprotocols (application-level protocols
		# layered over the WebSocket Protocol) are acceptable to the client.
		sec_proto = req.header('sec-websocket-protocol')
		accept_proto = None # 현재는 지원하는 이름이 없음.
		if sec_proto:
			pass
		
		#
		# Verify origin header
		#
		# RFC6455 1.3. Opening Handshake
		# The |Origin| header field [RFC6454] is used to protect against
		# unauthorized cross-origin use of a WebSocket server by scripts using
		# the WebSocket API in a web browser. The server is informed of the
		# script origin generating the WebSocket connection request. If the
		# server does not wish to accept connections from this origin, it can
		# choose to reject the connection by sending an appropriate HTTP error
		# code. This header field is sent by browser client; ...
		if self.origins:
			origin = req.header('origin')
			if origin and (not origin in self.origins):
				self.__ws_error_response(sock, HTTPStatus.FORBIDDEN)
				return
	
		#
		# Check service endpoint
		#
		# RFC6455 1.3. Opening Handshake
		# The "Request-URI" of the GET method [RFC2616] is used to identify the
		# endpoint of the WebSocket connection, both to allow multiple domains
		# to be served from one IP address and to allow multiple WebSocket
		# endpoints to be served by a signle server.
		endpoint = req.parseduri.path
		# ex) URL "/echo"         -> path="/echo"
		# ex) URL "/echo/xyz?a=b" -> path="/echo/xyz"
		# ex) URL ""              -> path="/"
		if self.endpoints:
			if endpoint and (not endpoint in self.endpoints):
				self.__ws_error_response(sock, HTTPStatus.NOT_FOUND)
				return
	
		#
		# Calculate hash
		#
		# RFC6455 1.3. Opening Handshake
		# Finally, the server has to prove to the client that it received the
		# client's WebSocket handshake, so that the server doesn't accept
		# connections that are not WebSocket connections. This prevents an
		# attacker from tricking a WebSocket server by sending it carefully
		# crafted packets using XMLHttpRequest [XMLHttpRequest] or a form
		# submission....
		wskey = req.header('sec-websocket-key')
		wskeyguid = wskey + WSServer.WS_GUIDSTR
		hashobj = hashlib.sha1(wskeyguid.encode('ascii')) # bytes -> hash object
		hashbytes = bytes.fromhex(hashobj.hexdigest()) # str -> bytes
		wsacceptb64 = base64.b64encode(hashbytes).decode('ascii')
		
		#
		# Handshake Response
		#
		# RFC6455 1.3. Opening Handshake
		# The handshake from the server is much simpler than the client
		# handshake. The first line is an HTTP Status-Line, with the status
		# code 101:
		resp = httpmsg.HTTPResp(status=101, phrase='Switching Protocols')
		resp.addHeader('Connection', 'Upgrade')
		resp.addHeader('Upgrade', 'websocket')
		resp.addHeader('Sec-WebSocket-Version', WSServer.WS_VERSION)
		resp.addHeader('Sec-WebSocket-Accept', wsacceptb64)
		resp.addHeader('Sec-WebSocket-Protocol', accept_proto)
		resp_encoded = resp.encode()
		logging.debug('[%s] resp_encoded=[%s]', tid, resp_encoded)
		sock.sendall(resp_encoded)
		
		if self.handler:
			self.handler(endpoint, sock)
	
	#
	# __ws_handshake_wrap
	#
	def __ws_handshake_wrap(self, sock):
		try:
			self.__ws_handshake(sock)
		finally:
			sock.close()
			self.sockets.remove(sock)

	#
	# __ws_error_response
	#
	@staticmethod
	def __ws_error_response(sock, status: HTTPStatus):
		resp = httpmsg.HTTPResp(status.value, status.phrase)
		resp.addHeader('Server', WSServer.WS_USERAGENT)
		resp.addHeader('Content-Type', 'text/html')
		sock.sendall(resp.encode())

	#
	# __ws_sockread_all
	#
	@staticmethod
	def __ws_sockread_all(sock, remain):
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

	#
	# __ws_masking
	#
	@staticmethod
	def __ws_masking(mask, data):
		dlen = len(data)
		unmasked = bytearray(dlen)
		for i in range(dlen):
			j = i % 4
			unmasked[i] = data[i] ^ mask[j]
		return unmasked

	#
	# ws_read
	#
	@staticmethod
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
			maskbytes = WSServer.__ws_sockread_all(sock, 4)
			if not maskbytes: return None
			logging.debug('[%s] [frameRecv] maskbytes=[%s]' % (tid, maskbytes))
		
		payload = None
		if plen > 0:
			payload = WSServer.__ws_sockread_all(sock, plen)
			if not payload: return None
			logging.debug('[%s] [frameRecv] payload-32B=[%s]' % (tid, payload[:32]))
			if mask == 1:
				# 마스킹된 데이터는 의미가 없으므로 변수를 덮어쓴다.
				payload = WSServer.__ws_masking(maskbytes, payload)
					
		try:
			if opcode == WSServer.WS_OPCODE_TEXT_1:
				textdata = payload.decode(WSServer.WS_TEXT_ENCODING, errors='replace')
				logging.debug('[%s] [frameRecv] payload-txt=[%s]' % (tid, textdata))
				return (opcode, textdata)
			elif opcode == WSServer.WS_OPCODE_CLOSE_8:
				logging.debug('[%s] [frameRecv] closing...' % tid)
				sock.close()
				return None
		finally:
			logging.debug('[%s] [frameRecv] frame end.' % tid)

	#
	# ws_write
	#
	@staticmethod
	def ws_write(sock):
		raise Exception('Not implemented')