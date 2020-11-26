import logging
import threading
import hashlib
import base64
import httpmsg
import socket
import random
import unittest
import time
import io
	
from http import HTTPStatus

####################################################################
# WSData
####################################################################

"""
Lowlevel 의 소켓처리 및 WS 의 컨트롤 프레임에 대한 처리는 최대한 
노출시키지 말고 큐를 사용하여 App 에 데이터를 전달하도록 한다. 
데이터는 이 클래스를 사용하여 Wrapping 하도록 한다. 
"""
class WSData:
	#
	# Constructor
	#
	def __init__(self, endpoint, opcode, fin, payload):
		self.endpoint = endpoint
		self.opcode = opcode
		self.fin = fin
		self.payload = payload
		self.length = len(payload)
	
	#
	# asText
	#
	def asText(self):
		if self.payload:
			return self.payload.decode(WSServer.WS_TEXT_ENCODING, errors='replace')
		else:
			return ''

####################################################################
# WSServer
####################################################################

class WSServer:
	NETWORK_BYTE_ORDER = 'big'
	WS_GUIDSTR = '258EAFA5-E914-47DA-95CA-C5AB0DC85B11'
	WS_USERAGENT = 'WSS/1.1.15 jupiter'
	WS_VERSION = 13
	WS_TEXT_ENCODING = 'utf-8'
	WS_BYTE_ORDER = NETWORK_BYTE_ORDER
	WS_OPCODE_CONT_0   = 0x0
	WS_OPCODE_TEXT_1   = 0x1
	WS_OPCODE_BINARY_2 = 0x2
	WS_OPCODE_RES_3    = 0x3
	WS_OPCODE_RES_4    = 0x4
	WS_OPCODE_RES_5    = 0x5
	WS_OPCODE_RES_6    = 0x6
	WS_OPCODE_RES_7    = 0x7
	WS_OPCODE_CLOSE_8  = 0x8
	WS_OPCODE_PING_9   = 0x9
	WS_OPCODE_PONG_A   = 0xa
	WS_OPCODE_RES_B    = 0xb
	WS_OPCODE_RES_C    = 0xc
	WS_OPCODE_RES_D    = 0xd
	WS_OPCODE_RES_E    = 0xe
	WS_OPCODE_RES_F    = 0xf
	WS_OPCODE_MAP = {
		WS_OPCODE_CONT_0:	'0-ContinuationFrame',
		WS_OPCODE_TEXT_1:	'1-TextFrame',
		WS_OPCODE_BINARY_2:	'2-BinaryFrame',
		WS_OPCODE_RES_3:	'3-Reserved for further non-control frames',
		WS_OPCODE_RES_4:	'4-Reserved for further non-control frames',
		WS_OPCODE_RES_5:	'5-Reserved for further non-control frames',
		WS_OPCODE_RES_6:	'6-Reserved for further non-control frames',
		WS_OPCODE_RES_7:	'7-Reserved for further non-control frames',
		WS_OPCODE_CLOSE_8:	'8-ConnectionClose',
		WS_OPCODE_PING_9:	'9-Ping',
		WS_OPCODE_PONG_A:	'A-Pong',
		WS_OPCODE_RES_B:	'B-Reserved for further control frames',
		WS_OPCODE_RES_C:	'C-Reserved for further control frames',
		WS_OPCODE_RES_D:	'D-Reserved for further control frames',
		WS_OPCODE_RES_E:	'E-Reserved for further control frames',
		WS_OPCODE_RES_F:	'F-Reserved for further control frames'
		}
	
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
		handler: def handler(socket, WSData): ...
		"""
		self.handler = handler

	# 
	# start
	#
	def start(self):
		t = threading.Thread(target=lambda: self.__serverloop(), args=())
		t.start()
	
	# 
	# run_forever
	#
	def run_forever(self):
		self.__serverloop()

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
	# __serverloop
	#
	def __serverloop(self):
		while True:
			logging.debug('waiting on %s...', self.server.getsockname())
			sock, remote = self.server.accept()
			self.sockets.append(sock)
			try:
				logging.info('accepted from %s' % str(remote))
				t = threading.Thread(target=lambda s: self.__sockhandler(s), args=(sock,))
				t.start()
				logging.info('thread started: tid=%d, remote=%s' % (t.ident, str(remote)))
			except Exception:
				self.sockets.remove(sock)

	#
	# __sockhandler
	#
	def __sockhandler(self, sock):
		try:
			endpoint = self.__ws_handshake(sock)
			if not endpoint: return
			
			tid = threading.get_ident()
			tid = str(tid) + '-' + endpoint
			logging.debug('[%s] handler started. endpoint=[%s]' % (tid, endpoint))
			
			# Ping Test (No need actually)
			pingdata = 'initpingtest'.encode(WSServer.WS_TEXT_ENCODING)
			WSServer.ws_write(sock, WSServer.WS_OPCODE_PING_9, pingdata)
			
			while True:
				wsdata = WSServer.ws_read(sock)
				if not wsdata:
					logging.debug('[%s] end of data' % tid)
					break
				
				opcode, fin, payload = wsdata
				opcode_name = WSServer.WS_OPCODE_MAP.get(opcode, -1)
				
				if len(payload) > 32:
					logging.info('[%s] opcode=[%s] len=[%d] payload=[%s...%s]' % 
						(tid, opcode_name, len(payload), payload[:16], payload[-16:]))
				else:
					logging.info('[%s] opcode=[%s] len=[%d] payload=[%s]' % 
						(tid, opcode_name, len(payload), payload))

				if opcode == WSServer.WS_OPCODE_TEXT_1:
					event = WSData(endpoint, opcode, fin, payload)
				elif opcode == WSServer.WS_OPCODE_BINARY_2:
					event = WSData(endpoint, opcode, fin, payload)
				elif opcode == WSServer.WS_OPCODE_CLOSE_8:
					reason = payload.decode(WSServer.WS_TEXT_ENCODING)
					logging.debug('[%s] closing. reason=[%s]' % (tid, reason))
					WSServer.ws_write(sock, opcode, payload)
					t = threading.Thread(target=WSServer.__ws_close_pending, args=(sock,))
					t.start()
					return None
				elif opcode == WSServer.WS_OPCODE_PING_9:
					WSServer.ws_write(sock, WSServer.WS_OPCODE_PONG_9, payload)
					logging.debug('[%s] ping->pong' % tid)
					continue
				elif opcode == WSServer.WS_OPCODE_PONG_A:
					logging.debug('[%s] pong recv.' % tid)
					continue
				else:
					raise Exception('Invalid opcode: ' + opcode)
				
				if self.handler:
					self.handler(sock, event)
		except Exception as e:
			logging.debug('[%s] error=[%s]' % (tid, e))
		finally:
			logging.debug('[%s] handler end' % tid)
			sock.close()
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
					return None
	
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
				return None
	
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
		return endpoint

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
		received = b''
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
	def __ws_masking(data, mask=None):
		# mask 가 None 인 경우 로컬에서 mask 를 생성하는
		# 경우로 판단하여 아래와 같이 랜덤한 값을 만든다.
		if not mask:
			maskrand = random.getrandbits(32)
			mask = maskrand.to_bytes(4, WSServer.WS_BYTE_ORDER)
		
		dlen = len(data)
		# 로컬에서 메시지를 생성하는 경우는 mask 인자가 None 이며
		# 아래의 result 는 mask 처리한 결과값이 될 것이다.
		# 반대로 메시지를 받아서 처리하는 경우는 mask 인자가
		# 넘어와야 하며 아래의 result 는 mask 를 제거한 원본 
		# 데이터가 될 것이다. 즉 (data ^ mask) ^ mask = data 이다.
		result = bytearray(dlen)
		for i in range(dlen):
			j = i % 4
			result[i] = data[i] ^ mask[j]
		return (bytes(result), mask)

	#
	# __ws_close_pending
	#
	@staticmethod
	def __ws_close_pending(sock):
		time.sleep(3)
		# Close Frame 은 주고 받았으나 상대방이 소켓을 끊기를 
		# 잠시 기다렸다가 끊도록 한다. 상대방이 이미 끊었을 수도 있다.
		try:
			sock.close()
		except:
			...

	#
	# ws_read
	#
	@staticmethod
	def ws_read(sock):
		tid = threading.get_ident()

		#  0                   1                   2                   3
		#  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
		# +-+-+-+-+-------+-+-------------+-------------------------------+
		# |F|R|R|R| opcode|M| Payload len |    Extended payload length    |
		# |I|S|S|S|  (4)  |A|     (7)     |             (16/64)           |
		# |N|V|V|V|       |S|             |   (if payload len==126/127)   |
		# | |1|2|3|       |K|             |                               |
		# +-+-+-+-+-------+-+-------------+ - - - - - - - - - - - - - - - +
		# |     Extended payload length continued, if payload len == 127  |
		# + - - - - - - - - - - - - - - - +-------------------------------+
		# |                               |Masking-key, if MASK set to 1  |
		# +-------------------------------+-------------------------------+
		# | Masking-key (continued)       |          Payload Data         |
		# +-------------------------------- - - - - - - - - - - - - - - - +
		# :                     Payload Data continued ...                :
		# + - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - +
		# |                     Payload Data continued ...                |
		# +---------------------------------------------------------------+

		#
		# first octet
		#
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
		
		#
		# second octet
		#
		b = sock.recv(1)
		if not b: return None
		n = ord(b)
		mask = (n & 0x80) == 0x80
		plen = n & 0x07f
		
		#
		# Payload Length and extended payload length
		#
		if plen >= 126:
			# RFC6455 5.2. Base Framing Protocol
			# Pyaload length: 7 bits, 7+16 bits, or 7+64 bits
			# The length of the "Payload data", in bytes: if 0-125, that is the 
			# payload length. If 126, the following 2 bytes interpreted as a
			# 16-bit unsigned integer are the payload length. If 127, the
			# following 8 bytes interpreted as a 64-bit unsigned integer (the
			# most significant bit MUST be 0) are the payload length. Multibyte
			# length quantities are expressed in network byte order....
			if plen == 126:
				tmpbytes = WSServer.__ws_sockread_all(sock, 2)
				plen = int.from_bytes(tmpbytes, WSServer.WS_BYTE_ORDER, signed=False)
			else:
				tmpbytes = WSServer.__ws_sockread_all(sock, 8)
				plen = int.from_bytes(tmpbytes, WSServer.WS_BYTE_ORDER, signed=False)
		#logging.debug('[%s] [frameRecv] 0x%x' % (tid, n) + ' | {0:08b}'.format(n))
		logging.debug('[%s] [frameRecv] mask=%d, plen=%d' % (tid, mask, plen))

		#
		# Mask
		#
		if mask == 1:
			maskbytes = WSServer.__ws_sockread_all(sock, 4)
			if not maskbytes: return None
			logging.debug('[%s] [frameRecv] maskbytes=[%s]' % (tid, maskbytes))

		#
		# Payload
		#
		if plen > 0:
			payload = WSServer.__ws_sockread_all(sock, plen)
			if not payload: return None
			logging.debug('[%s] [frameRecv] payload-32B=[%s]' % (tid, payload[:32]))
			if mask == 1:
				# 마스킹된 데이터는 의미가 없으므로 변수를 덮어쓴다.
				payload, _ = WSServer.__ws_masking(payload, maskbytes)
		else:
			payload = b''

		return (opcode, fin, payload)

	#
	# ws_write
	#
	@staticmethod
	def ws_write(sock, opcode, data: bytes, fin=1):
		tid = threading.get_ident()

		#  0                   1                   2                   3
		#  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
		# +-+-+-+-+-------+-+-------------+-------------------------------+
		# |F|R|R|R| opcode|M| Payload len |    Extended payload length    |
		# |I|S|S|S|  (4)  |A|     (7)     |             (16/64)           |
		# |N|V|V|V|       |S|             |   (if payload len==126/127)   |
		# | |1|2|3|       |K|             |                               |
		# +-+-+-+-+-------+-+-------------+ - - - - - - - - - - - - - - - +
		# |     Extended payload length continued, if payload len == 127  |
		# + - - - - - - - - - - - - - - - +-------------------------------+
		# |                               |Masking-key, if MASK set to 1  |
		# +-------------------------------+-------------------------------+
		# | Masking-key (continued)       |          Payload Data         |
		# +-------------------------------- - - - - - - - - - - - - - - - +
		# :                     Payload Data continued ...                :
		# + - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - +
		# |                     Payload Data continued ...                |
		# +---------------------------------------------------------------+
		
		logging.debug('[%s] [frameSend] <<<< frame start >>>>' % tid)
		
		rsv1 = 0
		rsv2 = 0
		rsv3 = 0
		opcode = opcode
		mask = 0 # server does not mask data
		maskbytes = None
		
		logging.debug('[%s] [frameSend] fin=%d, rsv1/2/3=%d/%d/%d, opcode=%d' % 
					(tid, fin, rsv1, rsv2, rsv3, opcode))
		
		#
		# 1st octet
		#
		octets = (fin << 7) + (rsv1 << 6) + (rsv2 << 5) + (rsv3 << 4) + (opcode & 0xf)

		#
		# Payload length
		#
		plen = len(data)
		if plen > int('0xffff', 16): # 66535
			# 16bit 로도 표현이 불가능하다. 이 때는 64bit 을 모두 사용한다.
			octets = (octets << 8) + (mask << 7) + (127 & 0x7f)
			octets = (octets << 64) + (plen & 0xffffffffffffffff)
			octetcnt = 10
		elif plen > 126:
			# 7bit 로 표현이 불가능하며 16bit 를 사용한다.
			octets = (octets << 8) + (mask << 7) + (126 & 0x7f)
			octets = (octets << 16) + (plen & 0xffff)
			octetcnt = 4
		else: # 126 까지는 7bit 로 표현이 가능하다.
			octets = (octets << 8) + (mask << 7) + (plen & 0x7f)
			octetcnt = 2

		logging.debug('[%s] [frameSend] mask=%d, plen=%d' % (tid, mask, plen))

		#
		# Send 1st octet + payload length
		#
		sock.send(octets.to_bytes(octetcnt, WSServer.WS_BYTE_ORDER, signed=False))

		#
		# Send mask bytes
		#
		if mask == 1:
			logging.debug('[%s] [frameSend] maskbytes=[%s]' % (tid, maskbytes))
			sock.send(maskbytes)

		#
		# Send payload
		#
		if plen > 0:
			logging.debug('[%s] [frameSend] payload-32B=[%s]' % (tid, data[:32]))
			sock.send(data)

####################################################################
# BytesStream
####################################################################

"""
send, recv 를 구현하고 있어 소켓이 사용되는 곳에서 사용할 수 
있으며 테스트를 위한 용도로 사용된다.
"""
class BytesStream:
	#
	# Constructor
	#
	def __init__(self, buffer=None):
		self.bio = io.BytesIO(buffer)
	
	#
	# recv
	#
	def recv(self, size):
		return self.bio.read(size)
	
	#
	# send
	#
	def send(self, buffer):
		self.bio.write(buffer)
	
	#
	# seek
	#
	def seek(self, pos, whence=0):
		self.bio.seek(pos, whence)

	#
	# buffer
	#
	def buffer(self):
		return self.bio.getvalue()

####################################################################
# Test
####################################################################

class Test(unittest.TestCase):
	#
	# Constructor
	#
	def __init__(self, *args, **kwargs):
		unittest.TestCase.__init__(self, *args, **kwargs)
		logging.basicConfig(
			level=logging.DEBUG, 
			format='%(asctime)s.%(msecs)03d - %(message)s',
			datefmt='%Y-%m-%d %H:%M:%S')

	#
	# testFrameSendRecv
	#
	def testFrameSendRecv(self):
		sdata = b'1234abcd\x20\x20'
		bstr = BytesStream()
		WSServer.ws_write(bstr, WSServer.WS_OPCODE_BINARY_2, sdata)
		bstr.seek(0)
		opcode, _, rdata = WSServer.ws_read(bstr)
		assert opcode == 2
		assert rdata == sdata

	#
	# testFrameSendRecvLong
	#
	def testFrameSendRecvLong(self):		
		sdata = ('a' + 'b'*1109 + 'c').encode('utf_8')
		bstr = BytesStream()
		WSServer.ws_write(bstr, WSServer.WS_OPCODE_TEXT_1, sdata)
		bstr.seek(0)
		opcode, _, rdata = WSServer.ws_read(bstr)
		assert opcode == 1
		assert rdata == sdata

	#
	# testFrameSendRecvHuge
	#
	def testFrameSendRecvHuge(self):
		sdata = ('a' + 'b'*111109 + 'c').encode('utf_8')
		bstr = BytesStream()
		WSServer.ws_write(bstr, WSServer.WS_OPCODE_TEXT_1, sdata)
		bstr.seek(0)
		opcode, _, rdata = WSServer.ws_read(bstr)
		assert opcode == 1
		assert rdata == sdata

	#
	# testFrameSendCont
	#
	def testFrameSendCont(self):
		sdata = ('1' + '2'*88 + '3').encode('utf_8')
		sdata1 = sdata[:30]
		sdata2 = sdata[30:60]
		sdata3 = sdata[60:90]
		bstr = BytesStream()
		WSServer.ws_write(bstr, WSServer.WS_OPCODE_TEXT_1, sdata1, fin=0)
		WSServer.ws_write(bstr, WSServer.WS_OPCODE_CONT_0, sdata2, fin=0)
		WSServer.ws_write(bstr, WSServer.WS_OPCODE_CONT_0, sdata3, fin=1)
		bstr.seek(0)
		opcode, fin, rdata1 = WSServer.ws_read(bstr)
		assert opcode == WSServer.WS_OPCODE_TEXT_1 and fin == 0
		opcode, fin, rdata2 = WSServer.ws_read(bstr)
		assert opcode == WSServer.WS_OPCODE_CONT_0 and fin == 0
		opcode, fin, rdata3 = WSServer.ws_read(bstr)
		assert opcode == WSServer.WS_OPCODE_CONT_0 and fin == 1
		assert rdata1 + rdata2 + rdata3 == sdata
	
	#
	# testPingPongFrame
	#
	def testPingPongFrame(self):
		pingdata = '~ping~'.encode('utf_8')
		pongdata = '~pong~'.encode('utf_8')
		bstr = BytesStream()
		WSServer.ws_write(bstr, WSServer.WS_OPCODE_PING_9, pingdata)
		WSServer.ws_write(bstr, WSServer.WS_OPCODE_PONG_A, pongdata)
		bstr.seek(0)
		opcode, _, pingdata1 = WSServer.ws_read(bstr)
		assert opcode == WSServer.WS_OPCODE_PING_9, pingdata == pingdata1
		opcode, _, pongdata1 = WSServer.ws_read(bstr)
		assert opcode == WSServer.WS_OPCODE_PONG_A, pongdata == pongdata1
