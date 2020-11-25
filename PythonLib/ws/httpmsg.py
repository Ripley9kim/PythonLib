import collections
import unittest
import re

from abc import abstractmethod
from urllib.parse import urlparse
from email import message_from_string
from io import StringIO

####################################################################
# HTTPMsg
####################################################################

class HTTPMsg:
	HTTP_VERSION = 'HTTP/1.1'
	
	# 
	# Constructor
	# 
	def __init__(self, version=HTTP_VERSION):
		self.version = version
		self.headers = collections.OrderedDict()
		self.content = None

	#
	# startLine
	#
	@abstractmethod
	def startLine(self) -> str:
		raise Exception('Not implemented')
	
	#
	# header
	#
	def header(self, name, defvalue=None):
		"""
		주어진 헤더이름을 사용하여 대소문자 구분없이 저장된 헤더를 찾는다.
		헤더가 존재한다면 그것의 값을 반환하고 없다면 defvalue 를 반환한다.
		defvalue 은 입력되지 않은 경우 None 이다.
		"""
		h = self.headers.get(name.lower())
		return h[1] if h else defvalue

	#
	# headerAsInt
	#
	def headerAsInt(self, name, defvalue=0) -> int:
		"""
		주어진 헤더이름을 사용하여 대소문자 구분없이 저장된 헤더를 찾는다.
		헤더가 존재한다면 그것의 값을 int 타입으로 변환하여 반환하고 
		없다면 defvalue 를 (주어지지 않는다면 0 임) 반환한다.
		"""
		h = self.headers.get(name.lower())
		return int(h[1] if h else defvalue)
	
	#
	# addHeader
	#
	def addHeader(self, name, value):
		"""
		value 가 None 이거나 트림 후 길이가 0 인 경우에는 입력하지 않는다.
		"""
		# None 이거나 str 인 경우 길이가 0 이면 아래서 반환한다.
		# 그러나 str 인 경우 strip 한 후에 다시 체크해야만 한다.
		if not value: return
		value = str(value).strip()
		if value: # str 변환하고 strip() 한 후에도 길이가 있다면
			self.headers[name.lower()] = (name, value)
	
	#
	# all
	#
	def all(self) -> list:
		"""
		모든 헤더에 대해서 (name, value) tuple 의 목록을 반환한다.
		"""
		return [item for item in self.headers.values()]

	#
	# encode
	#
	def encode(self, encoding='utf_8') -> bytes:
		sio = StringIO()
		print(self.startLine(), end='\r\n', file=sio)
		if self.headers:
			# self.headers 는 OrderedDict 타입이므로 순서대로 인코딩될 것이다.
			for hname, hvalue in self.headers.values():
				hname = hname.strip()
				hvalue = hvalue.strip()
				print('%s: %s' % (hname, hvalue), end='\r\n', file=sio)
		# Content 가 없더라도 반드시 붙여준다.
		print('', end='\r\n', file=sio)
		# StartLine + Headers 에 대한 인코딩
		encoded = sio.getvalue().encode(encoding)
		# Content 는 (존재한다면) 인코딩 개념없이 처음부터 bytes 로 처리된다.
		if self.content:
			encoded += self.content
		return encoded

####################################################################
# HTTPReq
####################################################################

class HTTPReq(HTTPMsg):
	#
	# Constructor
	#
	def __init__(self, method='GET', requesturi='/', version=HTTPMsg.HTTP_VERSION):
		HTTPMsg.__init__(self, version)
		self.method = method
		self.requesturi = requesturi
		self.parseduri = urlparse(requesturi)

	#
	# startLine
	#
	def startLine(self) -> str:
		return '%s %s %s' % (self.method, self.requesturi, self.version)
	
	#
	# requestLine
	#
	def requestLine(self) -> str:
		return self.startLine()

####################################################################
# HTTPResp
####################################################################

class HTTPResp(HTTPMsg):
	#
	# Constructor
	#
	def __init__(self, version=HTTPMsg.HTTP_VERSION, status=200, phrase='OK'):
		HTTPMsg.__init__(self, version)
		self.status = int(status)
		self.phrase = phrase
		
	#
	# startLine
	#
	def startLine(self) -> str:
		return '%s %d %s' % (self.version, self.status, self.phrase)
	
	#
	# statusLine
	#
	def statusLine(self) -> str:
		return self.startLine()

####################################################################
# message_from_bytes
####################################################################

def message_from_bytes(buffer, encoding='utf_8'):
	"""
	StartLine 과 Headers 와 Content 를 포함한 bytes 타입의 데이터를 입력한다.
	반환되는 타입은 HTTPReq 이거나 HTTPResp 둘 중의 하나가 된다.
	encoding 은 utf_8 이 기본값이며 반드시 필요한 경우가 아니라면 이 기본값을 사용한다.
	"""
	parts = buffer.split(b'\r\n\r\n')
	head = parts[0]
	content = parts[1]
	
	text = head.decode(encoding)
	idx = text.find('\r\n')
	
	# startLine (Request-Line / Status-Line)
	# EX) GET /echo HTTP/1.1
	# EX) HTTP/1.1 200 OK
	startLine = text[:idx].strip()
	if startLine.startswith('HTTP/'):
		match = re.search(r'^([^\s]+)\s+(\d+)\s+(.+)$', startLine)
		version = match.group(1)
		status = match.group(2)
		phrase = match.group(3).strip()
		newmsg = HTTPResp(version, status, phrase)
	else:
		match = re.search(r'^([^\s]+)\s+([^\s]+)\s+(.+)$', startLine)
		method = match.group(1)
		requesturi = match.group(2)
		version = match.group(3).strip()
		newmsg = HTTPReq(method, requesturi, version)
	
	# headerlines
	# EX) Upgrade: websocket
	# EX) Sec-WebSocket-Version: 13
	headerlines = text[idx+1:].strip()
	headerParsed = message_from_string(headerlines)
	
	# headers: 키는 소문자 헤더이름이다.
	# EX) {'upgrade': ('Upgrade', 'websocket'), ...}
	for name in headerParsed:
		key = name.lower()
		value = headerParsed[name]
		newmsg.headers[key] = (name, value)
	
	if content and len(content) > 0:
		newmsg.content = content
	return newmsg

####################################################################
# message_from_socket
####################################################################

def message_from_socket(sock):
	buffer = bytearray()
	while True:
		b = sock.recv(1)
		buffer.append(ord(b))
		if buffer[-4:] == b'\r\n\r\n':
			break
	msg = message_from_bytes(buffer)
	clen = msg.headerAsInt('Content-Length', -1)
	if clen > 0:
		content = sock.recv(clen)
		msg.content = content
	return msg

####################################################################
# Test
####################################################################

class Test(unittest.TestCase):
	#
	# testRequestParsing
	#
	def testRequestParsing(self):
		test_req = """
GET /echo HTTP/1.1
Host: localhost:8080
Connection: Upgrade
Pragma: no-cache
Cache-Control: no-cache
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/86.0.4240.198 Safari/537.36
Upgrade: websocket
Origin: file://
Sec-WebSocket-Version: 13
Accept-Encoding: gzip, deflate, br
Accept-Language: ko-KR,ko;q=0.9,en-US;q=0.8,en;q=0.7
Sec-WebSocket-Key: VnnUzLgNPNQB2YXQDn/ceQ==
Sec-WebSocket-Extensions: permessage-deflate; client_max_window_bits
"""
		test_req = test_req.replace('\n', '\r\n').strip() + '\r\n\r\n'
		test_req_bytes = test_req.encode('utf_8')
		msg = message_from_bytes(test_req_bytes)
		assert test_req_bytes == msg.encode()
		assert msg.requestLine() == 'GET /echo HTTP/1.1'
		assert msg.method == 'GET'
		assert msg.requesturi == '/echo'
		assert msg.version == HTTPMsg.HTTP_VERSION
		assert msg.header('cache-control') == 'no-cache'
		assert msg.header('Cache-Control') == 'no-cache'
		assert msg.header('NO-header') == None
		assert msg.header('NO-header', '') == ''
		assert msg.content == None

	#
	# testRequestBuilding
	#
	def testRequestBuilding(self):
		test_req = """
GET /echo HTTP/1.1
Host: localhost:8080
Connection: Upgrade
Pragma: no-cache
Cache-Control: no-cache
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/86.0.4240.198 Safari/537.36
Upgrade: websocket
Origin: file://
Sec-WebSocket-Version: 13
Accept-Encoding: gzip, deflate, br
Accept-Language: ko-KR,ko;q=0.9,en-US;q=0.8,en;q=0.7
Sec-WebSocket-Key: VnnUzLgNPNQB2YXQDn/ceQ==
Sec-WebSocket-Extensions: permessage-deflate; client_max_window_bits
"""
		test_req = test_req.replace('\n', '\r\n').strip() + '\r\n\r\n'
		test_req_bytes = test_req.encode('utf_8')
		
		msg = HTTPReq(method='GET', requesturi='/echo')
		msg.addHeader('Host', 'localhost:8080')
		msg.addHeader('Connection', 'Upgrade')
		msg.addHeader('Pragma', 'no-cache')
		msg.addHeader('Cache-Control', 'no-cache')
		msg.addHeader('User-Agent', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/86.0.4240.198 Safari/537.36')
		msg.addHeader('Upgrade', 'websocket')
		msg.addHeader('Origin', 'file://')
		msg.addHeader('Sec-WebSocket-Version', '13')
		msg.addHeader('Accept-Encoding', 'gzip, deflate, br')
		msg.addHeader('Accept-Language', 'ko-KR,ko;q=0.9,en-US;q=0.8,en;q=0.7')
		msg.addHeader('Sec-WebSocket-Key', 'VnnUzLgNPNQB2YXQDn/ceQ==')
		msg.addHeader('Sec-WebSocket-Extensions', 'permessage-deflate; client_max_window_bits')
		assert test_req_bytes == msg.encode()
		assert msg.startLine() == 'GET /echo HTTP/1.1'
		assert msg.method == 'GET'
		assert msg.requesturi == '/echo'
		assert msg.version == HTTPMsg.HTTP_VERSION
		assert msg.header('cache-control') == 'no-cache'
		assert msg.header('Cache-Control') == 'no-cache'
		assert msg.header('NO-header') == None
		assert msg.header('NO-header', '') == ''
		assert msg.content == None

	#
	# testResponseParsing
	#
	def testResponseParsing(self):
		test_resp = """	
HTTP/1.1 101 Switching Protocols
Upgrade: websocket
Connection: Upgrade
Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=
Sec-WebSocket-Protocol: chat
"""
		test_resp = test_resp.replace('\n', '\r\n').strip() + '\r\n\r\n'
		test_resp_bytes = test_resp.encode('utf_8')
		msg = message_from_bytes(test_resp_bytes)
		assert test_resp_bytes == msg.encode()
		assert msg.statusLine() == 'HTTP/1.1 101 Switching Protocols'
		assert msg.version == HTTPMsg.HTTP_VERSION
		assert msg.status == 101
		assert msg.phrase == 'Switching Protocols'
		assert msg.header('Connection') == 'Upgrade'
		assert msg.header('CONNECTIOn') == 'Upgrade'
		assert msg.header('NO-header') == None
		assert msg.header('NO-header', '') == ''
		assert msg.content == None

	#
	# testResponseBuilding
	#
	def testResponseBuilding(self):
		test_resp = """	
HTTP/1.1 101 Switching Protocols
Upgrade: websocket
Connection: Upgrade
Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=
Sec-WebSocket-Protocol: chat
"""
		test_resp = test_resp.replace('\n', '\r\n').strip() + '\r\n\r\n'
		test_resp_bytes = test_resp.encode('utf_8')
		
		msg = HTTPResp(status=101, phrase='Switching Protocols')
		msg.addHeader('Upgrade', 'websocket')
		msg.addHeader('Connection', 'Upgrade')
		msg.addHeader('Sec-WebSocket-Accept', 's3pPLMBiTxaQ9kYGzzhZRbK+xOo=')
		msg.addHeader('Sec-WebSocket-Protocol', 'chat')
		assert test_resp_bytes == msg.encode()
		assert msg.startLine() == 'HTTP/1.1 101 Switching Protocols'
		assert msg.version == HTTPMsg.HTTP_VERSION
		assert msg.status == 101
		assert msg.phrase == 'Switching Protocols'
		assert msg.header('Connection') == 'Upgrade'
		assert msg.header('CONNECTIOn') == 'Upgrade'
		assert msg.header('NO-header') == None
		assert msg.header('NO-header', '') == ''
		assert msg.content == None
	
	#
	# testAddingHeaders
	#
	def testAddingHeaders(self):
		msg = HTTPResp(status=101, phrase='Switching Protocols')
		msg.addHeader('my-x-header', None)
		assert msg.header('my-X-header') == None
		msg.addHeader('my-x-header', '')
		assert msg.header('my-X-header') == None
		msg.addHeader('my-x-header', '   ')
		assert msg.header('my-X-header') == None
		msg.addHeader('my-x-header', 100)
		assert msg.header('my-X-header') == '100'