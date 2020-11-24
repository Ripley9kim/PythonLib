// ------------------------------------------------
// Websocket
// ------------------------------------------------

url = "ws://localhost:8080/echo"
w = new WebSocket(url);

w.onopen = function() {
	console.log("WebSocket(onopen)");
	
	w.send(" 공백하나로시작; test sequence 초기화 시퀀스 1/3 완료.\r\n\t ");
	
	// long binary data
	w.binaryType = "arraybuffer";
	var longdata = new Int8Array(1111);
	longdata.fill(20); // fill with space chars
	longdata[0] = 99
	longdata[longdata.length-1] = 100
	w.send(longdata);
	
	// very long binary data
	var extdata = new Int8Array(111111);
	extdata.fill(20); // fill with space chars
	extdata[0] = 99
	extdata[extdata.length-1] = 100
	w.send(extdata);
	
	// huge binary data
	/*
	var extdata = new Int8Array(11111111);
	extdata.fill(20); // fill with space chars
	extdata[0] = 99
	extdata[extdata.length-1] = 100
	w.send(extdata);
	*/
	
	// text data
	w.binaryType = "blob";
}

var lastmessage;
w.onmessage = function(e) {
	lastmessage = e;
	console.log("WebSocket(onmessage): ", e.data);
}

w.onclose = function(e) {
	console.log("WebSocket(onclose): ", e);
}

w.onerror = function(e) {
	console.log("WebSocket(onerror): ", e);
}

// ------------------------------------------------
// MISC
// ------------------------------------------------

window.onload = function() {
	$("#send").click(function() {
		var msg = $("#msg").val();
		console.log('sending...:', msg);
		w.send(msg);
	});
	
	$("#close").click(function() {
		console.log('closing...:');
		w.close();
	});
	
	console.log('WebSocket(created): obj=', w);
	console.log('WebSocket(created): url=', url);
}