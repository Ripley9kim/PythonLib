// ------------------------------------------------
// Websocket
// ------------------------------------------------

url = "ws://localhost:8080"
w = new WebSocket(url);

w.onopen = function() {
	console.log("WebSocket(onopen)");
	w.send(" 공백하나로시작; thank you for accepting this Web Socket request 되는걸.\r\n\t ");
}

var lastmessage;
w.onmessage = function(e) {
	lastmessage = e;
	console.log("WebSocket(onmessage): ", e.data.toString());
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