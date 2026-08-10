from http.server import BaseHTTPRequestHandler,HTTPServer
import os
from urllib.parse import urlparse

class Handler(BaseHTTPRequestHandler):
	def _send(self,code,body):
		self.send_response(code)
		self.send_header("Content-type","text/html;charset=utf-8")
		self.end_headers()
		self.wfile.write(body.encode("utf-8"))

	def do_GET(self):
		path= urlparse(self.path).path
		if path=="/" :
			self._send(200,
			"""
			<html>
			<body>
			<h1>My DAST LAB App</h1>
			<p>This is the  staging version of my app</p>
			<ul>
			<li> <a href="/numbers">Numbers</a> </li>
			<li> <a href="/about" >About</a> </li>
			<li> <a href="/login" >Login</a> </li>
			</ul>
			</body>
			</html>
			""",)
		elif path == "/numbers":
			numbers = "".join(f"<li>{i}</li>" for i in range(6))
			self._send( 200 ,
			f"""
			<html>
			<body>
			<h1>Numbers</h1>
			<ul>{numbers}</ul>
			</body>
			</html>
			""",)
		elif path == "/about" :
			self._send(200 , """
			<html>
			<body>
			<h1>About</h1>
			<p>This is a simple app used to for DAST practice</p>
			</body>
			</html> """)
		elif path =="/login" :
			self._send(200,"""
			<html>
			<body>
			<h1>Login</h1>
			<form method="post">
			<label>Username</label>
			<br>
			<label>Password</label>
			<input type="password" name="password"/>
			<br>
			<button type="submit" >Submit</button>
			</form>
			</body>
			</html> """,)
		else:
			self._send(404,"<h1>404 Not found</h1?")
port= int(os.environ.get("PORT","5000"))
server = HTTPServer(("0.0.0.0",port),Handler)
print(f"Server running on port {port}")
server.serve_forever()
