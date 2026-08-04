from http.server import BaseHTTPRequestHandler, HTTPServer
import json

class MyHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        print("POST received!")
        print("Path:", self.path)
        print("Headers:")
        for k, v in self.headers.items():
            print(f"  {k}: {repr(v)}")
        length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(length)
        print("Body:", repr(body))
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.end_headers()
        self.wfile.write(b'{"status":"success"}')

server = HTTPServer(('127.0.0.1', 8080), MyHandler)
print("Listening on 8080...")
server.handle_request()
