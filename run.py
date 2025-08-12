import eventlet
# QUAN TRỌNG: monkey_patch() phải được gọi đầu tiên, trước khi import app
eventlet.monkey_patch()

from app import app
from eventlet import wsgi

print(">>> Starting server with eventlet WSGI. Listening on http://127.0.0.1:5000")
print(">>> Press CTRL+C to quit.")
wsgi.server(eventlet.listen(('127.0.0.1', 5000)), app)
