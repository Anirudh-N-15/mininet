#!/usr/bin/env python3
"""The protected web server (h10): python's http.server with a realistic backlog.

    python3 -m egl.web_server [port]

python3 -m http.server listens with a backlog of only 5 connections, far below
real servers (nginx and Apache default to 511). With 5 slots, a handful of
spoofed SYNs would lock out every user and exaggerate the damage, so we use 511.
Each response closes its connection (HTTP/1.0), so every visit ends in a FIN.
"""

import os
import sys
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer


class Server(ThreadingHTTPServer):
    request_queue_size = 511   # = listen() backlog, the nginx/Apache default


def main():
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 80
    os.chdir("/tmp")
    Server(("", port), SimpleHTTPRequestHandler).serve_forever()


if __name__ == "__main__":
    main()
