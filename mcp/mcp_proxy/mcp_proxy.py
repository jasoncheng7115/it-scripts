#!/usr/bin/env python3
"""
MCP HTTP Proxy - Single port proxy for all MCP servers.

A simple HTTP/HTTPS proxy that allows MCP servers to connect to
remote hosts through a single local port.

Usage:
    python mcp_proxy.py [port]     # Default: 28080

Then set in Claude Desktop config for each MCP server:
    "env": {
        "HTTP_PROXY": "http://127.0.0.1:28080",
        "HTTPS_PROXY": "http://127.0.0.1:28080",
        ...
    }

Author: Jason Cheng (jason@jason.tools)
License: MIT
"""

import asyncio
import sys
import re

DEFAULT_PORT = 28080


async def pipe(reader, writer):
    """Copy data bidirectionally"""
    try:
        while True:
            data = await reader.read(65536)
            if not data:
                break
            writer.write(data)
            await writer.drain()
    except:
        pass
    finally:
        try:
            writer.close()
            await writer.wait_closed()
        except:
            pass


async def handle_client(client_reader, client_writer):
    """Handle HTTP CONNECT proxy requests"""
    try:
        # Read the request line
        request_line = await asyncio.wait_for(client_reader.readline(), timeout=30)
        if not request_line:
            return

        request = request_line.decode('utf-8', errors='ignore').strip()

        # Parse CONNECT request: CONNECT host:port HTTP/1.1
        match = re.match(r'CONNECT\s+([^:]+):(\d+)\s+HTTP/', request, re.IGNORECASE)

        if match:
            # HTTPS CONNECT tunnel
            host, port = match.group(1), int(match.group(2))

            # Read and discard headers
            while True:
                line = await client_reader.readline()
                if line in (b'\r\n', b'\n', b''):
                    break

            print(f"[CONNECT] {host}:{port}", flush=True)

            try:
                # Connect to target
                remote_reader, remote_writer = await asyncio.wait_for(
                    asyncio.open_connection(host, port),
                    timeout=30
                )

                # Send success response
                client_writer.write(b'HTTP/1.1 200 Connection Established\r\n\r\n')
                await client_writer.drain()

                # Bidirectional tunnel
                await asyncio.gather(
                    pipe(client_reader, remote_writer),
                    pipe(remote_reader, client_writer),
                    return_exceptions=True
                )

            except Exception as e:
                print(f"[ERROR] {host}:{port} - {e}", flush=True)
                client_writer.write(b'HTTP/1.1 502 Bad Gateway\r\n\r\n')
                await client_writer.drain()
        else:
            # Regular HTTP request - parse GET/POST etc
            match = re.match(r'(GET|POST|PUT|DELETE|HEAD|OPTIONS)\s+http://([^/:]+)(?::(\d+))?(/.*)?\s+HTTP/', request, re.IGNORECASE)
            if match:
                method, host, port, path = match.groups()
                port = int(port) if port else 80
                path = path or '/'

                print(f"[{method}] {host}:{port}{path}", flush=True)

                # Read headers
                headers = []
                while True:
                    line = await client_reader.readline()
                    if line in (b'\r\n', b'\n', b''):
                        break
                    # Skip proxy headers
                    if not line.lower().startswith(b'proxy-'):
                        headers.append(line)

                try:
                    remote_reader, remote_writer = await asyncio.wait_for(
                        asyncio.open_connection(host, port),
                        timeout=30
                    )

                    # Forward request
                    remote_writer.write(f'{method} {path} HTTP/1.1\r\n'.encode())
                    remote_writer.write(f'Host: {host}\r\n'.encode())
                    for h in headers:
                        remote_writer.write(h)
                    remote_writer.write(b'\r\n')
                    await remote_writer.drain()

                    # Bidirectional tunnel for response
                    await asyncio.gather(
                        pipe(client_reader, remote_writer),
                        pipe(remote_reader, client_writer),
                        return_exceptions=True
                    )

                except Exception as e:
                    print(f"[ERROR] {host}:{port} - {e}", flush=True)
                    client_writer.write(b'HTTP/1.1 502 Bad Gateway\r\n\r\n')
                    await client_writer.drain()
            else:
                print(f"[INVALID] {request[:50]}", flush=True)
                client_writer.write(b'HTTP/1.1 400 Bad Request\r\n\r\n')
                await client_writer.drain()

    except asyncio.TimeoutError:
        pass
    except Exception as e:
        print(f"[ERROR] {e}", flush=True)
    finally:
        try:
            client_writer.close()
            await client_writer.wait_closed()
        except:
            pass


async def main():
    port = int(sys.argv[1]) if len(sys.argv) > 1 else DEFAULT_PORT

    server = await asyncio.start_server(handle_client, '127.0.0.1', port)

    print("=" * 55, flush=True)
    print("MCP HTTP Proxy", flush=True)
    print("=" * 55, flush=True)
    print(f"Listening: 127.0.0.1:{port}", flush=True)
    print("", flush=True)
    print("Add to each MCP server env:", flush=True)
    print(f'  "HTTP_PROXY": "http://127.0.0.1:{port}"', flush=True)
    print(f'  "HTTPS_PROXY": "http://127.0.0.1:{port}"', flush=True)
    print("=" * 55, flush=True)

    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\nProxy stopped.", flush=True)
    except OSError as e:
        if e.errno in (48, 98):
            print(f"Error: Port already in use", flush=True)
            sys.exit(1)
        raise
