"""Stable, host-private TCP endpoints for replacing OpenVPN SOCKS backends."""
import asyncio
import ipaddress
import json
import logging
import os
import re
import tempfile
import threading
from pathlib import Path

from .bridge import Country


class GatewayRouter:
    """GatewayPool publisher; sing-box must run on the same Linux host."""

    def __init__(self, host, manifest_path, *, max_connections=256):
        address = ipaddress.ip_address(host)
        if address.version != 4 or not address.is_private or address.is_unspecified or address.is_link_local:
            raise ValueError('a local private IPv4 bind address is required')
        if type(max_connections) is not int or max_connections < 1:
            raise ValueError('positive connection limit required')
        self.host, self.path, self.limit = str(address), Path(manifest_path), max_connections
        self._servers, self._routes, self._ports, self._connections = {}, {}, {}, {}
        self._closed = False
        self._lock = threading.RLock()
        self._loop = asyncio.new_event_loop()
        self._thread = threading.Thread(target=self._loop.run_forever, daemon=True)
        self._thread.start()

    def publish(self, routes):
        with self._lock:
            if self._closed:
                raise RuntimeError('gateway router is closed')
            return asyncio.run_coroutine_threadsafe(self._publish(dict(routes)), self._loop).result()

    def countries(self):
        with self._lock:
            if self._closed:
                return []
            return asyncio.run_coroutine_threadsafe(self._countries(), self._loop).result()

    async def _countries(self):
        return [Country(code, self.host, self._servers[code].sockets[0].getsockname()[1],
                        route.vless_port, route.hy2_port) for code, route in sorted(self._routes.items())]

    async def _publish(self, routes):
        ports = dict(self._ports)
        for code, route in routes.items():
            address = ipaddress.ip_address(route.socks_host)
            if (not re.fullmatch(r'[A-Z]{2}', code) or route.country != code or address.version != 4
                    or not address.is_private or address.is_unspecified or address.is_link_local
                    or any(type(port) is not int or not 1 <= port <= 65535
                           for port in (route.socks_port, route.vless_port, route.hy2_port))):
                raise ValueError('invalid private country route')
            pair = (route.vless_port, route.hy2_port)
            if code in ports and ports[code] != pair:
                raise ValueError('public country ports cannot change')
            ports[code] = pair
        assigned = [port for pair in ports.values() for port in pair]
        if len(set(assigned)) != len(assigned):
            raise ValueError('duplicate public country port')
        staged = {}
        try:
            if any(server.sockets[0].getsockname()[1] in assigned for server in self._servers.values()):
                raise ValueError('public port conflicts with an existing private listener')
            for code in routes.keys() - self._servers.keys():
                async def accept(reader, writer, country=code):
                    await self._relay(country, reader, writer)
                for _ in range(32):
                    server = await asyncio.start_server(accept, self.host, 0)
                    if server.sockets[0].getsockname()[1] not in assigned:
                        staged[code] = server
                        break
                    server.close()
                    await server.wait_closed()
                else:
                    raise OSError('could not allocate a nonconflicting private port')
            servers = {**self._servers, **staged}
            endpoints = {(self.host, server.sockets[0].getsockname()[1]) for server in servers.values()}
            if any((route.socks_host, route.socks_port) in endpoints for route in routes.values()):
                raise ValueError('recursive gateway route')
            manifest = {code: {'socks_host': self.host, 'socks_port': servers[code].sockets[0].getsockname()[1],
                               'vless_port': route.vless_port, 'hy2_port': route.hy2_port,
                               'server_ip': route.server_ip, 'exit_ip': route.exit_ip}
                        for code, route in sorted(routes.items())}
            self._write_manifest(manifest)
        except BaseException:
            for server in staged.values():
                server.close()
                await server.wait_closed()
            raise
        # Nothing awaits between committing the manifest and the in-memory targets.
        previous = self._routes
        self._servers.update(staged)
        self._ports, self._routes = ports, routes
        for writer, (code, upstream) in tuple(self._connections.items()):
            if previous.get(code) != routes.get(code):
                writer.close()
                if upstream is not None:
                    upstream.close()
        return await self._countries()

    def _write_manifest(self, countries):
        filename = None
        try:
            with tempfile.NamedTemporaryFile('w', dir=self.path.parent, prefix='.routes-', delete=False) as output:
                filename = output.name
                json.dump({'countries': countries}, output, sort_keys=True)
                output.write('\n')
                output.flush()
                os.fsync(output.fileno())
            os.replace(filename, self.path)
        finally:
            if filename and os.path.exists(filename):
                os.unlink(filename)

    async def _relay(self, code, reader, writer):
        upstream = None
        route = self._routes.get(code)
        try:
            # A private bind alone does not prevent routed LAN access to host addresses.
            peer = writer.get_extra_info('peername')[0]
            if peer != self.host:
                logging.warning('private gateway relay rejected source %s (expected %s)', peer, self.host)
                return
            if route is None or len(self._connections) >= self.limit:
                return
            self._connections[writer] = (code, None)
            remote_reader, upstream = await asyncio.wait_for(
                asyncio.open_connection(route.socks_host, route.socks_port), timeout=10)
            if self._routes.get(code) != route or writer.is_closing():
                return
            self._connections[writer] = (code, upstream)

            async def pump(source, destination):
                while True:
                    data = await source.read(65536)
                    if not data:
                        if destination.can_write_eof():
                            destination.write_eof()
                        return
                    destination.write(data)
                    await destination.drain()

            await asyncio.gather(pump(reader, upstream), pump(remote_reader, writer))
        except (OSError, asyncio.TimeoutError) as exc:
            logging.warning('private gateway relay failed: %s (errno=%s)', type(exc).__name__, getattr(exc, 'errno', None))
        finally:
            self._connections.pop(writer, None)
            writer.close()
            if upstream is not None:
                upstream.close()

    async def _shutdown(self):
        self._routes.clear()
        for server in self._servers.values():
            server.close()
            await server.wait_closed()
        tasks = asyncio.all_tasks(self._loop) - {asyncio.current_task()}
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)

    def close(self):
        with self._lock:
            if self._closed:
                return
            try:
                self._write_manifest({})
            finally:
                asyncio.run_coroutine_threadsafe(self._shutdown(), self._loop).result()
                self._closed = True
                self._loop.call_soon_threadsafe(self._loop.stop)
                self._thread.join()
                self._loop.close()
