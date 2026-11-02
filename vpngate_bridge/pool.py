"""Stage and revalidate private gateways before changing active routes."""
import ipaddress
import threading
from dataclasses import dataclass

from .probe import probe
from .selection import score


@dataclass(frozen=True)
class ActiveRoute:
    country: str
    server_ip: str
    exit_ip: str
    socks_host: str
    socks_port: int
    vless_port: int
    hy2_port: int


class GatewayPool:
    def __init__(self, gateways, ports, api_key, max_countries, publish):
        if type(max_countries) is not int or max_countries < 1:
            raise ValueError('max_countries must be positive')
        self.gateways, self.ports, self.api_key = gateways, ports, api_key
        self.max_countries, self.publish = max_countries, publish
        self._active = {}
        self._lock = threading.RLock()

    def routes(self):
        with self._lock:
            return {code: route for code, (route, _) in self._active.items()}

    def replace(self, candidate, blocked, *, expected_absent=False):
        with self._lock:
            code = candidate.country
            if expected_absent and code in self._active:
                raise ValueError('country was concurrently activated')
            if code not in self._active and len(self._active) >= self.max_countries:
                raise ValueError('country limit reached')
            networks = tuple(ipaddress.ip_network(net) for net in blocked)
            relay = ipaddress.ip_address(candidate.ip)
            if not relay.is_global or any(relay in net for net in networks):
                raise ValueError('relay is not eligible')
            vless_port, hy2_port = self.ports.assign(code)
            context = self.gateways.open(candidate)
            endpoint = context.__enter__()
            try:
                measurement = probe(candidate, endpoint, self.api_key)
                exit_ip = ipaddress.ip_address(measurement.exit_ip)
                if (measurement.expected_country != code or measurement.country != code or score(measurement) is None
                        or any(exit_ip in net for net in networks)
                        or any(route.exit_ip == str(exit_ip) for other, (route, _) in self._active.items() if other != code)):
                    raise ValueError('gateway did not pass activation checks')
                host, port = endpoint.rsplit(':', 1)
                ip = ipaddress.ip_address(host)
                if ip.version != 4 or not ip.is_private or ip.is_loopback or ip.is_link_local or not 1 <= int(port) <= 65535:
                    raise ValueError('invalid gateway endpoint')
                route = ActiveRoute(code, str(relay), str(exit_ip), str(ip), int(port), vless_port, hy2_port)
                proposed = self.routes()
                proposed[code] = route
                self.publish(proposed)
            except BaseException as exc:
                context.__exit__(type(exc), exc, exc.__traceback__)
                raise
            previous = self._active.get(code)
            self._active[code] = (route, context)
            if previous:
                previous[1].__exit__(None, None, None)
            return route

    def remove(self, country, *, expected=None):
        with self._lock:
            previous = self._active.get(country)
            if previous is None:
                return False
            if expected is not None and previous[0] != expected:
                raise ValueError('country route changed during health check')
            proposed = self.routes()
            del proposed[country]
            self.publish(proposed)
            del self._active[country]
            previous[1].__exit__(None, None, None)
            return True
