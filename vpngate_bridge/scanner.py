"""Scan through disposable gateways and return measured winners only."""
import ipaddress
import logging
import time

from .probe import ClassificationError, ProbeError, probe
from .selection import choose, score


def scan(grouped, gateways, api_key, blocked, max_countries, *, exclude_exits=(), blacklist=None, now=None, stop_event=None):
    if type(max_countries) is not int or max_countries < 1:
        raise ValueError('max_countries must be positive')
    if now is None:
        now = time.time()
    blocked = set(blocked)
    if blacklist is not None:
        blocked.update(blacklist.active(now))
    networks = [ipaddress.ip_network(item) for item in blocked]

    def reject(candidate):
        address = ipaddress.ip_address(candidate.ip)
        network = ipaddress.ip_network(f'{address}/{24 if address.version == 4 else 64}', strict=False)
        if blacklist is not None:
            blacklist.add(candidate.ip, 'candidate failed eligibility probe', now)
        blocked.add(str(network))
        networks.append(network)

    excluded = {str(ipaddress.ip_address(ip)) for ip in exclude_exits}
    results, sources = [], {}
    for country, candidates in sorted(grouped.items()):
        for candidate in candidates:
            if stop_event is not None and stop_event.is_set():
                return {}
            if candidate.country != country:
                raise ValueError('candidate country does not match group')
            address = ipaddress.ip_address(candidate.ip)
            if any(address in network for network in networks):
                continue
            try:
                with gateways.open(candidate) as proxy:
                    result = probe(candidate, proxy, api_key)
            except ProbeError as exc:
                logging.info('candidate in %s rejected: %s', country, exc)
                if not isinstance(exc, ClassificationError):
                    reject(candidate)
                continue
            if result.expected_country != country or score(result) is None:
                reject(candidate)
                continue
            if result.exit_ip in excluded:
                continue
            results.append(result)
            sources[id(result)] = candidate
    if stop_event is not None and stop_event.is_set():
        return {}
    # A later failure invalidates earlier results from the same relay subnet too.
    results = [result for result in results
               if not any(ipaddress.ip_address(sources[id(result)].ip) in network for network in networks)]
    winners = choose(results, blocked)
    ordered = sorted(winners.items(), key=lambda item: (-score(item[1]), item[0]))[:max_countries]
    return {country: (sources[id(result)], result) for country, result in ordered}
