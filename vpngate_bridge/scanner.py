"""Scan through disposable gateways and return measured winners only."""
import ipaddress
import logging

from .probe import ProbeError, probe
from .selection import choose, score


def scan(grouped, gateways, api_key, blocked, max_countries, *, exclude_exits=()):
    if type(max_countries) is not int or max_countries < 1:
        raise ValueError('max_countries must be positive')
    blocked = tuple(blocked)
    networks = tuple(ipaddress.ip_network(item) for item in blocked)
    excluded = {str(ipaddress.ip_address(ip)) for ip in exclude_exits}
    results, sources = [], {}
    for country, candidates in sorted(grouped.items()):
        for candidate in candidates:
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
                continue
            if result.exit_ip in excluded:
                continue
            results.append(result)
            sources[id(result)] = candidate
    winners = choose(results, blocked)
    ordered = sorted(winners.items(), key=lambda item: (-score(item[1]), item[0]))[:max_countries]
    return {country: (sources[id(result)], result) for country, result in ordered}
