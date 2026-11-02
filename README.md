# VPNGate Bridge

Work in progress. This repository is not yet deployable and does not provide a proxy or subscription service. Only discovery is implemented; candidates are untrusted and have not been probed or verified as residential.

Run tests: `python3 -m unittest discover -s tests`.

VPNGate is operated by volunteers and its [logging policy](https://www.vpngate.net/en/about_abuse.aspx) describes connection and destination metadata logging. A non-hosting IP classification does not prove an address is residential or that service will be stable.

The pure selection module checks country, hosting classification, exit uniqueness, three latency measurements and a persistent expiring subnet blacklist. It does **not** yet perform network measurements or obtain hosting classifications. Its score caps latency at 1 s, measured throughput at 100 Mbit/s and uptime at 7 days; requiring all three probes to succeed makes the stability component constant for eligible candidates. These normalization choices are provisional.

The OpenVPN parser pins the relay IP and accepts only a limited set of directives and inline PEM blocks. It is not a network sandbox: firewall, DNS and IPv6 leak protection must be implemented and independently tested before running candidates.
