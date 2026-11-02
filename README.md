# VPNGate Bridge

Work in progress. This repository is not yet deployable and does not provide a proxy or subscription service. Only discovery is implemented; candidates are untrusted and have not been probed or verified as residential.

Run tests: `python3 -m unittest discover -s tests`.

VPNGate is operated by volunteers and its [logging policy](https://www.vpngate.net/en/about_abuse.aspx) describes connection and destination metadata logging. A non-hosting IP classification does not prove an address is residential or that service will be stable.

The pure selection module checks country, hosting classification, exit uniqueness, three latency measurements and a persistent expiring subnet blacklist. The `probe` module can measure a running SOCKS gateway with curl and classify its exit via ipapi.is, but no gateway orchestration exists yet. Its score caps latency at 1 s, measured throughput at 100 Mbit/s and uptime at 7 days; requiring all three probes to succeed makes the stability component constant for eligible candidates. These normalization choices are provisional.

The OpenVPN parser pins the relay IP and accepts only a limited set of directives and inline PEM blocks. It is not a network sandbox: firewall, DNS and IPv6 leak protection must be implemented and independently tested before running candidates.

The probe requires curl, an isolated SOCKS5 gateway, and an [ipapi.is API key](https://ipapi.is/developers.html) with `is_datacenter` data. It checks the exit three times through the SOCKS gateway, classifies that IP over HTTPS, then downloads 1 MB via Cloudflare for a speed sample. Classification errors and missing fields fail closed; the key is not passed to curl. The probe and provider integration have not been tested against a live VPNGate tunnel.
