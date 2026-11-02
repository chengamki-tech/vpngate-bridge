"""Allow diagnostics directly; require a live lease for network service."""
import os
import signal
import subprocess
import sys
from vpngate_bridge.lease import supervise


def main(args):
    if not args:
        raise ValueError('sing-box command required')
    if args[0] in ('check', 'version', 'format'):
        return subprocess.run(['sing-box', *args], check=False).returncode
    if args[0] != 'run':
        raise ValueError('unsupported bridge command')
    def terminate(*_):
        raise SystemExit(143)
    signal.signal(signal.SIGTERM, terminate)
    return supervise('/run/vgb/lease.json', os.environ['BRIDGE_RUN_ID'], ['sing-box', *args])


if __name__ == '__main__':
    try:
        sys.exit(main(sys.argv[1:]))
    except (ValueError, RuntimeError, KeyError, OSError):
        print('bridge startup rejected: valid generation and lease required', file=sys.stderr)
        sys.exit(1)
