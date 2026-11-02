"""Generate a disposable config for the sing-box configuration checker."""
import json
from pathlib import Path
from vpngate_bridge.bridge import Client, Country, build_config

config = build_config([Country('JP', '172.18.0.3', 1080, 20000, 20001)],
                      [Client('ci', 'bf000d23-0752-40b4-affe-68f7707a9661', 'temporary-test-password')],
                      '/work/cert.pem', '/work/key.pem')
Path('/tmp/vpngate-bridge-ci/config.json').write_text(json.dumps(config))
