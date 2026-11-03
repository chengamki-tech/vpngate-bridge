"""Apply only the final-counter hooks to the exact upstream revision we build."""
import shutil
import subprocess
import sys
from pathlib import Path


def main(root):
    root = Path(root)
    revision = subprocess.check_output(['git', '-C', str(root), 'rev-parse', 'HEAD'], text=True).strip()
    if revision != 'c005f35300ce76427dc285481ec5695f5b179cd2':
        raise RuntimeError('unsupported sing-box revision')
    tracked = ['experimental/v2rayapi/stats.go', 'experimental/v2rayapi/server.go',
               'adapter/lifecycle.go', 'route/conn.go', 'box.go']
    subprocess.run(['git', '-C', str(root), 'diff', '--exit-code', '--', *tracked], check=True)
    replacements = {
        'stats.go': [
            ('\tcounters  map[string]*atomic.Int64\n', '\tcounters  map[string]*atomic.Int64\n\tfinalState finalState\n'),
            ('return bufio.NewInt64CounterConn(conn, readCounter, writeCounter)',
             'return s.guardTCP(bufio.NewInt64CounterConn(conn, readCounter, writeCounter))'),
            ('return bufio.NewInt64CounterPacketConn(conn, readCounter, nil, writeCounter, nil)',
             'return s.guardPacket(bufio.NewInt64CounterPacketConn(conn, readCounter, nil, writeCounter, nil))'),
            ('func (s *StatsService) RoutedFlow(ctx context.Context, metadata adapter.InboundContext, matchedRule adapter.Rule, matchOutbound adapter.Outbound) tun.FlowTracker {',
             'func (s *StatsService) RoutedFlow(ctx context.Context, metadata adapter.InboundContext, matchedRule adapter.Rule, matchOutbound adapter.Outbound) tun.FlowTracker {\n\ts.finalState.unsupported.Store(true)'),
        ],
        'server.go': [('\t\t\ts.grpcServer.Stop()\n\t\t\treturn nil',
                       '\t\t\ts.grpcServer.Stop()\n\t\t\treturn s.statsService.writeFinal()')],
    }
    target = root / 'experimental/v2rayapi'
    updates = {}
    for name, changes in replacements.items():
        text = (target / name).read_text()
        for old, new in changes:
            if text.count(old) != 1:
                raise RuntimeError('upstream finalization hook changed: ' + name)
            text = text.replace(old, new, 1)
        updates[name] = text
    for name in ('final_stats.go', 'final_stats_test.go'):
        if (target / name).exists():
            raise RuntimeError('final counter extension already exists')
    for name, text in updates.items():
        (target / name).write_text(text)
    for name in ('final_stats.go', 'final_stats_test.go'):
        shutil.copyfile(Path(__file__).parent / name, target / name)


if __name__ == '__main__':
    main(sys.argv[1])
