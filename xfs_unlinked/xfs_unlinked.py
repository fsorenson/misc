#!/usr/bin/env python3
"""
xfs_unlinked.py - report inodes on the XFS unlinked (deleted-but-open) list

XFS tracks deleted-but-still-open inodes via per-AG hash bucket chains in
the AGI:
    AGI.unlinked[64]  ->  inode.next_unlinked  ->  ...  ->  null (0xffffffff)

All values in the chain are AG-relative inode numbers (agino).
Absolute inode number = (agno << (agblklog + inopblog)) | agino

Usage:
    xfs_unlinked.py <image-or-device>  [--min-size BYTES] [--sort size|mtime|ino]
"""

import subprocess
import sys
import argparse
from collections import defaultdict
from datetime import datetime

NULL_AGINO  = 0xffffffff
BATCH_SIZE  = 64          # inodes per xfs_db invocation

# ── helpers ───────────────────────────────────────────────────────────────────

def xdb(img, *cmds):
    args = ['xfs_db', '-r']
    for c in cmds:
        args += ['-c', c]
    args.append(img)
    r = subprocess.run(args, capture_output=True, text=True)
    return r.stdout

def parse_kv(out):
    """Parse 'key = value' lines from xfs_db output into a dict."""
    d = {}
    for line in out.splitlines():
        line = line.strip()
        if '=' not in line:
            continue
        k, _, v = line.partition('=')
        d[k.strip()] = v.strip()
    return d

def human(n):
    for unit, threshold in (('GiB', 1 << 30), ('MiB', 1 << 20), ('KiB', 1 << 10)):
        if n >= threshold:
            return f'{n / threshold:.1f} {unit}'
    return f'{n} B'

def parse_mode(mode_str):
    """Return (type_char, octal_str) from xfs_db mode string like '0100700'."""
    try:
        m = int(mode_str, 8)
    except ValueError:
        return '?', mode_str
    fmt = (m >> 12) & 0xf
    type_char = {0o10: '-', 0o04: 'd', 0o12: 'l', 0o06: 'b',
                 0o02: 'c', 0o01: 'p', 0o14: 's'}.get(fmt, '?')
    perms = oct(m & 0o7777)[2:].zfill(4)
    return type_char, perms

def parse_mtime(ts_str):
    """
    xfs_db prints mtime.sec as a ctime-style string, e.g.
        'Tue Jul  7 18:19:56 2026'
    Returns (datetime, str) or (None, ts_str) on failure.
    """
    ts_str = ' '.join(ts_str.split())   # collapse multiple spaces
    for fmt in ('%a %b %d %H:%M:%S %Y', '%a %b  %d %H:%M:%S %Y'):
        try:
            return datetime.strptime(ts_str, fmt), ts_str
        except ValueError:
            pass
    return None, ts_str

# ── superblock read ───────────────────────────────────────────────────────────

def read_sb(img):
    out = xdb(img, 'sb 0', 'p agcount agblklog inopblog')
    d = parse_kv(out)
    return {
        'agcount':  int(d.get('agcount',  4)),
        'agblklog': int(d.get('agblklog', 20)),
        'inopblog': int(d.get('inopblog', 3)),
    }

# ── AGI unlinked bucket collection ───────────────────────────────────────────

def collect_heads(img, sb):
    ag_shift = sb['agblklog'] + sb['inopblog']
    heads = []   # (agno, abs_ino)
    for agno in range(sb['agcount']):
        out = xdb(img, f'agi {agno}', 'p unlinked')
        ag_base = agno << ag_shift
        for line in out.splitlines():
            if 'unlinked' not in line or '=' not in line:
                continue
            val_part = line.split('=', 1)[1].strip()
            for token in val_part.split():
                agino_str = token.split(':', 1)[-1]
                try:
                    agino = int(agino_str)
                except ValueError:
                    continue
                if agino != NULL_AGINO:
                    heads.append((agno, ag_base | agino))
    return heads, ag_shift

# ── batched inode query ───────────────────────────────────────────────────────

_FIELDS = 'core.size core.nlinkv2 core.uid core.gid core.mode core.nblocks core.mtime.sec next_unlinked'

def batch_query(img, agno_ino_pairs):
    """
    Query all requested fields for each inode in a single xfs_db call.
    Returns dict: abs_ino -> raw field dict.
    """
    if not agno_ino_pairs:
        return {}
    abs_inodes = [ino for _, ino in agno_ino_pairs]
    cmds = []
    for ino in abs_inodes:
        cmds += [f'inode {ino}', f'p {_FIELDS}']
    out = xdb(img, *cmds)

    results = {}
    cur_ino_iter = iter(abs_inodes)
    cur_ino = None
    cur = {}

    for line in out.splitlines():
        line = line.strip()
        if not line or '=' not in line:
            continue
        k, _, v = line.partition('=')
        k, v = k.strip(), v.strip()

        if k == 'core.size':
            # flush previous inode
            if cur_ino is not None and cur:
                results[cur_ino] = cur
            cur_ino = next(cur_ino_iter, None)
            cur = {k: v}
        elif cur_ino is not None:
            cur[k] = v

    if cur_ino is not None and cur:
        results[cur_ino] = cur

    return results

# ── BFS chain traversal ───────────────────────────────────────────────────────

def traverse(img, heads, ag_shift):
    visited  = {}   # abs_ino -> raw field dict + 'agno'
    frontier = list(heads)
    round_n  = 0

    while frontier:
        round_n += 1
        seen_this = set()
        to_query  = []
        for agno, abs_ino in frontier:
            if abs_ino not in visited and abs_ino not in seen_this:
                to_query.append((agno, abs_ino))
                seen_this.add(abs_ino)

        new_frontier = []
        for i in range(0, len(to_query), BATCH_SIZE):
            batch   = to_query[i:i + BATCH_SIZE]
            results = batch_query(img, batch)
            for agno, abs_ino in batch:
                raw = results.get(abs_ino)
                if raw is None:
                    continue
                raw['agno'] = agno
                visited[abs_ino] = raw
                nxt_str = raw.get('next_unlinked', 'null')
                nxt = NULL_AGINO if nxt_str == 'null' else int(nxt_str)
                if nxt != NULL_AGINO:
                    new_frontier.append((agno, (agno << ag_shift) | nxt))

        print(f'  round {round_n}: {len(visited)} inodes visited, '
              f'{len(new_frontier)} in next frontier', file=sys.stderr, flush=True)
        frontier = new_frontier

    return visited

# ── reporting ─────────────────────────────────────────────────────────────────

def build_records(visited):
    records = []
    for abs_ino, raw in visited.items():
        size     = int(raw.get('core.size', 0))
        nblocks  = int(raw.get('core.nblocks', 0))
        nlink    = int(raw.get('core.nlinkv2', 0))
        uid      = int(raw.get('core.uid', 0))
        gid      = int(raw.get('core.gid', 0))
        mode_str = raw.get('core.mode', '0')
        mtime_s  = raw.get('core.mtime.sec', '')
        agno     = raw['agno']
        type_char, perms = parse_mode(mode_str)
        mtime_dt, mtime_disp = parse_mtime(mtime_s)
        records.append({
            'ino':        abs_ino,
            'agno':       agno,
            'type':       type_char,
            'perms':      perms,
            'uid':        uid,
            'gid':        gid,
            'size':       size,
            'nblocks':    nblocks,
            'nlink':      nlink,
            'mtime_dt':   mtime_dt,
            'mtime_disp': mtime_disp,
        })
    return records

def print_table(records, sort_key, min_size):
    filtered = [r for r in records if r['size'] >= min_size]

    if sort_key == 'size':
        filtered.sort(key=lambda r: r['size'], reverse=True)
    elif sort_key == 'mtime':
        filtered.sort(key=lambda r: (r['mtime_dt'] or datetime.min), reverse=True)
    elif sort_key == 'ino':
        filtered.sort(key=lambda r: r['ino'])

    # column widths
    INO_W   = 12
    AG_W    = 3
    TYPE_W  = 5     # "type"
    PERM_W  = 6
    UID_W   = 6
    GID_W   = 6
    BLK_W   = 8
    SZ_W    = 15
    HSZ_W   = 9
    DT_W    = 25

    hdr = (f"{'inode':>{INO_W}}  {'AG':>{AG_W}}  {'type':<{TYPE_W}}  "
           f"{'perms':<{PERM_W}}  {'uid':>{UID_W}}  {'gid':>{GID_W}}  "
           f"{'blocks':>{BLK_W}}  {'size (bytes)':>{SZ_W}}  {'size':>{HSZ_W}}  "
           f"{'mtime':<{DT_W}}")
    sep = '-' * len(hdr)
    print(hdr)
    print(sep)

    for r in filtered:
        mtime_col = r['mtime_disp'][:DT_W] if r['mtime_disp'] else ''
        print(f"{r['ino']:>{INO_W}}  {r['agno']:>{AG_W}}  {r['type']:<{TYPE_W}}  "
              f"{r['perms']:<{PERM_W}}  {r['uid']:>{UID_W}}  {r['gid']:>{GID_W}}  "
              f"{r['nblocks']:>{BLK_W}}  {r['size']:>{SZ_W},}  "
              f"{human(r['size']):>{HSZ_W}}  {mtime_col:<{DT_W}}")

    return filtered

def print_summary(records, filtered, min_size):
    total_inodes = len(records)
    total_bytes  = sum(r['size'] for r in records)
    shown_inodes = len(filtered)
    shown_bytes  = sum(r['size'] for r in filtered)

    print()
    print('=' * 72)
    print('SUMMARY')
    print('=' * 72)
    print(f'  Total unlinked inodes:  {total_inodes:>8,}')
    print(f'  Total space held:       {total_bytes:>15,} bytes  ({human(total_bytes)})')
    if min_size > 0:
        print(f'  Shown (>= {human(min_size)}):      {shown_inodes:>8,}  ({human(shown_bytes)})')

    # by file type
    by_type = defaultdict(lambda: [0, 0])
    for r in records:
        by_type[r['type']][0] += 1
        by_type[r['type']][1] += r['size']
    print()
    print('  By file type:')
    type_names = {'-': 'regular file', 'd': 'directory', 'l': 'symlink',
                  'b': 'block dev',    'c': 'char dev',  'p': 'fifo',
                  's': 'socket',       '?': 'unknown'}
    for tc, (cnt, sz) in sorted(by_type.items(), key=lambda x: -x[1][1]):
        print(f'    {tc}  {type_names.get(tc, tc):<14}  {cnt:>6,} inodes  {sz:>15,} bytes  ({human(sz)})')

    # mtime range
    dated = [r for r in records if r['mtime_dt'] is not None]
    if dated:
        oldest = min(dated, key=lambda r: r['mtime_dt'])
        newest = max(dated, key=lambda r: r['mtime_dt'])
        print()
        print('  mtime range:')
        print(f'    oldest:  {oldest["mtime_disp"]}  (inode {oldest["ino"]})')
        print(f'    newest:  {newest["mtime_disp"]}  (inode {newest["ino"]})')

    # top recurring sizes (likely held by the same process/application)
    size_counts = defaultdict(int)
    for r in records:
        if r['size'] > 0:
            size_counts[r['size']] += 1
    if size_counts:
        top = sorted(size_counts.items(), key=lambda x: x[0] * x[1], reverse=True)[:10]
        print()
        print('  Most space-consuming distinct sizes (count × size):')
        print(f"    {'size (bytes)':>15}  {'human':>9}  {'count':>7}  {'total':>12}  pattern?")
        print(f"    {'-'*15}  {'-'*9}  {'-'*7}  {'-'*12}  --------")
        for sz, cnt in top:
            print(f'    {sz:>15,}  {human(sz):>9}  {cnt:>7,}  {sz*cnt:>12,}')

    # uid breakdown
    uid_counts = defaultdict(lambda: [0, 0])
    for r in records:
        uid_counts[r['uid']][0] += 1
        uid_counts[r['uid']][1] += r['size']
    if uid_counts:
        print()
        print('  By uid:')
        for uid, (cnt, sz) in sorted(uid_counts.items(), key=lambda x: -x[1][1])[:5]:
            print(f'    uid {uid:>6}:  {cnt:>6,} inodes  {sz:>15,} bytes  ({human(sz)})')

# ── main ──────────────────────────────────────────────────────────────────────

def main():
    ap = argparse.ArgumentParser(
        description='Report inodes on the XFS unlinked (deleted-but-open) list '
                    'using xfs_db.')
    ap.add_argument('image', help='XFS image file or block device')
    ap.add_argument('--min-size', metavar='BYTES', type=int, default=0,
                    help='only show inodes with size >= BYTES in the detail table '
                         '(all are counted in the summary)')
    ap.add_argument('--sort', choices=['size', 'mtime', 'ino'], default='size',
                    help='sort detail table by this field (default: size)')
    ap.add_argument('--summary-only', action='store_true',
                    help='skip the per-inode table; print only the summary')
    args = ap.parse_args()

    img = args.image

    print(f'Reading superblock from {img} ...', file=sys.stderr, flush=True)
    sb = read_sb(img)
    ag_shift = sb['agblklog'] + sb['inopblog']
    print(f'  agcount={sb["agcount"]}  agblklog={sb["agblklog"]}  '
          f'inopblog={sb["inopblog"]}  ag_shift={ag_shift}',
          file=sys.stderr)

    print('Collecting unlinked chain heads from AGIs ...', file=sys.stderr, flush=True)
    heads, ag_shift = collect_heads(img, sb)
    print(f'  {len(heads)} heads across {sb["agcount"]} AGs', file=sys.stderr)

    if not heads:
        print('No unlinked inodes found.', file=sys.stderr)
        sys.exit(0)

    print('Traversing unlinked chains ...', file=sys.stderr, flush=True)
    visited = traverse(img, heads, ag_shift)
    print(f'Traversal complete: {len(visited)} unlinked inodes total',
          file=sys.stderr, flush=True)

    records = build_records(visited)

    if not args.summary_only:
        print()
        print(f'Unlinked inodes on {img}'
              + (f'  (showing size >= {human(args.min_size)})' if args.min_size else ''))
        print()
        filtered = print_table(records, args.sort, args.min_size)
    else:
        filtered = [r for r in records if r['size'] >= args.min_size]

    print_summary(records, filtered, args.min_size)

if __name__ == '__main__':
    main()
