#!/bin/sh
# Validate docs/ against the code and against docs/CONTRIBUTING.md.
# Usage: scripts/check-docs.sh
set -e
cd "$(dirname "$0")/.."
exec python3 - "$PWD" <<'PYEOF'
import os, re, sys

root = sys.argv[1]
DOCS = os.path.join(root, 'docs')
fail = []
def bad(check, msg):
    fail.append("%-14s %s" % (check + ':', msg))

def read(p):
    with open(os.path.join(root, p)) as f:
        return f.read()

# ---------------------------------------------------------------- config keys
cfg_c = read('config.c')
defines = dict(re.findall(r'^#define\s+([A-Z0-9_]+_DEF)\s+(.+?)\s*$', cfg_c, re.M))
# entries[] rows: { TYPE, "KEY", levels, modified, secret, .value.X = DEFAULT }
entries = {}
for m in re.finditer(r'\{\s*([A-Z_0-9]+)\s*,\s*"([A-Z0-9_]+)"\s*,[^{}]*?'
                     r'\.value\.([sib])\s*=\s*([^,}]+?)\s*\}', cfg_c):
    typ, key, slot, dflt = m.groups()
    entries[key] = (typ, slot, dflt.strip())

cfg_md = read('docs/reference/pantavisor-configuration.md').split('\n')
def table_keys(sep_prefix):
    i = next(n for n, l in enumerate(cfg_md) if l.startswith(sep_prefix))
    out = {}
    n = i + 1
    while n < len(cfg_md) and cfg_md[n].startswith('|'):
        km = re.match(r'\|\s*`([^`]+)`', cfg_md[n])
        if km:
            out[km.group(1)] = cfg_md[n]
        n += 1
    return out

summary = table_keys('|-----|-------|---------|-------------|')
levels  = table_keys('|-----|-------------------------')

# keys implemented outside entries[] but legitimately documented
EXTRA_OK = {'PV_SYSCTL_*', 'PV_SYSCTL_KERNEL_CORE_PATTERN', 'PV_REMOUNT_POLICY'}

for key in sorted(entries):
    if key not in summary:
        bad('config', "%s is in config.c entries[] but missing from the Summary table" % key)
    if key not in levels:
        bad('config', "%s is in config.c entries[] but missing from the Levels table" % key)
for key in sorted(set(summary) - set(entries) - EXTRA_OK):
    bad('config', "%s is documented but not in config.c entries[]" % key)
for key in sorted(set(levels) - set(summary)):
    bad('config', "%s is in the Levels table but not in the Summary table" % key)
for name, tbl in (('Summary', summary), ('Levels', levels)):
    ks = list(tbl)
    if ks != sorted(ks):
        bad('config', "the %s table is not sorted alphabetically" % name)

# defaults, where both sides are mechanically comparable
def code_default(slot, raw):
    raw = defines.get(raw, raw)
    if slot == 'b':
        return '1' if raw == 'true' else '0'
    if slot == 'i':
        return raw if re.fullmatch(r'-?\d+', raw) else None
    if raw == 'NULL':
        return ''
    m = re.fullmatch(r'"(.*)"', raw)
    return m.group(1) if m else None

for key, (typ, slot, raw) in sorted(entries.items()):
    want = code_default(slot, raw)
    if want is None or key not in summary:
        continue
    cells = [c.strip() for c in summary[key].split('|')]
    if len(cells) < 5:
        continue
    got = cells[3]
    got = '' if got == 'empty' else got
    gm = re.match(r'`([^`]*)`', got)
    got = gm.group(1) if gm else got
    if got != want:
        bad('config', "%s default is `%s` in the doc but `%s` in config.c" % (key, got or 'empty', want or 'empty'))

# ------------------------------------------------------------- ctrl endpoints
cmds_md = read('docs/reference/pantavisor-commands.md')
sections = set(re.findall(r'^## (/\S+)', cmds_md, re.M))
routes = set()
for fn in sorted(os.listdir(os.path.join(root, 'ctrl'))):
    if not fn.endswith('.c'):
        continue
    for m in re.finditer(r'pv_ctrl_add_endpoint\(\s*"([^"]+)"', read('ctrl/' + fn)):
        routes.add(m.group(1))
for r in sorted(routes):
    segs = [s for s in r.split('/') if s and s != '{}']
    if not segs:
        continue
    if '/' + segs[0] not in sections:
        bad('ctrl', "route %s has no '## /%s' section in pantavisor-commands.md" % (r, segs[0]))
        continue
    for s in segs[1:]:
        if s not in cmds_md:
            bad('ctrl', "route %s: segment '%s' is not mentioned in pantavisor-commands.md" % (r, s))

# ------------------------------------------------------------- devmeta keys
meta_md = read('docs/reference/pantavisor-metadata.md')
meta_h = read('metadata.h')
srcs = []
for dirpath, dirs, names in os.walk(root):
    dirs[:] = [d for d in dirs if d not in ('.git', 'docs', 'build')]
    for n in names:
        if n.endswith(('.c', '.h')):
            srcs.append(os.path.join(dirpath, n))
def macro_uses(macro):
    n = 0
    for f in srcs:
        try:
            with open(f, errors='ignore') as fh:
                n += fh.read().count(macro)
        except OSError:
            pass
    return n
for m in re.finditer(r'^#define\s+(DEVMETA_KEY_\w+)\s+"([^"]+)"', meta_h, re.M):
    macro, key = m.groups()
    # a macro nothing references produces no metadata, so it is not a doc gap
    if macro_uses(macro) < 2:
        continue
    if ('`%s`' % key) not in meta_md:
        bad('metadata', "device metadata key '%s' is not documented in pantavisor-metadata.md" % key)

# ------------------------------------------- frontmatter, indexes, and links
pages = []
for dirpath, _, names in os.walk(DOCS):
    for n in names:
        if n.endswith('.md'):
            pages.append(os.path.relpath(os.path.join(dirpath, n), DOCS))

def frontmatter(rel):
    txt = read(os.path.join('docs', rel))
    if not txt.startswith('---\n'):
        return {}
    end = txt.index('\n---\n', 4)
    fm = {}
    for line in txt[4:end].split('\n'):
        if ':' in line:
            k, v = line.split(':', 1)
            fm[k.strip()] = v.strip().strip('"')
    return fm

positions = {}
for rel in sorted(pages):
    fm = frontmatter(rel)
    if not fm:
        bad('frontmatter', "%s has no frontmatter" % rel)
        continue
    if fm.get('draft') == 'true':
        continue
    for field in ('title', 'sidebar_position', 'description'):
        if field not in fm:
            bad('frontmatter', "%s is missing '%s'" % (rel, field))
    folder = os.path.dirname(rel)
    pos = fm.get('sidebar_position')
    if pos is not None:
        if (folder, pos) in positions:
            bad('frontmatter', "%s and %s share sidebar_position %s" % (positions[(folder, pos)], rel, pos))
        positions[(folder, pos)] = rel
    # index membership
    if os.path.basename(rel) != 'index.md':
        idx = os.path.join(folder, 'index.md')
        if idx in pages and os.path.basename(rel) not in read(os.path.join('docs', idx)):
            bad('index', "%s is not linked from %s" % (rel, idx))

LINK = re.compile(r'\[[^\]]*\]\(([^)\s]+)\)')
def anchors_of(rel):
    out = set()
    for line in read(os.path.join('docs', rel)).split('\n'):
        m = re.match(r'^#+\s+(.*)', line)
        if m:
            a = re.sub(r'[^\w\s-]', '', m.group(1).lower()).strip().replace(' ', '-')
            out.add(a)
    return out
anchors = {rel: anchors_of(rel) for rel in pages}

for rel in sorted(pages):
    txt = read(os.path.join('docs', rel))
    # strip fenced blocks by line, then inline code spans, so only prose is checked
    prose_lines, fenced = [], False
    for line in txt.split('\n'):
        if line.lstrip().startswith('```'):
            fenced = not fenced
            continue
        if not fenced:
            prose_lines.append(re.sub(r'`[^`]*`', '', line))
    prose = '\n'.join(prose_lines)
    # the site renders MDX: a bare {expr} or <tag> outside code is evaluated as JSX
    for m in re.finditer(r'\{[A-Za-z_]|<[a-zA-Z][a-zA-Z0-9_-]*>', prose):
        bad('mdx', "%s has unescaped MDX syntax '%s' outside a code span" % (rel, m.group(0)))
    if '!!!' in prose:
        bad('mdx', "%s uses MkDocs '!!!' admonition syntax" % rel)
    if ':material-' in prose:
        bad('mdx', "%s uses a MkDocs Material icon code" % rel)
    for target in LINK.findall(txt):
        if target.startswith(('http', '#', 'mailto', '/')):
            continue
        path, _, anc = target.partition('#')
        if not path or not path.endswith('.md'):
            continue
        tgt = os.path.normpath(os.path.join(os.path.dirname(rel), path))
        if tgt.startswith('..'):        # cross-repo: only resolves on the site
            continue
        if tgt not in pages:
            bad('link', "%s -> %s (no such file)" % (rel, target))
        elif anc and anc not in anchors[tgt]:
            bad('link', "%s -> %s (no such anchor)" % (rel, target))

# ----------------------------------------------------- docs.pantahub.com redirects
# The pages listed in CONTRIBUTING.md are 301 targets from the retired MkDocs site.
# Renaming, deleting or drafting one turns a live redirect into a 404.
frozen = []
contrib = read('docs/CONTRIBUTING.md').split('\n')
i = next((n for n, l in enumerate(contrib) if l.startswith('| Page | Redirected from |')), None)
if i is None:
    bad('redirect', "CONTRIBUTING.md has no 'Page | Redirected from' table")
else:
    for line in contrib[i + 2:]:
        if not line.startswith('|'):
            break
        m = re.match(r'\|\s*\[`([^`]+)`\]', line)
        if m:
            frozen.append(m.group(1))
for rel in frozen:
    if rel not in pages:
        bad('redirect', "%s is a docs.pantahub.com redirect target but no longer exists" % rel)
    elif frontmatter(rel).get('draft') == 'true':
        bad('redirect', "%s is a docs.pantahub.com redirect target but is draft: true" % rel)

# ------------------------------------------------------------------- verdict
if fail:
    print("docs check FAILED (%d):\n" % len(fail))
    for line in fail:
        print("  " + line)
    sys.exit(1)
print("docs check OK: %d config keys, %d ctrl routes, %d pages, %d frozen URLs"
      % (len(entries), len(routes), len(pages), len(frozen)))
PYEOF
