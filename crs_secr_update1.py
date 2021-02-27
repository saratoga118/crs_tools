#!/usr/bin/env python3

import re
import argparse

parser = argparse.ArgumentParser(
    prog='PROG',
    formatter_class=argparse.ArgumentDefaultsHelpFormatter)
parser.add_argument('--maxargs', type=int, default=5, help='max number of args for target id updated')
parser.add_argument('file', nargs='*', help='file names')
args = parser.parse_args()

ms_re = re.compile(r"\bModSecurity:\s+")
at_re = re.compile(r"\s+at\s+([^.]+)")

fld_re = re.compile(r"\[(\w+)\s+\"([^\"]+)(.*)")

p_re = re.compile(r"^(/[^/]+)/")


def path1(s):
    m = p_re.search(s)
    return m.group(1)


def parse_line(line):
    res = {}
    m = at_re.search(line)
    if m:
        res["_at"] = m.group(1)
    while line:
        m = fld_re.search(line)
        if m:
            fld_name, contents, rest = m.groups()
            res.setdefault(fld_name, set())
            res[fld_name].add(contents)
            line = rest
        else:
            line = ''
    return res


at_list = {}
for infname in args.file:
    with open(infname) as infile:
        for line in infile:
            r = parse_line(line)
            if "id" in r:
                for rid in r["id"]:
                    at_list.setdefault(rid, {
                        "msg": r["msg"],
                        "_at": set(),
                        "uri": set()
                    }
                                       )
                    at_list[rid]["_at"].add(r["_at"])
                    for uri in r["uri"]:
                        at_list[rid]["uri"].add(uri)

s_upd = []
s_whitel = []

pfx_list = {}
for rid in sorted(at_list):
    p1 = [
        ("# Rule id %s - %s" % (rid, at_list[rid]["msg"])),
        ("# 'at' list: %s" % str(at_list[rid]["_at"])),
        ("# uri list: %s" % str(at_list[rid]["uri"]))
    ]
    if len(at_list[rid]["_at"]) < args.maxargs:
        s_upd.extend(p1)
        for arg in sorted(at_list[rid]["_at"]):
            s_upd.extend(["SecRuleUpdateTargetById %s \"!%s\"" % (rid, arg)])
        s_upd.extend([""])
    else:
        # # white-list the user parameter for rule #981260 when the REQUEST_URI is /index.php
        # SecRule REQUEST_URI "@beginsWith /index.php" "phase:1,t:none,pass, \
        #   nolog,ctl:ruleRemoveTargetById=981260;ARGS:user
        ppfx = [path1(x) for x in at_list[rid]["uri"]]
        for path in ppfx:
            pfx_list.setdefault(path, set())
            pfx_list[path].add(rid)

for path in sorted(pfx_list):
    ctll = ",".join(["ctl:ruleRemoveTargetById=%s" % i for i in pfx_list[path]])
    s_whitel.extend(["SecRule REQUEST_URI \"@beginsWith %s\" \"phase:1,t:none,pass,nolog," % path + ctll + '"'])

print("# >>>>> White list <<<<<<")
for line in s_whitel:
    print(line)

print("# >>>>> Excludes <<<<<<")
for line in s_upd:
    print(line)
