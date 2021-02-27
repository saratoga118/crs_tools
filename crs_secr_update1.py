#!/usr/bin/env python3

import re
import argparse
import logging

from typing import List, Any, Union

parser = argparse.ArgumentParser(
    prog='crs_secr_update1',
    formatter_class=argparse.ArgumentDefaultsHelpFormatter)
parser.add_argument('--maxargs', type=int, default=5, help='max number of args for target id updated')
parser.add_argument('--debug', action="store_true", help='Turn on debugging')
parser.add_argument('file', nargs='*', help='file names')
args = parser.parse_args()

if args.debug:
    logging.basicConfig(level=logging.DEBUG)

logging.debug("maxargs is %i" % args.maxargs)

ms_re = re.compile(r'\bModSecurity:\s')
# at_re = re.compile(r"\s+(?:at\s+([^.]+)|in\s+(\S+))")
at_re = re.compile(r'\s+at\s+([^.]+)')
fld_re = re.compile(r"\[(\w+)\s+\"([^\"]+)(.*)")
p_re = re.compile(r"^(/[^/]+)/")


def path1(s):
    m = p_re.search(s)
    return m.group(1) if m else ''


def parse_line(modsec_line):
    res = {}
    m = at_re.search(modsec_line)
    if m:
        res["_at"] = m.group(1)
        while modsec_line:
            m = fld_re.search(modsec_line)
            if m:
                fld_name, contents, rest = m.groups()
                res.setdefault(fld_name, set())
                res[fld_name].add(contents)
                modsec_line = rest
            else:
                modsec_line = ''
    return res


at_list = {}
for input_filename in args.file:
    with open(input_filename) as infile:
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
                    if "_at" in r:
                        at_list[rid]["_at"].add(r["_at"])
                    for uri in r["uri"]:
                        at_list[rid]["uri"].add(uri)

s_upd = []
s_whitelist = []

pfx_list = {}
for rid in sorted(at_list):
    p1 = [
        ("# Rule id %s - %s" % (rid, at_list[rid]["msg"])),
        ("# 'at' list: %s" % str(at_list[rid]["_at"])),
        ("# uri list: %s" % str(at_list[rid]["uri"]))
    ]
    if len(at_list[rid]["_at"]) < args.maxargs:
        s_upd.extend(p1)
        for arg in sorted(at_list[rid]['_at']):
            s_upd.extend(['SecRuleUpdateTargetById %s "!%s"' % (rid, arg)])
        s_upd.extend([""])
    else:
        logging.debug('max_args exceeded for rule id %s: List of ModSecurity "at" %s' %
                      (rid, str(sorted(at_list[rid]["_at"]))))
        ppfx = []  # type: List[Union[Union[str, unicode], Any]]
        for x in at_list[rid]["uri"]:
            p1 = path1(x)
            if p1:
                ppfx.append(p1)
        logging.debug('Path prefixes for rule id %s: %s' % (rid, str(ppfx)))
        for path in ppfx:
            pfx_list.setdefault(path, set())
            pfx_list[path].add(rid)

for path in sorted(pfx_list):
    ctll = ",".join(["ctl:ruleRemoveById=%s" % i for i in pfx_list[path]])
    s_whitelist.extend(['SecRule REQUEST_URI "@beginsWith %s" "phase:1,t:none,pass,nolog,%s"' % (path, ctll)])

print('')
print("# >>>>> White list <<<<<<")
print("# to be inserted in config file *before* ModSecurity rule file includes")

for line in s_whitelist:
    print(line)
print('')

print("# >>>>> Excludes <<<<<<")
print("# to be inserted in config file *after* ModSecurity rule file includes")
for line in s_upd:
    print(line)
print('')
