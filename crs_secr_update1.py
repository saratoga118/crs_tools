#!/usr/bin/env python3

import re
import sys

ms_re = re.compile(r"\bModSecurity:\s+")
at_re = re.compile(r"\s+at\s+([^\.]+)")

fld_re = re.compile(r"\[(\w+)\s+\"([^\"]+)(.*)")


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
with open(sys.argv[1]) as infile:
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

for rid in sorted(at_list):
    print("# Rule id %s - %s" % (rid, at_list[rid]["msg"]))
    print("# 'at' list:", at_list[rid]["_at"])
    print("# uri list:", at_list[rid]["uri"])

    for arg in sorted(at_list[rid]["_at"]):
        print("SecRuleUpdateTargetById %s \"!%s\"" % (rid, arg))
    print("")

