#!/usr/bin/python3

import re
import sys

msre = re.compile(r"\bModSecurity:\s+")
atre = re.compile(r"\s+at\s+([^.]+).*\[id\s+\"([^\"]+).*\[msg\s+\"([^\"]+)")

at_list = {}
with open(sys.argv[1]) as infile:
    for line in infile:
        m = msre.search(line)
        if m:
            n = atre.search(line)
            if n:
                at, id, msg = n.groups()
                at_list.setdefault(id, { "msg": "", "at": {} })
                at_list[id]["msg"] = msg
                at_list[id]["at"].setdefault(at, 0)
                at_list[id]["at"][at] += 1

for id in sorted(at_list):
    print("# Rule id %s - %s" % (id, at_list[id]["msg"]))
    for arg in sorted(at_list[id]["at"]):
        print("SecRuleUpdateTargetById %s \"!%s\"" % (id, arg))
    print("")




