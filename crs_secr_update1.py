#!/usr/bin/env python3

import re
import argparse
import logging


# from typing import List, Any, Union

parser = argparse.ArgumentParser(
    prog='crs_secr_update1',
    formatter_class=argparse.ArgumentDefaultsHelpFormatter)
parser.add_argument('--maxargs', type=int, default=15, help='max number of args for target id updated')
parser.add_argument('--debug', action="store_true", help='Turn on debugging')
parser.add_argument('--id-start', type=int, default=12001, help='Starting id for white list rules')
parser.add_argument('file', nargs='*', help='file names')
args = parser.parse_args()

if args.debug:
    logging.basicConfig(level=logging.DEBUG)

logging.debug("maxargs is %i" % args.maxargs)

ms_re = re.compile(r'\bModSecurity:\s')
# at_re = re.compile(r"\s+(?:at\s+([^.]+)|in\s+(\S+))")
re_well_formed_args = re.compile(r"^[\w_-]+([:\w_-]+)?$")

wl_rule_incr = 10

# Style with "against variable":

# Modsecurity: Rule Id: 942421 phase: 2 * Match, but no disruptive action: ModSecurity: Warning. Matched "Operator
# `Rx' with parameter `((?:[~!@#\$%\^&\*\(\)\-\+=\{\}\[\]\|:;\"'\xc2\xb4\xe2\x80\x99\xe2\x80\x98`<>][^~!@#\$%\^&\*\(
# \)\-\+=\{\}\[\]\|:;\"'\xc2\xb4\xe2\x80\x99\xe2\x80\x98`<>]*?){3})' against variable `REQUEST_COOKIES:DEA_vertrag' (
# Value: `J17106||en|||||100000000||||8515||Response_18f1ca847fe1aa7cc4fcbd24624ffac98f685f70|||||||||||nnnnoo (52
# characters omitted)' ) [file ...

at_re_list = [
    re.compile(r'\s+at\s+(.*?)\.\s+\[file'),
    re.compile(r"\s+against\s+variable\s+`([^']+)")
]

fld_re = re.compile(r"\[(\w+)\s+\"([^\"]+)(.*)")
p_re = re.compile(r"^(/[^/]+)/")


def base_path(s):
    m_p = p_re.search(s)
    return m_p.group(1) if m_p else '/'


def base_path_list(pl):
    res = set()
    for elt in pl:
        p1 = base_path(elt)
        if p1:
            res.add(p1)
    return res


def parse_line(modsec_line):
    res = {}
    for at_re in at_re_list:
        m_at = at_re.search(modsec_line)
        if m_at:
            res["_at"] = m_at.group(1)
            while modsec_line:
                m_at = fld_re.search(modsec_line)
                if m_at:
                    fld_name, contents, rest = m_at.groups()
                    # res.setdefault(fld_name, set())
                    if fld_name not in res:
                        res[fld_name] = set()
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
                        "msg": "",
                        "_at": set(),
                        "uri": set()
                    }
                    )
                    if "msg" in r:
                        at_list[rid]["msg"] = list(r["msg"])[0]
                    if "_at" in r:
                        at_list[rid]["_at"].add(r["_at"])
                    for uri in r["uri"]:
                        at_list[rid]["uri"].add(uri)

l_upd = []
d_update = {}
l_whitelist = []
s_disabled = set()

num_re = re.compile(r"^\d+$")

pfx_list = {}

"""r_comment = [
    ("# Rule id %s - %s" % (rid, at_list[rid]["msg"])),
    ("# 'at' list: %s" % str(at_list[rid]["_at"])),
    # ("# uri list: %s" % str(at_list[rid]["uri"]))
    ("# base path list: %s" % base_path_list(at_list[rid]["uri"]))
]
l_upd.extend(r_comment)
"""

for rid in sorted(at_list):
    num_match = num_re.search(rid)
    if num_match:
        if len(at_list[rid]["_at"]) < args.maxargs:
            for at in sorted(at_list[rid]["_at"]):
                m = re_well_formed_args.search(at)
                if m:
                    d_update.setdefault(rid, set())
                    d_update[rid].add(at)
                else:
                    """ We want to get rid of strange parameter names like 
                    FILES:%27Non-ASCII%20in%20Title%20%EF%80%A1%20blabla%20attaboy-en%20.pdf
                    """
                    logging.debug("Disabling rule %s due to ill-formed argument: %s" % (rid, at))
                    s_disabled.add(rid)
        else:
            logging.debug('max_args exceeded for rule id %s (%i matches): List of ModSecurity "at" %s' %
                          (rid, len(at_list[rid]["_at"]), str(sorted(at_list[rid]["_at"]))))
            path_prefix = base_path_list(at_list[rid]["uri"])
            logging.debug('Path prefixes for rule id %s: %s' % (rid, str(path_prefix)))
            for path in path_prefix:
                pfx_list.setdefault(path, set())
                pfx_list[path].add(rid)
    else:
        logging.warning("Ignoring non-numeric rule id '%s'" % rid)

# Determine ruleid's that occur in a large number of the path prefixes
paths = sorted(list(pfx_list))
num_paths = len(paths)
rid_paths = {}
max_rule_path_mentions_factor = 0.7

for path in paths:
    for rid in pfx_list[path]:
        rid_paths.setdefault(rid, set())
        rid_paths[rid].add(path)
max_rule_path_mentions = int(max_rule_path_mentions_factor * num_paths)
for rid in sorted(rid_paths):
    if len(rid_paths[rid]) > max_rule_path_mentions:
        logging.debug("rid %s occurs in %i of %i URI paths - disabling entire rule" %
                      (rid, len(rid_paths[rid]), len(paths)))
        s_disabled.add(rid)
        for path in pfx_list:
            pfx_list[path].remove(rid)

wl_rule_id = args.id_start
for path in sorted(pfx_list):
    ctl_list = "," . join(["\\\n    ctl:ruleRemoveById=%s" % i for i in sorted(pfx_list[path])])
    if ctl_list:
        l_whitelist.extend(['SecRule REQUEST_URI "@beginsWith %s" "id:\'%i\',phase:1,t:none,pass,nolog,%s"\n' %
                            (path, wl_rule_id, ctl_list)])
        wl_rule_id += wl_rule_incr

print('')
print("# >>>>> White list <<<<<<")
print("# to be inserted in config file *before* ModSecurity rule file includes\n")

for line in sorted(l_whitelist):
    print(line)
print('')

print("# >>>>> Excludes <<<<<<")
print("# to be inserted in config file *after* ModSecurity rule file includes")

print("# Disabled secrules")
for rid in sorted(s_disabled):
    print("SecRuleRemoveById %s" % rid)
print('')

print("# Updated secrules")
for rid in sorted(l_upd):
    for at in sorted(d_update[rid]):
        print('SecRuleUpdateTargetById %s "!%s"' % (rid, at))
print('')
