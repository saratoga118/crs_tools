#!/usr/bin/env python3

import argparse
import logging
import re
import fileinput

# from typing import List, Any, Union
from typing import Any

import modsecurity_lines

parser = argparse.ArgumentParser(
    prog='crs_secr_update1',
    formatter_class=argparse.ArgumentDefaultsHelpFormatter)
parser.add_argument('--max-rule-vars', type=int, default=15,
                    help='max number of args for target id updated: If there are more arguments than'
                    'max-rule-vars, the entire rule is disabled with SecRuleRemoveById')
parser.add_argument('--min-arg-matches', type=int, default=5,
                    help='minimum number of rule hits for a given argument of a rule to be considered '
                         'for rule updates. Rules with fewer hits will not cause any SecRule statement '
                         'to be created.')
parser.add_argument('--min-uri-matches', type=int, default=5,
                    help='minimum number of hits for a given URI of a rule to be considered for rule udates')
parser.add_argument('--debug', action="store_true",
                    help='Turn on debugging')
parser.add_argument('--id-start', type=int, default=12001,
                    help='Starting id for white list rules')
parser.add_argument('--base-path-tokens', type=int, default=1,
                    help='Number of directory path elements for per '
                    'directory rules')
parser.add_argument("--skip-base-path-filtering", action="store_true",
                    help="Turns off base path filtering, i.e. all uri matches encountered are"
                         "taken literally")
parser.add_argument("--force-white-listing", action="store_true",
                    help="Force the creation of per base path and per RID white listing rules")


parser.add_argument('file', nargs='*',  help='file names')
args = parser.parse_args()

if args.debug:
    logging.basicConfig(level=logging.DEBUG)

logging.debug("max_rule_vars is %i" % args.max_rule_vars)
logging.debug("min_arg_matches is %i" % args.min_arg_matches)
logging.debug("min_uri_matches is %i" % args.min_uri_matches)
logging.debug("base_path_tokens is %i" % args.base_path_tokens)
logging.debug("force-white-listing is %s" % str(args.force_white_listing))
logging.debug("skip-base-path-filtering is %s" % str(args.skip_base_path_filtering))
logging.debug("id_start is %i" % args.id_start)

ms_re = re.compile(r'\bModSecurity:\s+(.*)')
re_well_formed_args = re.compile(r"^[\w_-]+([:\w_-]+)?$")

good_uri_re = re.compile(r"^/[\w/.-]*$")


def well_formed_uri(p):
    return good_uri_re.search(p)


wl_rule_incr = 10

p_re = re.compile(r"^((/[^/]+){1,%i})/" % args.base_path_tokens)


def base_path(path_list):
    res = set()
    if not args.skip_base_path_filtering:
        for p in path_list:
            m_p = p_re.search(p)
            res.add(m_p.group(1) if m_p else '/')
    else:
        res = set(path_list)
    return res


rule_attr_list: dict[Any, Any] = {}
rid_msg = {}
paranoia_level = {}


def get_paranoia_level(pl):
    return paranoia_level.get(pl, "__undef__")


wl = {}


def add_wl(path, rid, at):
    if path not in wl:
        wl[path] = {}
    if rid not in wl[path]:
        wl[path][rid] = set()
    wl[path][rid].add(at)


ill_formed_notified = set()

# with fileinput.input(files=('spam.txt', 'eggs.txt')) as f:
# for input_filename in args.file:
with fileinput.input(files=args.file) as infile:
    for line in infile:
        if line.lower().find("modsecurity:") > 0:
            r = modsecurity_lines.parse_line(line)
            ignore = False
            if "uri" in r:
                for uri in r["uri"]:
                    if not well_formed_uri(uri):
                        if uri not in ill_formed_notified:
                            logging.debug("Ignoring ill-formed URI '%s'" % uri)
                            ill_formed_notified.add(uri)
                        ignore = True
            else:
                logging.debug("line without 'uri': %s" % line.rstrip())
            if not ignore:
                if "id" in r:
                    for rid in r["id"]:
                        if rid not in rule_attr_list:
                            rule_attr_list[rid] = modsecurity_lines.RuleMatches()
                        cur_rule = rule_attr_list[rid]
                        if "msg" in r:
                            if rid not in rid_msg:
                                rid_msg[rid] = list(r["msg"])[0]
                        if "_at" in r:
                            cur_rule.add_attr(r["_at"])
                        if "tag" in r:
                            for t in r["tag"]:
                                cur_rule.add_tag(t)
                            pl = cur_rule.get_paranoia_level()
                            if pl:
                                paranoia_level[rid] = pl
                        for uri in r["uri"]:
                            cur_rule.add_uri(uri)
                else:
                    logging.debug("Line without id: %s" % line.rstrip())

rule_update_dict = {}
l_whitelist = []
s_disabled = set()

pfx_list = {}

"""
r_comment = [
    ("# RuleMatches id %s - %s" % (rid, rule_attr_list[rid]["msg"])),
    ("# 'at' list: %s" % str(rule_attr_list[rid]["_at"])),
    # ("# uris list: %s" % str(rule_attr_list[rid]["uris"]))
    ("# base path list: %s" % base_path_list(rule_attr_list[rid]["uris"]))
]
l_upd.extend(r_comment)
"""


for rid in sorted(rule_attr_list):
    attrs = rule_attr_list[rid].get_attrs()
    if len(attrs) <= args.max_rule_vars:
        """ The number of attrs found for this rule is small enough to create SecRuleUpdateTargetById
        """
        for at in sorted(attrs):
            if attrs[at] >= args.min_arg_matches:
                m = re_well_formed_args.search(at)
                if m:
                    if not args.force_white_listing:
                        rule_update_dict.setdefault(rid, set())
                        rule_update_dict[rid].add(at)
                    else:
                        bps = base_path(rule_attr_list[rid].get_uris())
                        for b in bps:
                            add_wl(b, rid, at)
                else:
                    """ We want to get rid of strange parameter names like 
                    FILES:%27Non-ASCII%20in%20Title%20%EF%80%A1%20blabla%20attaboy-en%20.pdf
                    """
                    logging.debug("Disabling rule '%s' due to ill-formed argument: '%s'" % (rid, at))
                    s_disabled.add(rid)
            else:
                logging.debug("rid '%s', arg '%s': Ignoring due to insufficient argument hits (%i)" %
                              (rid, at, attrs[at]))
    else:
        """ Too many different ARGS for given ruleid. Creating an exception based on the path
        """
        logging.debug("max_rule_vars exceeded for rule id '%s' (%i matches): List of args %s" %
                      (rid, len(attrs), str(sorted(attrs))))
        base_path_hits = {}
        for bp in base_path(rule_attr_list[rid].get_uris()):
            if bp not in base_path_hits:
                base_path_hits[bp] = 0
            base_path_hits[bp] += 1
        for bp in base_path_hits:
            hits = base_path_hits[bp]
            if hits >= args.min_uri_matches:
                pfx_list.setdefault(bp, set())
                pfx_list[bp].add(rid)
            else:
                logging.debug("rid '%s', URI '%s': Ignoring due to insufficient base path hits (%i)" %
                              (rid, bp, hits))

# Determine ruleid's that occur in a large number of the path prefixes
paths = sorted(list(pfx_list))
num_paths = len(paths)
rid_paths = {}
max_rule_path_mentions_factor = 0.7

# logging.debug("Paths: "+str(paths))
# logging.debug("Number of paths: %i" % len(paths))
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
            if rid in pfx_list[path]:
                pfx_list[path].remove(rid)

wl_rule_id = args.id_start
for path in sorted(pfx_list):
    ctl_list = ",".join(["\\\n    ctl:ruleRemoveById=%s" % i for i in sorted(pfx_list[path])])
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

if wl:
    print("# Begin White listing with URI, rule-id and args")
    for bp in sorted(wl):
        for rid in sorted(wl[bp]):
            for at in sorted(wl[bp][rid]):
                # See SecRule REQUEST_URI "@beginsWith /index.php/component/users/" "id:5,phase:1,t:none,pass,nolog,
                # ctl:ruleRemoveTargetById=981318;ARGS:/jform\[password[12]\]/"
                print('SecRule REQUEST_URI "@beginsWith {path}" "id:{id},phase:1,t:none,pass,nolog,'
                      'ctl:ruleRemoveTargetById={rid};{at}"'.format(path=bp, id=wl_rule_id, rid=rid, at=at))
                wl_rule_id += wl_rule_incr
            print("")
    print("# End White listing with URI, rule-id and args")

print("\n# >>>>> Excludes <<<<<<")
print("# to be inserted in config file *after* ModSecurity rule file includes\n")


def print_rid_msg(rd):
    print("# RuleMatches id %s: %s; paranoia level %s" % (rd,
                                                          rid_msg.get(rd, "__no_msg__"),
                                                          get_paranoia_level(rd)))


print("# Disabled secrules")
for rid in sorted(s_disabled):
    print_rid_msg(rid)
    print("SecRuleRemoveById %s\n" % rid)
print('')

print("# Updated secrules")
for rid in sorted(rule_update_dict):
    if rid not in s_disabled:
        print_rid_msg(rid)
        for at in sorted(rule_update_dict[rid]):
            print('SecRuleUpdateTargetById %s "!%s"' % (rid, at))
    print("")
print('')
