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
parser.add_argument("--skip-base-path-filtering", action="store_true",
                    help="Turns off base path filtering, i.e. all uri matches encountered are"
                         "taken literally")


parser.add_argument('file', nargs='*',  help='file names')
args = parser.parse_args()

if args.debug:
    logging.basicConfig(level=logging.DEBUG)


comment_re = re.compile(r'^\s*#.*$')
rule_re = re.compile(r'^\s*(SecRule\w+)\s+(\S+)\s+(.*)$')

last_kw = ''
last_rid = ''
"""
 file := prematch_section, {match_section}, postmatch_section
 match_section := {relevant_comment}, rule_statement, {rule_statement}
 relevant_comment = "# ", string
 rule_statement = rule_kw, rule_id, rule_arg
"""

r={}
def store_it(kw, rid, rest, comments):
    if kw not in r:
        r[kw]={}
    if rid not in r[kw]:
        r[kw][rid].extend(comments,rest)

prematch_finished = False
prematch_lines = []
postmatch_lines = []
with fileinput.input(files=args.file) as infile:
    lno = 1
    for line in infile:
        m = rule_re.search(line)
        if m:
            prematch_finished = True
            kw, rid, rest = m.groups()
            store_it(kw, rid, rest, comments)
            else:
        m = comment_re.search(line)
        if m:
            if reading_comment:
                comment_stop_lno = lno
                pass
            else:
                reading_comment = True
                comment_start_lno = lno
        else:
            reading_comment = False




