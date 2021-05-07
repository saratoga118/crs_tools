import re

# Style with "against variable":

# Modsecurity: Rule Id: 942421 phase: 2 * Match, but no disruptive action: ModSecurity: Warning. Matched "Operator
# `Rx' with parameter `((?:[~!@#\$%\^&\*\(\)\-\+=\{\}\[\]\|:;\"'\xc2\xb4\xe2\x80\x99\xe2\x80\x98`<>][^~!@#\$%\^&\*\(
# \)\-\+=\{\}\[\]\|:;\"'\xc2\xb4\xe2\x80\x99\xe2\x80\x98`<>]*?){3})' against variable `REQUEST_COOKIES:DEA_vertrag' (
# Value: `J17106||en|||||100000000||||8515||Response_18f1ca847fe1aa7cc4fcbd24624ffac98f685f70|||||||||||nnnnoo (52
# characters omitted)' ) [file ...

at_re_list = [
    re.compile(r'\s+at\s+(.*?)\.\s+(\[.*)'),
    re.compile(r"\s+against\s+variable\s+`([^']+)(.*)")
]


def parse_line(modsec_line):
    res = {}
    for at_re in at_re_list:
        m_at = at_re.search(modsec_line)
        if m_at:
            res["_at"] = m_at.group(1)
    r = parse_fields(modsec_line)
    if r:
        for i in r:
            res[i] = r[i]
    return res


fld_re = re.compile(r'\s\[(\w+)\s+"(.*?)"\](.*)')


def parse_fields(line):
    res = {}
    while line:
        m_fld = fld_re.search(line)
        if m_fld:
            fld_name, contents, rest = m_fld.groups()
            # res.setdefault(fld_name, set())
            if fld_name not in res:
                res[fld_name] = set()
            res[fld_name].add(contents)
            line = rest
        else:
            line = ''
    return res


"""
def parse_fields_str(line):
    res = {}
    while line:
        tok_start = line.find("[")
        if tok_start < 0:
            return res
        tok_end = line.find("]")
        if tok_end < 0:
            return res
        b = line[tok_start + 1:tok_end]
        li = b.split(" ", 1)
        if len(li) == 2:
            fld, val = li
            if val[0] == '"':
                val = val[1:-1]
            if fld not in res:
                res[fld] = set()
            res[fld].add(val)
        else:
            # logging.warning("unexpected number of fields: " + str(li))
            pass
        line = line[1+tok_end:]
    return res
"""
