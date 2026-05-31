#!/usr/bin/env python3
import re, sys
path = "/etc/dnsdist/dnsdist.conf"
with open(path) as f:
    s = f.read()
s = re.sub(
    r"addAction\(NetmaskGroupRule\(newNMG\(\):addMask\(([^)]+)\)\), DropAction\(\)\)",
    lambda m: "local _nmg = newNMG(); _nmg:addMask(" + m.group(1) + "); addAction(NetmaskGroupRule(_nmg), DropAction())",
    s
)
with open(path, "w") as f:
    f.write(s)
print("fixed")
