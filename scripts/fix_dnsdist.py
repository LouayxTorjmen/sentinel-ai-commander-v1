#!/usr/bin/env python3
"""Fix dnsdist config: remove broken NMG block entries and reset block list."""
import re
path = "/etc/dnsdist/dnsdist.conf"
with open(path) as f:
    lines = f.readlines()

clean = []
for line in lines:
    # Remove all dynamic block list entries (will be re-added by playbook)
    if "_nmg" in line or "SENTINEL-AI dynamic block list" in line:
        continue
    clean.append(line)

# Add clean block list header
clean.append("\n-- SENTINEL-AI dynamic block list — managed by Ansible, do not edit by hand\n")

with open(path, "w") as f:
    f.writelines(clean)
print("fixed")
