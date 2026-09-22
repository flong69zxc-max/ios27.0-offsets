# -*- coding: utf-8 -*-
# @category iOS
# @runtime Jython

import os
import sys

print("=== SCRIPT START ===")

ws = os.environ.get("GITHUB_WORKSPACE", "/tmp")
OUT = os.path.join(ws, "offsets.txt")
print("=== OUTPUT: %s ===" % OUT)

try:
    out = open(OUT, "w")
    out.write("=== iOS 27.0 24A437 Kernel Offsets ===\n")
    out.flush()
except Exception as e:
    print("CANNOT OPEN OUTPUT: %s" % e)
    sys.exit(1)

BASE = 0xFFFFFFF00710B098
out.write("BASE: 0x%x\n\n" % BASE)
out.flush()

out.write("=== SYMBOLS ===\n")
out.flush()

names = [
    "_allproc",
    "_kernproc",
    "_cs_enforcement_disable",
    "_amfi_get_out_of_my_way",
    "_task_for_pid",
    "_necp_client_action",
    "_necp_client_copy_result",
    "_necp_client_add_flow",
    "_necp_client_remove_flow",
    "_proc_ucred",
    "_proc_pid",
    "_kauth_cred_getuid",
    "_current_task",
    "_current_proc",
]

try:
    tbl = currentProgram.getSymbolTable()
    for name in names:
        try:
            addr = None
            for s in tbl.getAllSymbols(True):
                n = s.getName()
                if n == name or n.lstrip("_") == name.lstrip("_"):
                    addr = s.getAddress().getOffset()
                    break
            if addr is not None:
                line = "%-32s 0x%x  off=0x%x\n" % (name, addr, addr - BASE)
            else:
                line = "%-32s NOT_FOUND\n" % name
            out.write(line)
            out.flush()
            print("SYM: %s" % line.strip())
        except Exception as e:
            out.write("%-32s ERR: %s\n" % (name, e))
            out.flush()
except Exception as e:
    out.write("TBL_ERR: %s\n" % e)
    out.flush()
    print("SYMBOL TABLE ERROR: %s" % e)

out.write("\n=== DONE ===\n")
out.close()
print("=== SCRIPT END ===")
