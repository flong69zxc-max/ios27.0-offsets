# -*- coding: utf-8 -*-
# @category iOS
# @runtime Jython

import os

ws = os.environ.get("GITHUB_WORKSPACE", "/tmp")
OUT = os.path.join(ws, "offsets.txt")
out = open(OUT, "w")
out.write("=== iOS 27.0 24A437 Disasm ===\n")
out.flush()

BASE = 0xFFFFFFF00710B098


def disasm(addr_hex, n, label):
    out.write("\n=== %s @ %s ===\n" % (label, addr_hex))
    out.flush()
    try:
        a = toAddr(int(addr_hex, 16))
    except:
        out.write("BAD_ADDR\n")
        return
    if a is None:
        out.write("NULL_ADDR\n")
        return
    listing = currentProgram.getListing()
    cur = a
    for i in range(n):
        inst = listing.getInstructionAt(cur)
        if inst is None:
            try:
                disassemble(cur)
            except:
                pass
            inst = listing.getInstructionAt(cur)
            if inst is None:
                out.write("[stop @ 0x%x]\n" % cur.getOffset())
                break
        out.write("0x%x: %s\n" % (cur.getOffset(), inst.toString()))
        if i % 50 == 49:
            out.flush()
        nxt = inst.getNext()
        if nxt is None:
            break
        cur = nxt.getAddress()
    out.flush()


# Known addresses from tester
disasm("0xFFFFFFF0070D2AC4", 800, "necp_client_copy_result")
disasm("0xFFFFFFF0070951D9", 500, "necp_client_action")
disasm("0xFFFFFFF0074440E3", 50,  "allproc_area")
disasm("0xFFFFFFF00763332F", 20,  "cs_enforcement_area")

out.write("\n=== DONE ===\n")
out.close()
print("=== SCRIPT END ===")
