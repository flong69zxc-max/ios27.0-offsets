# @category iOS
# @runtime Jython

from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor
import json

monitor = ConsoleTaskMonitor()
BASE = 0xFFFFFFF00710B098

out = open("offsets.txt", "w")
out.write("=== KERNEL OFFSETS iOS 27.0 24A437 ===\n")
out.write("BASE: 0x%x\n\n" % BASE)


def find_sym(name):
    tbl = currentProgram.getSymbolTable()
    it = tbl.getSymbols(name)
    if it.hasNext():
        return it.next().getAddress().getOffset()
    return None


def find_sym_fuzzy(fragment):
    tbl = currentProgram.getSymbolTable()
    for s in tbl.getAllSymbols(True):
        if fragment in s.getName():
            return s.getAddress().getOffset()
    return None


# ═══════════════════════════════════════════
# PART 1 — SYMBOLS
# ═══════════════════════════════════════════

out.write("=== SYMBOLS (offset from base) ===\n")

symbols = [
    "_cs_enforcement_disable",
    "_allproc",
    "_kernel_task",
    "_task_for_pid",
    "_necp_client_action",
    "_necp_client_copy_result",
    "_necp_client_add_flow",
    "_necp_client_remove_flow",
    "_amfi_get_out_of_my_way",
    "_proc_ucred",
    "_proc_pid",
    "_kauth_cred_getuid",
    "_kernproc",
    "_current_task",
    "_current_proc",
]

for sym in symbols:
    va = find_sym(sym)
    if va is None:
        va = find_sym_fuzzy(sym.replace("_", ""))
    if va:
        off = va - BASE
        out.write("%-32s addr=0x%x  offset=0x%x\n" % (sym, va, off))
    else:
        out.write("%-32s NOT FOUND\n" % sym)

out.write("\n")


# ═══════════════════════════════════════════
# PART 2 — DECOMPILE KEY FUNCTIONS
# ═══════════════════════════════════════════

def decompile_at(addr_str, label):
    fm = currentProgram.getFunctionManager()
    addr = currentProgram.getAddressFactory().getAddress(addr_str)
    if not addr:
        out.write("\n=== %s : BAD ADDRESS ===\n" % label)
        return
    func = fm.getFunctionAt(addr) or fm.getFunctionContaining(addr)
    if not func:
        out.write("\n=== %s : NO FUNCTION @ %s ===\n" % (label, addr_str))
        return
    out.write("\n=== %s @ 0x%x ===\n" % (label, func.getEntryPoint().getOffset()))

    ifm = DecompInterface()
    ifm.openProgram(currentProgram)
    res = ifm.decompileFunction(func, 120, monitor)
    if res and res.decompileCompleted():
        out.write(res.getDecompiledFunction().getC())
        out.write("\n")
    else:
        out.write("[-] decompile failed\n")


decompile_at("fffffff0070d2ac4", "necp_client_copy_result")
decompile_at("fffffff0070951d9", "necp_client_action")


# ═══════════════════════════════════════════
# PART 3 — NECP STRINGS
# ═══════════════════════════════════════════

out.write("\n=== NECP STRINGS ===\n")
listing = currentProgram.getListing()
count = 0
for d in listing.getDefinedData(True):
    if d.hasStringValue():
        s = str(d.getValue())
        if "necp" in s.lower():
            out.write("%s @ %s\n" % (s, d.getAddress()))
            count += 1
            if count > 150:
                out.write("... (truncated)\n")
                break
out.write("\n")


# ═══════════════════════════════════════════
# PART 4 — XREFS TO necp_client_action
# ═══════════════════════════════════════════

out.write("\n=== XREFS TO necp_client_action ===\n")
refMgr = currentProgram.getReferenceManager()
fm = currentProgram.getFunctionManager()
target = currentProgram.getAddressFactory().getAddress("fffffff0070951d9")
count = 0
for ref in refMgr.getReferencesTo(target):
    from_addr = ref.getFromAddress()
    func = fm.getFunctionContaining(from_addr)
    if func:
        out.write("REF: %s -> %s @ %s\n" % (from_addr, func.getName(), func.getEntryPoint()))
        count += 1
        if count > 50:
            out.write("... (truncated)\n")
            break
out.write("\n")


out.close()
print("=== DONE — offsets.txt written ===")
