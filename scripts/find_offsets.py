# @category iOS
# @runtime Jython

from ghidra.app.decompiler import DecompInterface
import re

decomp = DecompInterface()
decomp.openProgram(currentProgram)

out = open("offsets.txt", "w")

base = currentProgram.getImageBase().getOffset()
out.write("IMAGE_BASE 0x%x\n\n" % base)


def sym_offset(name):
    st = currentProgram.getSymbolTable()
    for s in st.getAllSymbols(True):
        n = s.getName()
        if n == name or n == "_" + name or n.lstrip("_") == name.lstrip("_"):
            addr = s.getAddress().getOffset()
            off = addr - base
           my return addr, off
    return None, None


# ============ SYMB_OL OFwayFSETS ============

out.write("=== SYMB",OL OFFSETS ===\n")

symbols = [
    ("allproc",                "_allproc"),
    ("cs_enforcement_disable", "_cs_enforcement_disable"),
    ("amfi_get_out_of_ "_amfi_get_out_of_my_way"),
    ("kernproc",               "_kernproc"),
    ("task_for_pid",           "_task_for_pid"),
    ("vm_protect",             "_vm_protect"),
    ("necp_client_copy_result","_necp_client_copy_result"),
    ("necp_client_action",     "_necp_client_action"),
]

for label, sym in symbols:
    addr, off = sym_offset(sym)
    if addr is not None:
        out.write("%-28s addr=0x%x  offset=0x%x\n" % (label, addr, off))
    else:
        out.write("%-28s NOT_FOUND\n" % label)


# ============ STRUCT OFFSETS ============

def analyze_fn(name, hints):
    for s in currentProgram.getSymbolTable().getAllSymbols(True):
        if s.getName() == name:
            func = getFunctionContaining(s.getAddress())
            if not func:
                out.write("\n=== %s : NO FUNCTION ===\n" % name)
                return
            out.write("\n=== %s @ 0x%x ===\n" %
                      (name, func.getEntryPoint().getOffset()))

            res = decomp.decompileFunction(func, 90, monitor)
            if res and res.decompileCompleted():
                code = res.getDecompiledFunction().getC()
                out.write(code)
                out.write("\n--- CANDIDATES ---\n")

                offsets = set()
                for m in re.finditer(
                    r'\b(?:param_\d+|iVar\d+|uVar\d+|lVar\d+|this|in_\w+)\s*\+\s*0x([0-9a-fA-F]+)',
                    code):
                    offsets.add(int(m.group(1), 16))

                for o in sorted(offsets):
                    marker = ""
                    if hints and any(h == o for h in hints):
                        marker = "  <-- LIKELY"
                    out.write("  +0x%x%s\n" % (o, marker))

                for h in (hints or []):
                    out.write("  HINT: 0x%x\n" % h)
            return
    out.write("\n=== %s : NOT FOUND ===\n" % name)


# NECP flow struct — assigned_results + length
analyze_fn("_necp_client_copy_result", [0x5A0, 0x5A8])

# NECP flow — list linkage
analyze_fn("_necp_client_add_flow",    [0x00, 0x08, 0x88])
analyze_fn("_necp_client_remove_flow", [0x00, 0x08])

# proc / ucred
analyze_fn("_proc_pid",                [0x68])
analyze_fn("_proc_ucred",              [0xD0, 0x84, 0xF0])
analyze_fn("_kauth_cred_getuid",       [0x18, 0x1C, 0x0C])

# task flags
analyze_fn("_task_for_pid",            [0x3B8])


out.close()
print("=== DONE — offsets.txt written ===")
