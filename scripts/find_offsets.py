# @category iOS
# @runtime Jython

from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor

monitor = ConsoleTaskMonitor()
BASE = 0xFFFFFFF00710B098

out = open("offsets.txt", "w")
out.write("=== iOS 27.0 24A437 Kernel Offsets ===\n")
out.write("BASE: 0x%x\n\n" % BASE)


# ═══════════════════════════════════════════════════════════
# PART 1 — SYMBOLS (no analysis needed, instant)
# ═══════════════════════════════════════════════════════════

out.write("=== SYMBOLS ===\n")

sym_names = [
    "_allproc", "_kernproc",
    "_cs_enforcement_disable",
    "_amfi_get_out_of_my_way",
    "_task_for_pid",
    "_necp_client_action",
    "_necp_client_copy_result",
    "_necp_client_add_flow",
    "_necp_client_remove_flow",
    "_proc_ucred", "_proc_pid",
    "_kauth_cred_getuid",
]

tbl = currentProgram.getSymbolTable()
for name in sym_names:
    addr = None
    for s in tbl.getAllSymbols(True):
        n = s.getName()
        if n == name or n.lstrip("_") == name.lstrip("_"):
            addr = s.getAddress().getOffset()
            break
    if addr is not None:
        out.write("%-32s 0x%x  (off=0x%x)\n" % (name, addr, addr - BASE))
    else:
        out.write("%-32s NOT FOUND\n" % name)


# ═══════════════════════════════════════════════════════════
# PART 2 — MANUAL DISASM + DECOMPILE of target functions
# ═══════════════════════════════════════════════════════════

out.write("\n=== TARGET FUNCTIONS ===\n")

def decompile_at(addr_hex, label):
    addr = toAddr(addr_hex)
    if not addr:
        out.write("\n[%s] bad addr\n" % label)
        return

    # Manual disassemble from address (2000 instructions max)
    try:
        disassemble(addr)
        # widen range
        cur = addr
        for _ in range(2000):
            inst = getInstructionAt(cur)
            if not inst:
                inst = getInstructionAfter(cur)
                if not inst:
                    break
                cur = inst.getAddress()
            else:
                cur = inst.getAddress()
            ni = getInstructionAfter(cur)
            if not ni:
                break
            cur = ni.getAddress()
            if getFunctionContaining(cur) and cur != addr:
                break
    except Exception as e:
        out.write("[%s] disasm error: %s\n" % (label, e))

    func = getFunctionContaining(addr) or getFunctionAt(addr)
    if not func:
        createFunction(addr, label)
        func = getFunctionAt(addr)

    out.write("\n=== %s @ 0x%x ===\n" % (label, addr.getOffset()))
    if not func:
        out.write("[-] no function created\n")
        return

    ifm = DecompInterface()
    ifm.openProgram(currentProgram)
    res = ifm.decompileFunction(func, 60, monitor)
    if res and res.decompileCompleted():
        code = res.getDecompiledFunction().getC()
        out.write(code)
        out.write("\n")
    else:
        out.write("[-] decompile failed\n")

# key addresses known from tester
decompile_at(0xFFFFFFF0070D2AC4, "necp_client_copy_result")
decompile_at(0xFFFFFFF0070951D9, "necp_client_action")

# try fuzzy for proc/ucred helpers
for frag in ["proc_ucred", "proc_pid", "kauth_cred_getuid"]:
    for s in tbl.getAllSymbols(True):
        if frag in s.getName():
            decompile_at(s.getAddress().getOffset(), s.getName())
            break


out.close()
print("=== DONE ===")
