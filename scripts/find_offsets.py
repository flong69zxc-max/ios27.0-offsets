# @category iOS
# @runtime Jython
import re

decomp = DecompInterface()
decomp.openProgram(currentProgram)

out = open("/tmp/offsets.txt", "w")

targets = [
    "necp_client_copy_result",
    "necp_client_add_flow",
    "necp_client_remove_flow",
    "proc_find",
    "proc_pid",
    "proc_ucred",
    "kauth_cred_getuid",
    "task_for_pid",
]

symbols = currentProgram.getSymbolTable()

for target in targets:
    for sym in symbols.getAllSymbols(True):
        if target in sym.getName():
            func = getFunctionContaining(sym.getAddress())
            if not func:
                continue
            out.write("\n=== %s @ %s ===\n" % (target, func.getEntryPoint()))
            res = decomp.decompileFunction(func, 60, monitor)
            if res and res.decompileCompleted():
                code = res.getDecompiledFunction().getC()
                out.write(code + "\n")
                offsets = re.findall(r'\+ 0x([0-9a-fA-F]+)', code)
                out.write("--- OFFSETS ---\n")
                for o in sorted(set(offsets), key=lambda x: int(x, 16)):
                    out.write("  +0x%s\n" % o)
            break

out.close()
