import claripy
import angr

sym_argv = claripy.BVS('sym_argv', 8 * 8)
p = angr.Project("./other/if.out", load_options={"auto_load_libs": True})
state = p.factory.entry_state(args=[p.filename, sym_argv])
pg = p.factory.simgr(state)
pg.run()
for dd in pg.deadended:
    res = dd.solver.eval(sym_argv, cast_to=bytes)
    print(b'[+] New Input: ' + res + b' |')
    print(str(dd.solver.constraints))