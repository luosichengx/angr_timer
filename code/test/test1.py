import angr

proj = angr.Project('/bin/true')
state = proj.factory.entry_state()

x = state.solver.BVS("x", 64)
print(x)
y = state.solver.BVS("y", 64)
print(y)

state.solver.add(x > y)
state.solver.add(y > 2)
state.solver.add(x < 10)
print(state.solver.eval(x))
print(state.solver.eval(y))