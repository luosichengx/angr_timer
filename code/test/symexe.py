import itertools
import os
import signal
import time
import configparser
import traceback

import angr
import claripy
import psutil
import logging
# from rust_procedures import *
import output_query_data_struct


cf = configparser.ConfigParser()
cf.read("./config.ini")

log_path = cf.get("Path", "log")
logger = logging.getLogger(__name__)
logger.setLevel(level=logging.INFO)
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger_angr = logging.getLogger('angr')
logger_angr.setLevel(logging.ERROR)
logger_claripy = logging.getLogger('claripy')
logger_claripy.setLevel(logging.ERROR)
console = logging.StreamHandler()
console.setLevel(logging.ERROR)
# logger.addHandler(console)


class empty_struct:
    exe_time = 0
    suc_time = 0
    query_record = output_query_data_struct.query_data()
    add_con_time = 0

    def __init__(self):
        pass


class Recorder:
    def __init__(self):
        self.engine = None
        self.successor = None
        self.backend_z3 = None
        self.frontend = None

    def add(self):
        record = empty_struct()
        try:
            if hasattr(angr.engines.vex.light.VEXMixin, "exe_time"):
                self.engine = angr.engines.vex.light.VEXMixin
            else:
                self.engine = record
        except:
            self.engine = record
        if hasattr(angr.engines.SimSuccessors, "suc_time"):
            self.successor = angr.engines.SimSuccessors
        else:
            self.successor = record
        if hasattr(claripy._backends_module.backend_z3.BackendZ3, "query_record"):
            self.backend_z3 = claripy._backends_module.backend_z3.BackendZ3
        else:
            self.backend_z3 = record
        if hasattr(claripy.frontends.full_frontend.FullFrontend, "con_time"):
            self.frontend = claripy.frontends.full_frontend.FullFrontend
        else:
            self.frontend = record


def handler(signum, frame):
    signal.alarm(5)
    raise TimeoutError


def killmyself():
    os.system('kill %d' % os.getpid())


def sigint_handler(signum, frame):
    killmyself()


def run_symexe(path, argv_size=8, withtime=True):
    log_handler = logging.FileHandler(os.path.join(log_path, os.path.splitext(os.path.basename(path))[0] + ".log"),
                                      mode='w')
    log_handler.setLevel(logging.INFO)
    log_handler.setFormatter(formatter)
    logger.addHandler(log_handler)

    logger.info('===========================================')
    logger.info('Analysing ' + path)

    sym_argv = claripy.BVS('sym_argv', argv_size * 8)
    sym_argv2 = claripy.BVS('sym_argv', 2 * 8)
    sym_argv3 = claripy.BVS('sym_argv', 2 * 8)
    try:
        load_lib_bool = cf.getboolean("Angr", "lib")
        p = angr.Project(path, load_options={"auto_load_libs": load_lib_bool})
    except:
        print('Invalid path: \"' + path + '\"')
        logger.error('invalid path or load lib failed')
        logger.removeHandler(log_handler)
        return
    main_obj = p.loader.main_object.get_symbol('main')
    state = p.factory.entry_state(args=[p.filename, sym_argv])
    # state = p.factory.entry_state(addr=main_obj.rebased_addr, args=[p.filename, sym_argv])
    # state = p.factory.entry_state(addr=0x4046d0, args=[p.filename, sym_argv])
    # state = p.factory.entry_state(args=[p.filename, sym_argv], add_options={angr.options.LAZY_SOLVES})
    recorder = Recorder()
    recorder.add()
    pg = p.factory.simgr(state)
    # add_rust_support(p)
    add_constraint_for_arg(state, sym_argv)
    cfg, executed_addr, total_addr = draw_cfg(p, recorder)

    path_count = [0]

    # pg.use_technique(angr.exploration_techniques.DFS())
    # pg.use_technique(angr.exploration_techniques.Veritesting())
    # pg.use_technique(angr.exploration_techniques.LengthLimiter(max_length=2000))
    # pg.use_technique(angr.exploration_techniques.LoopSeer(bound=10))
    # pg.use_technique(angr.exploration_techniques.LoopSeer(cfg=cfg, bound=5))

    tel = cf.getint("Time", "explore")
    start_time = time.time()
    try:
        if withtime:
            def my_split(state_list):
                jump_list = []
                stay_list = []
                move_list = []
                for i in state_list:
                    if i.addr not in jump_list:
                        jump_list.append(i.addr)
                        stay_list.append(i)
                    else:
                        move_list.append(i)
                return stay_list, move_list

            def my_step_func(lpg):
                if len(lpg.active) > 0:
                    next_ip = lpg.active[0].ip
                    next_addr = lpg.active[0].addr
                    next_node = cfg.get_any_node(next_addr)
                    # print(next_ip)
                    # print(next_node)
                    call_stack = str(lpg.active[0].callstack).split("\n")
                    call_stack = list(map(lambda x: x[9:18], call_stack))
                    call_stack_list = []
                    for c in call_stack:
                        try:
                            a = cfg.get_any_node(int(c, 16))
                            call_stack_list.append(a)
                        except:
                            pass
                    # print(call_stack_list)
                    # try:
                    #     print([str(i) for i in next_node.block.capstone.insns])
                    # except:
                    #     pass
                    # addr = lpg.active[0].history.addr
                    # if addr == next_addr:
                    #     if call_stack_list[0].name != "main" and next_node != None:
                    #         with open("rust_no_call_stack", 'a') as f:
                    #             f.write(path + ":\n")
                    #             call_stack_list.reverse()
                    #             for fun in call_stack_list[3:]:
                    #                 f.write("\t" + fun.name + "\n")
                    #             f.write("\n")
                    #         os.system('kill %d' % os.getpid())
                if len(lpg.active) > 1:
                    print(lpg)
                    # if len(recorder.backend_z3.query_record.query_list) < query_list_num:
                    #     recorder.backend_z3.query_record.query_list.append("branch point: " + str(lpg.active[0].history.addr))
                    # print(lpg.active[0].ip)
                try:
                    if len(lpg.spinning) != 0:
                        lpg.drop(stash="spinning")
                except:
                    pass
                if len(lpg.active) > 2:
                    lpg.split(stash_splitter=my_split)
                    lpg.drop(stash="stashed")

                if lpg.deadended:
                    for pg in lpg.deadended:
                        executed_addr.update(pg.history.bbl_addrs.hardcopy)
                        path_count[0] += 1
                    # if len(recorder.backend_z3.query_record.query_list) < query_list_num:
                    #     recorder.backend_z3.query_record.query_list.append("deadend: " + str(lpg.deadended[0].history.addr))
                    lpg.drop(stash='deadended')

                return lpg

            # signal.signal(signal.SIGINT, sigint_handler)
            signal.signal(signal.SIGALRM, handler)
            signal.alarm(tel)
            step_count = 0
            for _ in (itertools.count()):
                if not pg.complete() and pg._stashes['active']:
                    pg.run(n=100, step_func=my_step_func)
                    step_count += 1

                    end_time = time.time()
                    time_delta = end_time - start_time
                    if time_delta > tel:
                        logger.warning('Analysing time out 2')
                        break

                    # m = psutil.Process(os.getpid()).memory_percent()
                    # if m > 20:
                    #     logger.error("use too many memory")
                    #     with open("stop.json", "a") as f:
                    #         f.write(os.path.splitext(os.path.basename(path))[0])
                    #     break
                    # n = psutil.virtual_memory()[2]
                    # if n > 80 and m > 10:
                    #     logger.error("use too many total memory")
                    #     break
                    if step_count % 10000 == 0:
                        logger.info(str(step_count) + " instructions have been executed.")
                    continue
                break
            signal.alarm(0)
        else:
            pg.run()
    except TimeoutError:
        logger.warning('Analysing time out')
        signal.alarm(0)
    except:
        logger.error(traceback.format_exc())

    end_time = time.time()
    time_delta = end_time - start_time

    try:
        # check_coverage_correctness(cfg, executed_addr, total_addr)
        executed_addr = executed_addr.intersection(total_addr)
        block_cov = len(executed_addr) / len(total_addr)
    except:
        block_cov = 0

    # output all kinds of data
    logger.info("total_time: " + str(time_delta))
    log_time_info(block_cov, path_count, time_delta, recorder)
    export_selected_query(path, recorder)
    export_random_query(path, recorder)
    export_pathgroup(path, pg, sym_argv, time_delta)
    logger.removeHandler(log_handler)


def add_constraint_for_arg(state, sym_argv):
    for byte in sym_argv.chop(8):
        state.add_constraints(byte != '\x00')  # null
        state.add_constraints(byte >= ' ')  # '\x20'
        state.add_constraints(byte <= '~')  # '\x7e'


def check_coverage_correctness(cfg, executed_addr, total_addr):
    print(len(executed_addr))
    dif_addr = executed_addr - total_addr
    executed_addr = executed_addr.intersection(total_addr)
    print(len(executed_addr))
    print(len(total_addr))
    no_list = []
    for addr in dif_addr:
        no_list.append(cfg.get_any_node(addr))
    for i in no_list:
        print(i)
    print("true_list")
    yes_list = []
    for addr in executed_addr:
        yes_list.append(cfg.get_any_node(addr))
    for i in yes_list:
        print(i)
    return executed_addr


def draw_cfg(p, recorder):
    cfg = None
    total_addr = set()
    executed_addr = set()
    try:
        signal.signal(signal.SIGALRM, handler)
        signal.alarm(10)
        cfg = p.analyses.CFGEmulated()
        signal.alarm(0)
    except TimeoutError:
        signal.alarm(0)
        cfg = p.analyses.CFGFast()
    except:
        cfg = p.analyses.CFGFast()
    try:
        if cfg != None:
            main_obj = p.loader.main_object.get_symbol('main')
            own_addr = [main_obj.linked_addr, main_obj.rebased_addr]
            i = 0
            while (i < len(own_addr)):
                new_node = cfg.get_any_node(own_addr[i])
                if new_node is not None:
                    for succ_block in new_node.successors:
                        if succ_block.addr not in own_addr:
                            own_addr.append(succ_block.addr)
                i += 1
            total_addr = set(own_addr)
        else:
            logger.error('cfg recover failed')
            total_addr.add(None)
    except:
        pass
    try:
        query_list_num = 100
        recorder.engine.exe_time = 0
        recorder.successor.suc_time = 0
        recorder.backend_z3.query_record.list_num = query_list_num
    except:
        pass
    try:
        sol_time_dir = cf.get("Path", "time")
        recorder.backend_z3.query_record.time_output_addr = os.path.join(sol_time_dir, "solver_time.log")
    except:
        pass
    return cfg, executed_addr, total_addr


""" export query of single file"""
def export_random_query(path, recorder):
    output_dir = cf.get("Path", "output")
    output_path = os.path.join(output_dir, os.path.splitext(os.path.basename(path))[0] + "_con.json")
    try:
        with open(output_path, 'w') as f:
            for i in recorder.backend_z3.query_record.query_list:
                f.write("filename: " + path + "\n")
                f.write(i + "\n")
                recorder.backend_z3.query_record.query_list = []
    except:
        print("output query failed")


def log_time_info(block_cov, path_count, time_delta, recorder):
    try:
        logger.info("block coverage: " + str(block_cov))
        logger.info("paths: " + str(path_count[0]))
        logger.info("solver_time: " + str(recorder.backend_z3.query_record.sol_time))
        logger.info("add_con_time: " + str(recorder.frontend.con_time))
        logger.info("execute_time: " + str(recorder.engine.exe_time))
        logger.info("add_successor_time: " + str(recorder.successor.suc_time))
        logger.info("time_per: " + str(
            (recorder.engine.exe_time + recorder.successor.suc_time) / time_delta))
        recorder.frontend.con_time = 0
        recorder.engine.exe_time = 0
        recorder.successor.suc_time = 0
        recorder.backend_z3.query_record.sol_time = 0
    except:
        print("lib not changed")
    try:
        time_dir = cf.get("Path", "time")
        time_deltas = recorder.backend_z3.query_record.time_list
        with open(os.path.join(time_dir, "solver_time.log"), "a") as f:
            for time_delta in time_deltas:
                f.write(time_delta)
                recorder.backend_z3.query_record.time_list = []
    except:
        pass


""" export query with timespan limit"""
def export_selected_query(path, recorder):
    query_dir = cf.get("Path", "query")
    try:
        my_timeout_list = recorder.backend_z3.query_record.timeout_list
        with open(os.path.join(query_dir, "timeout_query.log"), "a") as f:
            for query in my_timeout_list:
                f.write("filename: " + path + "\n")
                f.write(query + "\n")
        my_query_before_timeout = recorder.backend_z3.query_record.query_before_timeout
        with open(os.path.join(query_dir, "timein_query.log"), "a") as f:
            for query in my_query_before_timeout:
                f.write("filename: " + path + "\n")
                f.write(query + "\n")
        mid_time_query = recorder.backend_z3.query_record.mid_time_list
        with open(os.path.join(query_dir, "mid_time_query.log"), "a") as f:
            for query in mid_time_query:
                f.write("filename: " + path + "\n")
                f.write(query + "\n")
    except:
        print("output timeout query failed")


def export_pathgroup(path, pg, sym_argv=None, time_delta=0):
    # output crash info
    for err in pg.errored:
        print('[-] Error: ' + repr(err))
        with open('errors.txt', 'a') as f:
            f.write(path + repr(err) + '\n')
    pg.drop(stash='active')
    try:
        pg.drop(stash='deferred')
    except:
        pass

"""
def add_rust_support(p):
    if "rust" in p.filename:
        # for obj in p.loader.initial_load_objects:
        #     for reloc in obj.imports.values():
        #         if reloc.resolvedby is not None:
        #             print(reloc.resolvedby.name, hex(reloc.resolvedby.rebased_addr))
        #         else:
        #             print(reloc)
        objs = p.loader.main_object
        # lang_start_addr = objs.get_symbol('_ZN2rt10lang_start20h58cfae38546804729kxE').rebased_addr
        p.hook_symbol('_ZN2rt10lang_start20h58cfae38546804729kxE', lang_start())
        # print_addr = objs.get_symbol('_ZN2io5stdio6_print20h47445faa595ef503E6gE').rebased_addr
        p.hook_symbol('_ZN2io5stdio6_print20h47445faa595ef503E6gE', angr.SIM_PROCEDURES['libc']['printf']())
        p.hook_symbol('_ZN6string13_$LT$impl$GT$9to_string9to_string21h12836934065809422381E', to_string())
        # p.hook_symbol('_ZN9panicking9panic_fmt20h4c8d12e3c05f3b8cZEKE', angr.SIM_PROCEDURES['stubs']['ReturnUnconstrained']())
"""

def conf_para(args, bin_path):
    print('[*] Analysing...')
    print(bin_path)
    input_length = args.length

    if input_length is None:
        input_length = cf.getint("Symvar", "length")

    run_symexe(bin_path, input_length, withtime=args.time)
    print('[*] Analysis completed\n')
