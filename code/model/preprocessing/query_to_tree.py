import json
import math
import sys

# import torch

import traceback

from pysmt.smtlib.parser import SmtLibParser
from six.moves import cStringIO
from pysmt.operators import __OP_STR__

sys.setrecursionlimit(1000000)
from collections import defaultdict
# from .Tree import varTree as Tree
from .Tree import varTree as Tree
import re
import numpy as np

pysmt_op = ["forall", "exists", "and", "or", "not", "=>", "iff", "symbol", "function", "real_constant", "bool_constant",
      "int_constant", "str_constant", "+", "-", "*", "<=", "<", "=", "ite", "toreal", "bv_constant", "bvnot", "bvand",
      "bvor", "bvxor", "concat", "extract", "bvult", "bvule", "bvneg", "bvadd", "bvsub", "bvmul", "bvudiv", "bvurem",
      "bvshl", "bvlshr", "bvrol", "bvror", "zero_extend", "sign_extend", "bvslt", "bvsle", "bvcomp", "bvsdiv", "bvsrem",
      "bvashr", "str.len", "str.++", "str.contains", "str.indexof", "str.replace", "str.substr", "str.prefixof",
      "str.suffixof", "str.to_int", "str.from_int", "str.at", "select", "store", "value", "/", "^",
      "algebraic_constant", "bv2nat"]

lib_op = ["compressed_op", "unknown", "distinct", ">=", ">", "bvuge", "bvugt", "bvsge", "bvsgt", "str.in_re",
          "str.to_re", "to_fp",  "re.range", "re.union", "re.++", "re.+", "re.*", "re.allchar", "re.none", "xor",
          "mod"]

fp_op = ["fp", "fp.neg", "fp.isZero", "fp.isNormal", "fp.isSubnormal", "fp.isPositive", "fp.isInfinite", "fp.isNan",
         "fp.eq", "fp.roundToIntegral", "fp.rem", "fp.sub", "fp.sqrt", "fp.lt", "fp.leq", "fp.gt", "fp.geq", "fp.abs",
         "fp.add", "fp.div", "fp.min", "fp.max", "fp.mul", "fp.to_sbv", "fp.to_ubv"]

op = pysmt_op + lib_op

none_op = ["extract", "zero_extend", "sign_extend", "to_fp", "repeat", "+oo", "-oo"]

tri_op = ["ite", "str.indexof", "str.replace", "str.substr", "store"]

bv_constant = "constant"
bool_constant = "constant"

reserved_word = ["declare-fun", "define-fun", "declare-sort", "define-sort", "declare-datatype", "declare-const"
                 "assert", "check-sat", "set-info", "set-logic", "set-option"]


class QT:
    def __init__(self, query_tree, filename=None):
        self.logic_tree = query_tree.logic_tree
        self.origin_time = query_tree.origin_time
        self.adjust_time = query_tree.adjust_time
        try:
            self.filename = query_tree.script_info.filename
        except:
            self.filename = filename
        # self.feature = [math.log(x + 1) for x in query_tree.feature]
        self.feature = query_tree.feature

    def gettime(self, time_selection="origin"):
        try:
            if time_selection == "origin":
                return self.origin_time
            else:
                return self.adjust_time
        except:
            return self.timeout


# SMT script file information, program name, solving time with symbolic tools, solving time with different solvers
class Script_Info:
    def __init__(self, string, is_json=False):
        self.script = None
        self.filename = None
        self.solving_time = None
        # a dict of solving time with different solvers as dict key, three solving time of each avoid variety
        self.solving_time_dic = None
        self.is_json = is_json
        self.load(string)

    def load(self, string):
        if self.is_json:
            try:
                string = json.loads(string)
                self.is_json = True
            except:
                self.is_json = False
        self.get_attr(string, None)

    def get_attr(self, str, input):
        if self.is_json:
            try:
                self.script = str["smt_script"]
                self.solving_time = str['time']
                self.filename = str['filename'].split("/")[-1]
                if 'solving_time_dic' in str.keys():
                    self.solving_time_dic = str['solving_time_dic']
                else:
                    self.solving_time_dic = str['double_check_time']
            except:
                pass
        else:
            data_list = str.split("\n")
            try:
                if data_list[0].startswith("filename"):
                    self.filename = data_list[0].split("/")[-1]
                    data_list = data_list[1:]
                else:
                    self.filename = input.split("/")[-1]

                if "time:" in data_list[-1]:
                    solving_time = data_list[-1].split(" ")[-1]
                    self.solving_time = float(solving_time)
                    self.solving_time_dic = None
                    data_list = data_list[:-1]
                self.script = "\n".join(data_list)
            except:
                self.script = str


class query_tree:
    def __init__(self, script_info, time_selection="origin"):
        self.tree_list = []
        self.logic_tree = None
        self.val_list = []
        self.val_dic = {}
        self.used = defaultdict(bool)
        self.mid_val = {}
        self.origin_time = None
        self.adjust_time = None
        self.cut_num = 0
        self.feature = np.array([0] * (len(op) + 4))
        self.script_info = script_info
        self.time_selection = time_selection
        self.type = []
        self.constant = []

    def cal_training_label(self):
        solver_list = ["msat", "cvc4", "yices", "btor", "z3"]
        if isinstance(self.script_info.solving_time_dic, dict):
            if self.time_selection in solver_list:
                time_list = self.script_info.solving_time_dic[self.time_selection]
            else:
                time_list = list(self.script_info.solving_time_dic.values())[0]
        else:
            time_list = self.script_info.solving_time_dic
        time_list = [float(x) for x in time_list]
        self.adjust_time = sum(time_list) / len(time_list)
        # self.solving_time = max(time_list)
        if self.script_info.solving_time:
            self.origin_time = float(self.script_info.solving_time)
        else:
            self.origin_time = 0

    def script_to_tree(self):
        data = self.script_info.script
        self.cal_training_label()
        last_reserved_word = None
        left_count = 0

        # replace variable with general symbol
        data_list = data.split("\n")
        define_fun = False
        sl = data.split("(assert")
        asserts = ["(assert" + x for x in sl[1:]]
        asserts_str = "".join(asserts)
        need_assert = False
        if "declare-fun" in asserts_str or "define-fun" in asserts_str:
            need_assert = True
            asserts = []
        define_list = []
        assert_str = ""
        for i in range(len(data_list)):
            if "declare-fun" in data_list[i] or "declare-sort" in data_list[i] or "define-sort" in data_list[i]:
                try:
                    var_name = data_list[i].split(" ", maxsplit=1)[1]
                    var_name = var_name.split(" (", maxsplit=1)[0]
                    var_name = var_name.rstrip(" ")
                except:
                    continue
                if "declare-fun" in data_list[i]:
                    self.val_list.append(var_name)
                    self.val_dic[var_name] = "var" + str(len(self.val_list))
                elif "declare-sort" in data_list[i]:
                    self.constant.append(var_name)
                elif "define-sort" in data_list[i]:
                    self.type.append(var_name)
                define_list.append(data_list[i])
                left_count, last_reserved_word = finished(data_list[i], left_count)
            elif "assert" in data_list[i]:
                if need_assert:
                    assert_str = assert_str + data_list[i]
                    left_count, last_reserved_word = finished(data_list[i], left_count)
                    if not left_count:
                        asserts.append(assert_str)
                        assert_str = ""
            elif "declare" in data_list[i] or "define" in data_list[i]:
                define_fun = True
                define_list.append(data_list[i])
                left_count, last_reserved_word = finished(data_list[i], left_count)
            elif last_reserved_word == "assert":
                if need_assert:
                    assert_str = assert_str + data_list[i]
                    left_count, word = finished(data_list[i], left_count)
                    if not left_count:
                        last_reserved_word = word
                        asserts.append(assert_str)
                        assert_str = ""
            elif last_reserved_word != None:
                define_list.append(data_list[i])
                left_count, word = finished(data_list[i], left_count)
                if not left_count:
                    last_reserved_word = word
            # else:
            #     print(last_reserved_word)
        if define_fun:
            self.construct_define(define_list)

        self.feature[-1] = len(self.val_list)

        # parse define-fun with pysmt parser
        # to do: handle more reserved word parser in SMT-LIB
        # if define_fun:
        #     last_reserved_word = None
        #     left_count = 0
        #     data_list = data.split("\n")
        #     for i in range(len(data_list)):
        #         if "declare-fun" in data_list[i]:
        #             define_list.append(data_list[i])
        #             left_count, finish, last_reserved_word = finished(data_list[i], left_count)
        #         elif "define-fun" in data_list[i]:
        #             define_list.append(data_list[i])
        #             left_count, finish, last_reserved_word = finished(data_list[i], left_count)
        #         elif last_reserved_word !=
        #     self.construct_define(define_list)

        try:
            # parse assertion stack into expression trees
            self.assertion_stack_to_tree_list(asserts)
            # merging sub tree: bottom_up_merging or accumulation
            # self.accumulation()
            self.bottom_up_merging()
            # truncate tree by depth. default 60
            self.cut_length()
            # collecting tree structure information
            self.feature[-4] = self.logic_tree.node
            self.feature[-2] = self.logic_tree.depth
        except TimeoutError:
            raise TimeoutError
        except Exception as e:
            self.logic_tree = vartree('unknown', None, None, None)
            raise e

    def construct_define(self, define_list):
        define_str = "\n".join(define_list)
        try:
            smt_parser = SmtLibParser()
            script = smt_parser.get_script(cStringIO(define_str))
        except:
            return
        try:
            assert_list = script.commands
            for assertion in assert_list:
                if assertion.name == "define-fun":
                    new_tree = self.fnode_to_tree(assertion.args[3])
                    self.mid_val[assertion.args[0]] = new_tree
                    self.used[assertion.args[0]] = False
        except:
            return

    def fnode_to_tree(self, fnode):
        transtable = list(__OP_STR__.values())
        # print(fnode)
        if fnode.is_symbol():
            if fnode.symbol_name() in self.val_list:
                root = vartree(self.val_dic[fnode.symbol_name()])
            else:
                root = vartree("constant")
        elif fnode.is_constant():
            root = vartree("constant")
        elif fnode.is_term():
            if fnode.is_and() and fnode.arg(1).is_true():
                root = self.fnode_to_tree(fnode.arg(0))
            else:
                subnode_list = []
                for subnode in fnode.args():
                    subnode_list.append(self.fnode_to_tree(subnode))
                subnode_list.extend([None, None, None])
                root = vartree(transtable[fnode.node_type()], subnode_list[0], subnode_list[1], subnode_list[2])
        else:
            root = vartree("unknown")
        return root

    def cut_length(self):
        root = self.logic_tree
        self._cut(root, 0)

    def _cut(self, root, depth):
        if root:
            if depth > 60:
                # var_list = list(root.var) + ['constant', None, None]
                # root.val = 'unknown'
                # for i in [0, 1, 2]:
                #     if var_list[i] != None:
                #         var_list[i] = vartree(var_list[i])
                # root.left = var_list[0]
                # root.mid = var_list[1]
                # root.right = var_list[2]
                self.cut_num += 1
                return self.generate_replace(root)
            root.left = self._cut(root.left, depth + 1)
            root.mid = self._cut(root.mid, depth + 1)
            root.right = self._cut(root.right, depth + 1)
        return root

    def generate_replace(self, root):
        var_list = list(root.var) + ['constant', None, None]
        for i in [0, 1, 2]:
            if var_list[i] != None:
                var_list[i] = vartree(var_list[i])
        root.left = var_list[0]
        root.mid = var_list[1]
        root.right = var_list[2]
        newroot = vartree('compressed_op', var_list[0], var_list[1], var_list[2])
        return newroot

    def bottom_up_merging(self):
        tl = self.tree_list
        while len(tl) != 1:
            new_tl = []
            if len(tl) % 3 != 0:
                tl.append(None)
            if len(tl) % 3 != 0:
                tl.append(None)
            for i in range(0, len(tl), 3):
                new_tl.append(vartree("and", tl[i], tl[i + 1], tl[i + 2]))
            tl = new_tl
        self.logic_tree = tl[0]

    def accumulation(self):
        tl = self.tree_list[1:]
        try:
            root = self.tree_list[0]
        except:
            return
            # print(self.script)
        while len(tl) != 0:
            if len(tl) == 1:
                root = vartree("and", root, tl[0])
            else:
                root = vartree("and", root, tl[0], tl[1])
            tl = tl[2:]
        self.logic_tree = root

    def assertion_stack_to_tree_list(self, assertions):
        assertions[-1] = assertions[-1].replace("(check-sat)", "")
        assertions[-1] = assertions[-1].replace("(exit)", "")
        if len(assertions) > 100:
            assertions[-100] = "\n".join(assertions[:-99])
            assertions = assertions[-100:]
        # assertion
        for assertion in assertions:
            root = self.count_feature(assertion)
            root.val = [math.log(x + 1) for x in root.val]
            self.tree_list.append(root)
            # if not self.parse_smt_comp(assertion):
            #     return
            # data_lines = assertion.split("\n")
            # # one line
            # for data_line in data_lines:
            #     if data_line == "(check-sat)" or data_line == "":
            #         continue
            #     if "time:" in data_line:
            #         break
            #     else:
            #         self.parse_angr_smt(data_line)

    def parse_smt_comp(self, assertion):
        data_list = assertion.split(" ")
        current_ind = 0
        data_len = len(data_list)
        stack = []
        swap_stack = ["define"]
        try:
            while current_ind < data_len:
                current = data_list[current_ind].replace("\n", "")
                current = current.strip(")")
                current = current.strip("(")
                if data_list[current_ind].startswith("("):
                    stack.extend(["("] * data_list[current_ind].count("("))
                if current == "assert":
                    current_ind += 1
                    continue
                elif current == "":
                    current_ind += 1
                    continue
                elif current in ["let", "forall", "exists"]:
                    swap_stack,stack = stack, swap_stack
                    # stack = ["define"]
                elif current == "_":
                    if data_list[current_ind + 1] in none_op:
                        stack[-1] = data_list[current_ind + 1]
                    elif data_list[current_ind + 1].startswith("bv"):
                        stack[-1] = vartree("constant")
                    else:
                        raise SyntaxError("unknown single op", data_list[current_ind + 1])
                    if ")" in data_list[current_ind + 2]:
                        current_ind += 2
                    else:
                        current_ind += 3
                    data_list[current_ind] = data_list[current_ind].replace(")", "", 1)
                elif current in op:
                    stack.append(current)
                    self.feature[op.index(current)] += 1
                elif current in self.mid_val or current[1:-1] in self.mid_val:
                    # if stack[0] == "define":
                    #     pa_count = stack.count("(")
                    #     current_ind += 1
                    #     while pa_count != 0:
                    #         pa_count += data_list[current_ind].count("(") - data_list[current_ind].count(")")
                    #         current_ind += 1
                    #         swap_stack, stack = stack, swap_stack
                    #         swap_stack = ["define"]
                    #     continue
                    if current[1:-1] in self.mid_val:
                        current = current[1:-1]
                    stack.append(self.mid_val[current])
                    # if self.used[current] == False:
                    #     stack.append(self.mid_val[current])
                    #     self.used[current] = True
                    # else:
                    #     if self.mid_val[current].node > 10:
                    #         stack.append(self.generate_replace(self.mid_val[current]))
                    #     else:
                    #         stack.append(copy(self.mid_val[current]))
                    if stack[-2] == "(" and isinstance(stack[-1], Tree):
                        left = 0
                        while (left >= 0 and current_ind < data_len - 1):
                            current_ind += 1
                            current = data_list[current_ind]
                            left = left + current.count("(") - current.count(")")
                # nested string trigger replace error
                # elif current.startswith("var"):
                #     stack.append(vartree(current))
                elif current in self.type:
                    pass
                elif current in self.constant:
                    stack.append(vartree("constant"))
                elif current in self.val_list:
                    var_n = self.val_dic[current]
                    stack.append(vartree(var_n))
                elif re.match("bv[0-9]+", current) or current in ["true", "false"] or current[0] == '"' or is_number(current):
                    stack.append(vartree("constant"))
                    self.feature[-3] += 1
                elif current.isalpha():
                    pass
                    print("unknown symbol", current, data_list)
                else:
                    stack.append(vartree("var"))
                res = data_list[current_ind].count(")")
                while (res != 0 and "(" in stack):
                    stack_rev = stack[::-1]
                    i = stack_rev.index("(")
                    tree_val = stack[-i:]
                    if len(tree_val) > 4:
                        pop_list = []
                        for ind, tr in enumerate(tree_val):
                            if ind != 0 and tr.val == "constant":
                                pop_list.append(ind)
                        tree_val = [tree_val[x] for x in range(len(tree_val)) if x not in pop_list] + [vartree("constant")] * 3
                    else:
                        tree_val = tree_val + [None] * 3
                    if isinstance(tree_val[0], Tree):
                        self.mid_val["val"] = tree_val[0]
                    else:
                        self.mid_val["val"] = vartree(tree_val[0], tree_val[1], tree_val[2], tree_val[3])
                    stack = stack[:-i - 1]
                    res -= 1
                    stack.append(self.mid_val["val"])
                    if stack[0] == "define" and len(stack) == 5:
                        if not isinstance(stack[3], Tree):
                            self.mid_val[stack[3]] = stack[4]
                            stack[4].set_name(stack[3])
                            self.used[stack[3]] = False
                        stack = stack[:2]
                        if res >= 2:
                            stack[0] = "define-done"
                            break
                        else:
                            res = 0
                    if current_ind + 1 == data_len and stack.count("(") + 1 == len(stack):
                        stack[0] = stack[-1]
                        break
                current_ind += 1
                if stack[0] == "define-done":
                    stack = swap_stack
                    swap_stack = ["define"]
            if current_ind == data_len:
                self.tree_list.append(stack[0])
        except TimeoutError:
            raise TimeoutError
        except Exception as e:
            traceback.print_exc()
            # print(assertion)
            # raise e
            return False
        return True

    def count_feature(self, assertion):
        for var_name in self.val_list:
            if " " in var_name:
                assertion = assertion.replace(var_name, self.val_dic[var_name])
        assertion = assertion.replace("(", " ")
        assertion = assertion.replace(")", " ")
        assertion = assertion.replace("\n", " ")
        from collections import Counter
        counts = Counter(assertion.split(" "))
        feature = [0] * 150
        for d in counts:
            if d in op:
                feature[op.index(d)] = counts[d]
            elif d in self.val_list:
                ind = min(int(self.val_dic[d][3:]), 20)
                feature[111 + ind] = counts[d]
            elif d[:3] == "var":
                ind = min(int(d[3:]), 20)
                feature[111 + ind] = counts[d]
            elif d.startswith("?x") or d.startswith("$x"):
                feature[21] += 1
        for i in range(len(self.feature) - 4):
            self.feature[i] += feature[i]
        root = vartree(feature)
        # self.tree_list.append(vartree(feature))
        return root

    def parse_angr_smt(self, data_line):
        for var_name in self.val_list:
            if " " in var_name:
                data_line = data_line.replace(var_name, self.val_dic[var_name])
        data_list = data_line.split(" ")
        stack = []
        name = None
        try:
            if "let" not in data_line:
                name = "midval"
            for da in data_list:
                if name and da.startswith("("):
                    for i in range(da.count("(")):
                        stack.append("(")
                d = da.strip("(")
                d = d.strip(")")
                if d in ['', '_', "let", "assert"]:
                    continue
                elif d == "true" or d == "false":
                    stack.append(vartree(bool_constant))
                elif d in op:
                    stack.append(d)
                    self.feature[op.index(d)] += 1
                elif d.startswith("?x") or d.startswith("$x"):
                    if name:
                        # stack.append(self.mid_val[d])
                        if self.used[d] == False:
                            stack.append(self.mid_val[d])
                            self.used[d] = True
                        else:
                            if self.mid_val[d].node > 20:
                                stack.append(self.generate_replace(self.mid_val[d]))
                            else:
                                stack.append(copy(self.mid_val[d]))
                    else:
                        name = d
                        if d in self.mid_val:
                            return
                # nested string trigger replace error
                # elif d.startswith("var"):
                #     stack.append(vartree(d))
                elif d in self.val_list or d[:3] == "var":
                    var_n = self.val_dic[d]
                    stack.append(vartree(var_n))
                elif re.match("bv[0-9]+", d):
                    stack.append(vartree(bv_constant))
                    self.feature[-3] += 1
                elif is_number(d):
                    pass
                elif d.isalpha():
                    pass
                    print("unknown symbol", d, data_line)
                else:
                    pass
                    print("unknown term", data_line, d)
                res = da.count(")")
                if len(stack) >= 2 and stack[-2] in none_op and isinstance(stack[-1], Tree):
                    single_tree = vartree(stack[-2], stack[-1])
                    stack = stack[:-2]
                    stack.append(single_tree)
                while (res != 0 and "(" in stack):
                    if len(stack) >= 2 and stack[-2] in none_op and isinstance(stack[-1], Tree):
                        single_tree = vartree(stack[-2], stack[-1])
                        stack = stack[:-2]
                        stack.append(single_tree)
                    stack_rev = stack[::-1]
                    i = stack_rev.index("(")
                    if len(stack[-i:]) == 1 or stack[-i] in none_op:
                        self.mid_val["val"] = stack[-i:][0]
                    else:
                        tree_val = stack[-i:] + [None] * 3
                        self.mid_val["val"] = vartree(tree_val[0], tree_val[1], tree_val[2], tree_val[3])
                    stack = stack[:-i - 1]
                    res -= 1
                    stack.append(self.mid_val["val"])
            if len(stack) != 0:
                stack = stack + [None] * 3
                if "let" in data_line and isinstance(stack[0], Tree):
                    self.mid_val[name] = stack[0]
                    stack[0].set_name(name)
                    self.used[name] = False
                    # print("let", stack[1])
                else:
                    if isinstance(stack[0], Tree):
                        self.tree_list.append(stack[0])
                    # print("assert", self.tree_list[-1])
        except Exception as e:
            # traceback.print_exc()
            if isinstance(e, TimeoutError):
                raise TimeoutError
            with open("parse_error.txt", "w") as f:
                f.write(data_line + "\n")
            data_line = data_line.replace("(", "")
            data_line = data_line.replace(")", "")
            data_list = data_line.split(" ")
            stack = []
            name = None
            if "let" not in data_line:
                name = "midval"
            for d in data_list:
                if d.startswith("?x") or d.startswith("$x"):
                    if name:
                        if self.used[d] == False:
                            stack.append(self.mid_val[d])
                            self.used[d] = True
                        else:
                            if self.mid_val[d].node > 20:
                                stack.append(self.generate_replace(self.mid_val[d]))
                            else:
                                stack.append(copy(self.mid_val[d]))
                    else:
                        name = d
                elif re.match("bv[0-9]+", d):
                    stack.append(vartree(bv_constant))
                elif d == "true" or d == "false":
                    stack.append(vartree(bool_constant))
                elif d.startswith("var"):
                    stack.append(vartree(d))
            stack = stack + [None] * 3
            if "let" in data_line:
                tree = vartree("unknown", stack[0], stack[1], stack[2])
                tree.set_name(name)
                self.mid_val[name] = tree
                self.used[name] = False
            else:
                self.tree_list.append(vartree("unknown", stack[0], stack[1], stack[2]))


def copy(tree):
    ret = None
    if tree:
        ret = Tree(tree.val)
        ret.left = copy(tree.left)
        ret.mid = copy(tree.mid)
        ret.right = copy(tree.right)
        ret.var = tree.var
        ret.depth = tree.depth
        ret.compress_depth = tree.compress_depth
    return ret


def vartree(val,left= None,mid= None,right= None):
    if left == None and isinstance(val, Tree):
        return val
    if isinstance(val, list):
        ret = Tree("")
        ret.val = val
        return ret
    ret = Tree(val, left, mid, right)
    ret.cal()
    return ret

def is_number(s):
    try:
        float(s)
        return True
    except ValueError:
        pass
    if re.match("b\#[0-9]+", s):
        return True
    return False

def finished(string, left_count):
    word = None
    for i in reserved_word:
        if i in string:
            word = i
            left_count = 0
    count = left_count + string.count("(")
    count = count - string.count(")")
    if not count:
        word = None
    return count, word