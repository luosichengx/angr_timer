import json
import math
import os
import random
import sys

import torch

sys.setrecursionlimit(1000000)
from collections import defaultdict
from .Tree import varTree as Tree
import re
import signal
import pickle


op = ["forall","exists","and","or","not","distinct","implies","iff","symbol","function","real_constant",
      "bool_constant","int_constant","str_constant","plus","minus","times","le","lt","equals",
      "ite","toreal","bv_constant","bvnot","bvand","bvor","bvxor","concat","extract","rotation",
      "extend","zero_extend","sign_extend","bvult","bvule","bvuge","bvugt","bvneg","bvadd","bvsub","bvmul","bvudiv",
      "bvurem","bvlshl","bvlshr","bvrol","bvror","bvzext","bvsext","bvslt","bvsle","bvcomp","bvsdiv",
      "bvsrem","bvashr","str_length","str_concat","str_contains","str_indexof","str_replace","str_substr",
      "str_prefixof","str_suffixof","str_to_int","int_to_str","str_charat","select","store","value",
      "div","pow","algebraic_constant","bvtonatural","_to_fp","=","bvsge","compressed_op","unknown"]

si_op = ["extract","zero_extend","sign_extend","_to_fp"]

tri_op = ["ite"]

bv_constant = "constant"
bool_constant = "constant"


class QT:
    def __init__(self, query_tree, filename):
        self.logic_tree = query_tree.logic_tree
        self.timeout = query_tree.timeout
        self.filename = filename
        self.feature = [math.log(x + 1) for x in query_tree.feature]

class query_tree:
    def __init__(self):
        self.filename = None
        self.sol_time = 0
        self.tree_list = []
        self.logic_tree = None
        self.val_list = []
        self.val_dic = {}
        self.used = defaultdict(bool)
        self.mid_val = {}
        self.timeout = None
        self.cut_num = 0
        self.feature = [0] * (len(op) + 4)
        self.script = None

    def load(self, input):
        with open(input) as f:
            data = f.read()
        self.script_to_tree(data, input)

    def script_to_tree(self, data, input):
        try:
            data = json.loads(data)
            self.filename = data['filename']
            try:
                self.timeout = float(data["time"])
                #self.timeout = max(data['double_check_time'])
                # self.timeout = sum(data['double_check_time']) / len(data['double_check_time'])
            except:
                print(data["double_check_time"])
                self.timeout = float(data["time"])
            data = data["smt_script"]
            data_list = data.split("\n")
        except:
            data_list = data.split("\n")
            try:
                if data_list[0].startswith("filename"):
                    self.filename = data_list[0].split("/")[-1]
                else:
                    self.filename = input.split("/")[-1]

                if "time:" in data_list[-1]:
                    self.sol_time = data_list[-1].split(" ")[-1]
                    self.timeout = float(self.sol_time)
            except:
                pass
        self.script = data
        for i in range(len(data_list)):
            if "declare-fun" in data_list[i]:
                var_name = data_list[i].split(" ", maxsplit=1)[1]
                var_name = var_name.split(" ()", maxsplit=1)[0]
                self.val_list.append(var_name)
                self.val_dic[var_name] = "var" + str(len(self.val_list))
                self.feature[-1] += 1
            elif "assert" in data_list[i]:
                break
        for var_name in self.val_list:
            data = data.replace(var_name, self.val_dic[var_name])
        try:
            self.str_to_tree_list(data.split("(assert\n")[1:])
            self.generate_logic_tree_by_order()
            self.cut_length()
            self.feature[-4] = self.logic_tree.node
            self.feature[-2] = self.logic_tree.depth
        except:
            self.logic_tree = vartree('unknown', None, None, None)

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

    def generate_logic_tree(self):
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

    def generate_logic_tree_by_order(self):
        tl = self.tree_list[1:]
        try:
            root = self.tree_list[0]
        except:
            print(self.script)
        while len(tl) != 0:
            if len(tl) == 1:
                root = vartree("and", root, tl[0])
            else:
                root = vartree("and", root, tl[0], tl[1])
            tl = tl[2:]
        self.logic_tree = root

    def str_to_tree_list(self, assertions):
        # assertion
        for assertion in assertions:
            data_lines = assertion.split("\n")
            # one line
            for data_line in data_lines:
                if data_line == "(check-sat)" or data_line == "":
                    continue
                data_list = data_line.split(" ")
                stack = []
                name = None
                if "time:" in data_line:
                    break
                else:
                    try:
                        if "let" not in data_line:
                            name = "midval"
                        for da in data_list:
                            if name and da.startswith("("):
                                for i in range(da.count("(")):
                                    stack.append("(")
                            d = da.replace("(", "")
                            d = d.replace(")", "")
                            if d == '' or d == '_' or d == "let":
                                continue
                            elif d.startswith("?x") or d.startswith("$x"):
                                if name:
                                    if self.used[d] == False:
                                        stack.append(self.mid_val[d])
                                        self.used[d] = True
                                    else:
                                        # stack.append(copy(self.mid_val[d]))
                                        stack.append(self.generate_replace(self.mid_val[d]))
                                else:
                                    name = d
                            elif d.isdigit():
                                pass
                            elif re.match("bv[0-9]+", d):
                                stack.append(vartree(bv_constant))
                                self.feature[-3] += 1
                            elif d == "true" or d == "false":
                                stack.append(vartree(bool_constant))
                                self.feature[-3] += 1
                            elif d.startswith("var"):
                                stack.append(vartree(d))
                                self.feature[-3] += 1
                            elif d in op:
                                stack.append(d)
                                self.feature[op.index(d)] += 1
                            res = da.count(")")
                            while(res != 0 and "(" in stack):
                                stack_rev = stack[::-1]
                                i = stack_rev.index("(")
                                if len(stack[-i:]) == 1:
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
                                self.tree_list.append(stack[0])
                                # print("assert", self.tree_list[-1])
                    except Exception as e:
                        if isinstance(e,TimeoutError):
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
                                        # stack.append(copy(self.mid_val[d]))
                                        stack.append(self.generate_replace(self.mid_val[d]))
                                else:
                                    name = d
                            elif re.match("bv[0-9]+", d):
                                stack.append(vartree(bv_constant))
                            elif d == "true" or d == "false":
                                stack.append(vartree(bool_constant))
                            elif d.startswith("var"):
                                stack.append(vartree(d))
                        stack = stack + [None]*3
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
    return ret


def vartree(val,left= None,mid= None,right= None):
    ret = Tree(val, left, mid, right)
    ret.cal()
    return ret


def handler(signum, frame):
    # signal.alarm(1)
    # print("timeout")
    raise TimeoutError


def script_list_to_dataset(data_list):
    qt_list = []
    for script in data_list:
        querytree = query_tree()
        querytree.script_to_tree(script, input)
        qt = QT(querytree, input)
        qt_list.append(qt)
        if len(qt_list) % 500 == 0:
            print(len(qt_list))
    return qt_list


def count_data(input):
    print(input)
    qt_list = []
    cut_list = []
    if os.path.isdir(input):
        for root, dirs, files in os.walk(input):
            for file in files:
                # print(file)
                try:
                    signal.signal(signal.SIGALRM, handler)
                    # signal.alarm(1)
                    querytree = query_tree()
                    querytree.load(os.path.join(input, file))
                    qt = QT(querytree, file)
                    qt_list.append(qt)
                    # signal.alarm(0)
                    cut_list.append(querytree.cut_num)
                    if len(qt_list) % 100 == 0:
                        print(len(qt_list))
                except TimeoutError:
                    pass
    elif os.path.exists(input):
        qt = query_tree()
        with open(input) as f:
            data = f.read()
        data_list = data.split("\n\n")
        for script in data_list:
            querytree = query_tree()
            querytree.script_to_tree(script, input)
            qt = QT(querytree, input)
            qt_list.append(qt)
            if len(qt_list) % 500 == 0:
                print(len(qt_list))
    else:
        i = 0
        input_file = input + str(i)
        while(os.path.exists(input_file)):
            qt = query_tree()
            query_tree.load(qt,input)
            qt_list.append(qt)
            i += 1
            input_file = input + str(i)
    torch.save(cut_list, 'cut60.pt')
    return qt_list


def split_train_test(qt_list):
    # random.shuffle(qt_list)
    td = int(len(qt_list) * 0.8)
    train = qt_list[:td]
    test = qt_list[td:]
    return train, test


def generate_dataset(input):
    qt_list = count_data(input)
    return split_train_test(qt_list)

