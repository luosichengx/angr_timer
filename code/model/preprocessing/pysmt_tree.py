import json
import sys

from pysmt.oracles import SizeOracle
from pysmt.smtlib.parser import SmtLibParser
from six.moves import cStringIO
from pysmt.operators import __OP_STR__

sys.setrecursionlimit(1000000)
# from Tree import varTree as Tree
import numpy as np
from .query_to_tree import *

class pysmt_query_tree(query_tree):
    # def __init__(self, script_info, time_selection="origin"):
    #     query_tree.__init__(script_info, time_selection)

    def script_to_tree(self):
        data = self.script_info.script
        self.cal_training_label()
        data_list = data.split("\n")
        for i in range(len(data_list)):
            if "declare-fun" in data_list[i]:
                var_name = data_list[i].split(" ", maxsplit=1)[1]
                var_name = var_name.split(" (", maxsplit=1)[0]
                self.val_list.append(var_name)
                self.val_dic[var_name] = "var" + str(len(self.val_list))
                self.feature[-1] += 1
            elif "assert" in data_list[i]:
                break
        # for var_name in self.val_list:
        #     data = data.replace(var_name, self.val_dic[var_name])
        try:
            # parse assertion stack into expression trees
            self.assertion_stack_to_tree_list(data)
            # merging sub tree: bottom_up_merging or accumulation
            self.accumulation()
            # truncate tree by depth. default 60
            self.cut_length()
            # collecting tree structure information
            self.feature[-4] = self.logic_tree.node
            self.feature[-2] = self.logic_tree.depth
        except Exception as e:
            # print(e)
            self.logic_tree = vartree('unknown', None, None, None)

    def assertion_stack_to_tree_list(self, assertions):
        sl = assertions.split("(assert")
        asserts = ["(assert" + x for x in sl[1:]]
        if len(asserts) > 50:
            asserts[-100] = "\n".join(asserts[:-49])
            asserts = asserts[-50:]
        asserts_bool = []
        new_str = sl[0]
        for assertion in asserts:
            if "assert" not in assertion:
                continue
            if assertion.count("\n") > 40 or assertion.count("assert") > 1:
                asserts_bool.append(True)
            else:
                asserts_bool.append(False)
                new_str += assertion
        assertions = new_str
        ind = 0
        try:
            smt_parser = SmtLibParser()
            script = smt_parser.get_script(cStringIO(assertions))
        except:
            return
        try:
            assert_list = script.commands
            command_ind = 0
            while(command_ind < len(assert_list) and assert_list[command_ind].name != "assert"):
                command_ind += 1
            for assert_ind in range(len(asserts)):
                if asserts_bool[assert_ind] == True:
                    new_tree = self.assertion_to_tree(None, asserts[assert_ind])
                else:
                    new_tree = self.assertion_to_tree(assert_list[command_ind], asserts[assert_ind])
                    command_ind += 1
                if new_tree != None:
                    self.tree_list.append(new_tree)
            # for command in assert_list:
            #     if command.name == "assert":
            #         new_tree = self.assertion_to_tree(command, asserts[ind])
            #         if new_tree != None:
            #             self.tree_list.append(new_tree)
            #         ind += 1
            assert_list = None
        except:
            traceback.print_exc()
            return

    def assertion_to_tree(self, command, assertion):
        if assertion.count("\n") < 40 and assertion.count("assert") == 1:
            root = self.fnode_to_tree(command.args[0], 20)
        else:
            root = self.count_feature(assertion)
            root.val = [math.log(x + 1) for x in root.val]
        return root

    def fnode_to_tree(self, fnode, depth=0):
        if depth == 0:
            root = Tree("")
            root.val = self.fnode_to_feature(fnode).tolist()
            return root
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
                root = self.fnode_to_tree(fnode.arg(0), depth - 1)
            else:
                subnode_list = []
                for subnode in fnode.args():
                    subnode_list.append(self.fnode_to_tree(subnode, depth - 1))
                subnode_list.extend([None, None, None])
                root = vartree(op[fnode.node_type()], subnode_list[0], subnode_list[1], subnode_list[2])
        else:
            root = vartree("unknown")
        return root

    def fnode_to_feature(self, fnode):
        features = np.zeros(150)
        if fnode.is_symbol():
            if fnode.symbol_name() in self.val_list:
                ind = min(int(self.val_dic[fnode.symbol_name()][3:]), 20)
                features[111 + ind] += 1
            else:
                features[133] += 1
        elif fnode.is_constant():
            features[21] += 1
        elif fnode.is_term():
            features[fnode.node_type()] += 1
            for subnode in fnode.args():
                features += self.fnode_to_feature(subnode)
        return features
