from preprocessing.query_to_tree import *
import numpy as np

class FV:
    def __init__(self, query_tree, filename=None):
        self.logic_tree = query_tree.feature_list
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

class feature_vectors(query_tree):
    # def __init__(self, script_info, time_selection="origin"):
    #     query_tree.__init__(script_info, time_selection)

    def script_to_tree(self):
        self.feature_list = []
        data = self.script_info.script
        self.cal_training_label()
        data_list = data.split("\n")
        for i in range(len(data_list)):
            if "declare-fun" in data_list[i]:
                var_name = data_list[i].split(" ", maxsplit=1)[1]
                var_name = var_name.split(" (", maxsplit=1)[0]
                var_name = var_name.rstrip(" ")
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
            self.standardlize()
            # truncate tree by depth. default 60
            # self.cut_length()
            # collecting tree structure information
            # self.feature[-4] = self.logic_tree.node
            # self.feature[-2] = self.logic_tree.depth
        except Exception as e:
            # print(e)
            self.logic_tree = vartree('unknown', None, None, None)

    def assertion_stack_to_tree_list(self, assertions):
        sl = assertions.split("(assert")
        asserts = ["(assert" + x for x in sl[1:]]
        asserts_bool = []
        new_str = sl[0]
        try:
            for assertion in asserts:
                feature = self.count_feature(assertion).val
                self.feature_list.append(feature)
        except:
            traceback.print_exc()
            return

    def standardlize(self):
        if len(self.feature_list) == 0:
            self.feature_list = np.zeros((50,150))
            return
        feature_list = np.array(self.feature_list)
        if len(feature_list) < 50:
            padding_num = 50 - len(feature_list)
            feature_list = np.row_stack([feature_list, np.zeros([padding_num, 150])])
            self.feature_list = feature_list
        else:
            feature_list[-50] = np.sum(feature_list[:-49], axis=0)
            self.feature_list = feature_list[-50:]
        self.feature = np.sum(feature_list, axis=0).tolist()
        self.feature_list = np.log(self.feature_list+1)