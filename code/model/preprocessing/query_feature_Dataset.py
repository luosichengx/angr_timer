from .query_tree_Dataset import *
from .feature_vectors import *

class query_feature_Dataset(Dataset):
    def generate_tree_dataset(self, input, time_selection=None, test_filename=None):
        if isinstance(input, list):
            self.str_list = input
        elif isinstance(input, str) and '\n' in input:
            self.str_list = [input]
        else:
            self.load_from_directory(input)
        self.judge_json(self.str_list[0])
        output_ind = 0
        for ind, string in enumerate(self.str_list):
            script = Script_Info(string, self.is_json)
            # self.script_list.append(script)
            s = time.time()
            # try:
            try:
                if script.solving_time_dic["z3"][0] < 0:
                    continue
            except:
                pass
            featurevectors = feature_vectors(script, time_selection)
            featurevectors.script_to_tree()
            e = time.time()
            # print(querytree.logic_tree.node, e - s)
            fv = FV(featurevectors)
            self.qt_list.append(fv)
            if len(self.qt_list) % 500 == 0:
                print(len(self.qt_list))
                # print(qt.feature, e-s)
                # break
                # th.save(self.qt_list, "/home/lsc/treelstm.pytorch/data/mid" + str(output_ind) + ".pkl")
                # output_ind += 1
                # del self.qt_list
                # gc.collect()
                # self.qt_list = []
        return self.qt_list

    def split_with_filename(self, test_filename=None):
        if not test_filename:
            random.shuffle(b)
            test_filename = b[:10]
        train_dataset = []
        test_dataset = []
        trt = 0
        tet = 0
        for qt in self.qt_list:
            if qt.filename in test_filename:
                test_dataset.append(qt)
                if qt.gettime() >= 300:
                    tet += 1
            else:
                train_dataset.append(qt)
                if qt.gettime() >= 300:
                    trt += 1
        return train_dataset,test_dataset
