import json
import time
import os
import random
import torch as th
import gc

from .query_to_tree import Script_Info, query_tree, QT
from preprocessing.pysmt_tree import pysmt_query_tree

b = ["[","chmod","dd","expr","hostid","md5sum","nproc","ptx","sha224sum","stdbuf","touch","unlink","b2sum","chown","df",
"factor","id","mkdir","numfmt","pwd","sha256sum","stty","tr","uptime","base32","chroot","dir","false","join","mkfifo",
"od","readlink","sha384sum","sum","true","users","base64","cksum","dircolors","fmt","kill","mknod","paste","realpath",
"sha512sum","sync","truncate","vdir","basename","comm","dirname","fold","link","mktemp","pathchk","rm","shred","tac",
"tsort","wc","basenc","cp","du","getlimits","ln","mv","pinky","rmdir","shuf","tail","tty","who","cat","csplit","echo",
"ginstall","logname","nice","pr","runcon","sort","tee","uname","whoami","chcon","cut","env","groups","ls","nl",
"printenv","seq","split","test","unexpand","yes","chgrp","date","expand","head","make-prime-list","nohup","printf",
"sha1sum","stat","timeout","uniq"]

test_filename = ["echo", "ginstall", "expr", "tail", "seq", "split", "test", "yes", "chgrp", "date", "expand", "head",
            "nohup", "printf", "sha1sum", "stat", "timeout", "uniq", "nice", "pr"]


# input all kinds of scripts and return expression tree
class Dataset:
    def __init__(self):
        self.str_list = []
        self.script_list = []
        self.qt_list = []
        self.is_json = True
        self.filename_list = []

    # read data from file directory or script, preprocess scripts into expression trees
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
            # if test_filename and script.filename in test_filename:
            #     if re.match("crosscombine[0-9]+", self.filename_list[ind]) or re.match("timeout[0-9]+", self.filename_list[ind]):
            #         continue
            querytree = query_tree(script, time_selection)
            querytree.script_to_tree()
            # except:
            #     pass
            # querytree = pysmt_query_tree(script, time_selection)
            # querytree.script_to_tree()
            # e = time.time()
            # # print(querytree.logic_tree.node, e - s)
            qt = QT(querytree)
            self.qt_list.append(qt)
            if len(self.qt_list) % 500 == 0:
                print(len(self.qt_list))
                # print(qt.feature, e-s)
                # break
                # if len(self.qt_list) % 4000 == 0:
                #     th.save(self.qt_list, "/home/lsc/treelstm.pytorch/data/mid" + str(output_ind) + ".pkl")
                #     output_ind += 1
                #     del self.qt_list
                #     gc.collect()
                #     self.qt_list = []
        return self.qt_list

    def augment_scripts_dataset(self, input):
        if isinstance(input, list):
            self.str_list = input
        elif isinstance(input, str) and '\n' in input:
            self.str_list = [input]
        else:
            self.load_from_directory(input)
        self.judge_json(self.str_list[0])
        for string in self.str_list:
            script = Script_Info(string, self.is_json)
            # self.script_list.append(script)
        return self.script_list

    # only accept files with single script
    def load_from_directory(self, input):
        if not input or input == "":
            return
        if os.path.isdir(input):
            for root, dirs, files in os.walk(input):
                for file in files:
                    # print(file)
                    with open(os.path.join(input, file)) as f:
                        data = f.read()
                    if data != "":
                        self.str_list.append(data)
                        self.filename_list.append(file)
        elif os.path.exists(input):
            with open(input) as f:
                data = f.read()
            if data != "":
                self.str_list = [data]

    def judge_json(self, data):
        try:
            json.loads(data)
            self.is_json = True
        except:
            pass

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