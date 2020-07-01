from __future__ import absolute_import

from collections import namedtuple
import networkx as nx

from dgl.graph import DGLGraph
import torch

SMTBatch = namedtuple('SMTBatch', ['graph', 'wordid', 'label'])

class dgl_dataset(object):
    def __init__(self, data, vocab=None, task="regression"):
        self.trees = []
        self.task = task
        self.filename_list = []
        self.vocab = vocab
        self.num_classes = 2
        self._load(data)

    def _load(self, qt_list):
        # build trees
        for qt in qt_list:
            self.trees.append(self._build_tree(qt))
            try:
                self.filename_list.append(qt.filename)
            except:
                self.filename_list.append(None)

    def _build_tree(self, qt):
        root = qt.logic_tree
        g = nx.DiGraph()
        def _rec_build(nid, root):
            for child in [root.left, root.mid, root.right]:
                if child:
                    cid = g.number_of_nodes()
                    try:
                        word = self.vocab.labelToIdx[child.val]
                    except:
                        word = 1
                    g.add_node(cid, x=word, y= 0)
                    g.add_edge(cid, nid)
                    _rec_build(cid, child)
        # add root
        if self.task == "classification":
            if isinstance(qt.timeout, bool):
                result = 0 if qt.timeout else 1
            else:
                result = 0 if qt.timeout > 250 else 1
        else:
            result = qt.timeout
            if not result:
                result = -1
        if result == None:
            result = 0
        g.add_node(0, x=self.vocab.labelToIdx[root.val], y=result)
        _rec_build(0, root)
        ret = DGLGraph()
        ret.from_networkx(g, node_attrs=['x', 'y'])
        return ret

    def __getitem__(self, idx):
        return self.trees[idx], self.filename_list[idx]

    def __len__(self):
        return len(self.trees)

    @property
    def num_vocabs(self):
        return self.vocab.size()
