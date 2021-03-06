import collections
import os
import torch as th
import torch.optim as optim
from torch.utils.data import DataLoader

import dgl
from .dgl_treelstm.tree_lstm import TreeLSTM
from .dgl_treelstm.util import extract_root
from .preprocessing import dgl_dataset,query_to_tree,Vocab,Constants

SSTBatch = collections.namedtuple('SSTBatch', ['graph', 'wordid', 'label', 'filename'])
def batcher(device):
    def batcher_dev(batch):
        tree_batch = [x[0] for x in batch]
        batch_trees = dgl.batch(tree_batch)
        return SSTBatch(graph=batch_trees,
                        wordid=batch_trees.ndata['x'].to(device),
                        label=batch_trees.ndata['y'].to(device),
                        filename=[x[1] for x in batch])
    return batcher_dev

class Predictor:
    model = None
    smt_vocab = None
    h_size = 150

    def __init__(self, smt_script, load_file,args):
        self.script = smt_script
        self.load_file = load_file
        self.device = th.device('cuda:{}'.format(args.gpu)) if th.cuda.is_available() else th.device('cpu')
        self.init_static()
        self.optimizer = optim.Adagrad(filter(lambda p: p.requires_grad,
                                              Predictor.model.parameters()), lr=args.lr, weight_decay=args.weight_decay)
        self.train_dataset = None
        self.test_dataset = None
        self.train_loader = None
        self.test_loader = None

    @staticmethod
    def init_static():
        base_dir = os.path.dirname(os.path.abspath(__file__))
        if not Predictor.smt_vocab:
            smt_vocab_file = "/".join([base_dir,'smt.vocab'])
            Predictor.smt_vocab = Vocab(filename=smt_vocab_file,
                                        data=[Constants.PAD_WORD, Constants.UNK_WORD,
                                              Constants.BOS_WORD, Constants.EOS_WORD])
        smt_vocab = Predictor.smt_vocab
        if not Predictor.model:
            pretrained_emb = th.load("/".join([base_dir,'smt.pth']), map_location='cpu')
            Predictor.model = TreeLSTM(Predictor.smt_vocab.size(),
                                       150,
                                       150,#args.h_size,
                                       2,#args.num_classes,
                                       0.5,#args.dropout,
                                       True,#args.regression,
                                       False,#args.attention,
                                       cell_type='childsum',
                                       pretrained_emb=pretrained_emb).to(th.device('cpu'))
            model = Predictor.model
            checkpoint = th.load("/".join([base_dir,'model.pkl']), map_location='cpu')
            model.load_state_dict(checkpoint['model'])

    # def load_file(self, args):
    #     train_dataset, test_dataset = query_to_tree.generate_dataset(
    #         os.path.join('./data/gnucore', args.data_source))
    #     return train_dataset + test_dataset
    #
    # def load_dataset(self, args):
    #     output_dir = os.path.join('./data/gnucore', args.input)
    #     if not os.path.exists(output_dir):
    #         os.makedirs(output_dir)
    #     train_file = os.path.join(output_dir, 'gnucore_train')
    #     test_file = os.path.join(output_dir, 'gnucore_test')
    #     if os.path.isfile(train_file):
    #         train_dataset = th.load(train_file)
    #         test_dataset = th.load(test_file)
    #     else:
    #         train_dataset, dev_dataset, test_dataset = query_to_tree.generate_dataset(
    #             os.path.join('./data/gnucore', args.data_source))
    #         th.save(train_dataset, train_file)
    #         th.save(test_dataset, test_file)
    #     return train_dataset, test_dataset

    @staticmethod
    def predict(script):
        Predictor.init_static()
        model = Predictor.model
        dataset = query_to_tree.script_list_to_dataset([script])
        dataset = dgl_dataset(dataset, Predictor.smt_vocab, "regression")
        device = th.device('cpu')
        test_loader = DataLoader(dataset=dataset,
                                 batch_size=1, collate_fn=batcher(device), shuffle=False, num_workers=0)
        t1 = 200
        model.eval()
        pred = -1
        for step, batch in enumerate(test_loader):
            g = batch.graph
            n = g.number_of_nodes()
            with th.no_grad():
                h = th.zeros((n, Predictor.h_size)).to(device)
                c = th.zeros((n, Predictor.h_size)).to(device)
                logits = model(batch, h, c)
            batch_label, logits = extract_root(batch, device, logits)
            logits = logits.reshape(-1)
            pred = logits
        return pred
