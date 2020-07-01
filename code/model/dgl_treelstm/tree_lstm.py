import time
import itertools
import networkx as nx
import numpy as np
import torch as th
import torch.nn as nn
import torch.nn.functional as F
import dgl

class TreeLSTMCell(nn.Module):
    def __init__(self, x_size, h_size):
        super(TreeLSTMCell, self).__init__()
        self.W_iou = nn.Linear(x_size, 3 * h_size, bias=False)
        self.U_iou = nn.Linear(2 * h_size, 3 * h_size, bias=False)
        self.b_iou = nn.Parameter(th.zeros(1, 3 * h_size))
        self.U_f = nn.Linear(2 * h_size, 2 * h_size)

    def message_func(self, edges):
        return {'h': edges.src['h'], 'c': edges.src['c']}

    def reduce_func(self, nodes):
        h_cat = nodes.mailbox['h'].view(nodes.mailbox['h'].size(0), -1)
        f = th.sigmoid(self.U_f(h_cat)).view(*nodes.mailbox['h'].size())
        c = th.sum(f * nodes.mailbox['c'], 1)
        return {'iou': self.U_iou(h_cat), 'c': c}

    def apply_node_func(self, nodes):
        iou = nodes.data['iou'] + self.b_iou
        i, o, u = th.chunk(iou, 3, 1)
        i, o, u = th.sigmoid(i), th.sigmoid(o), th.tanh(u)
        c = i * u + nodes.data['c']
        h = o * th.tanh(c)
        return {'h' : h, 'c' : c}

class ChildSumTreeLSTMCell(nn.Module):
    def __init__(self, x_size, h_size):
        super(ChildSumTreeLSTMCell, self).__init__()
        self.W_iou = nn.Linear(x_size, 3 * h_size, bias=False)
        self.U_iou = nn.Linear(h_size, 3 * h_size, bias=False)
        self.b_iou = nn.Parameter(th.zeros(1, 3 * h_size))
        self.U_f = nn.Linear(h_size, h_size)

    def message_func(self, edges):
        return {'h': edges.src['h'], 'c': edges.src['c']}

    def reduce_func(self, nodes):
        h_tild = th.sum(nodes.mailbox['h'], 1)
        f = th.sigmoid(self.U_f(nodes.mailbox['h']))
        c = th.sum(f * nodes.mailbox['c'], 1)
        return {'iou': self.U_iou(h_tild), 'c': c}

    def apply_node_func(self, nodes):
        iou = nodes.data['iou'] + self.b_iou
        i, o, u = th.chunk(iou, 3, 1)
        i, o, u = th.sigmoid(i), th.sigmoid(o), th.tanh(u)
        c = i * u + nodes.data['c']
        h = o * th.tanh(c)
        return {'h': h, 'c': c}

class TreeLSTM(nn.Module):
    def __init__(self,
                 num_vocabs,
                 x_size,
                 h_size,
                 num_classes,
                 dropout,
                 regression,
                 attention,
                 cell_type='nary',
                 pretrained_emb=None
                 ):
        super(TreeLSTM, self).__init__()
        self.x_size = x_size
        self.embedding = nn.Embedding(num_vocabs, x_size)
        if pretrained_emb is not None:
            self.embedding.weight.data.copy_(pretrained_emb)
            self.embedding.weight.requires_grad = True
        self.dropout = nn.Dropout(dropout)
        self.wh = nn.Linear(h_size, h_size)
        if regression:
            self.linear = nn.Linear(h_size, 1)
        else:
            self.linear = nn.Linear(h_size, num_classes)
        cell = TreeLSTMCell if cell_type == 'nary' else ChildSumTreeLSTMCell
        self.cell = cell(x_size, h_size)
        self.tree_attn = TreeAttention(h_size, h_size)
        self.attention = attention

    def forward(self, batch, h, c):
        """Compute tree-lstm prediction given a batch.
        Parameters
        ----------
        batch : dgl.data.SSTBatch
            The data batch.
        h : Tensor
            Initial hidden state.
        c : Tensor
            Initial cell state.
        Returns
        -------
        logits : Tensor
            The prediction of each node.
        """
        g = batch.graph
        g.register_message_func(self.cell.message_func)
        g.register_reduce_func(self.cell.reduce_func)
        g.register_apply_node_func(self.cell.apply_node_func)
        # feed embedding
        embeds = self.embedding(batch.wordid)
        g.ndata['iou'] = self.cell.W_iou(self.dropout(embeds))
        g.ndata['h'] = h
        g.ndata['c'] = c
        # propagate
        dgl.prop_nodes_topo(g)
        # compute logits
        h = self.dropout(g.ndata.pop('h'))
        # logits = self.linear(h)

        # attention part
        if self.attention:
            root_node_h_in_batch = []
            root_idx = []
            result_idx = 0
            for idx in g.batch_num_nodes:
                root_node_h_in_batch.append(h[result_idx])
                root_idx.append(result_idx)
                result_idx = result_idx + idx

            root_node_h_in_batch = th.cat(root_node_h_in_batch).reshape(len(root_idx), -1)
            node_num = th.tensor(batch.graph.batch_num_nodes)
            node_num = node_num.to(root_node_h_in_batch.device)
            h = self.tree_attn(h, root_node_h_in_batch, node_num)
        h = F.relu(self.wh(h))
        logits = self.linear(h)
        return logits


class TreeAttention(nn.Module):
    def __init__(self, hidden_size, memory_bank_size):
        super(TreeAttention, self).__init__()
        self.memory_project = nn.Linear(memory_bank_size, hidden_size, bias=False)
        self.softmax = MaskedSoftmax(dim=1)
        # self.softmax = nn.Softmax(dim=1)

    def score(self, memory_bank_samples, decoder_state_sample):
        """
        :param memory_bank_samples: [batch_size (1), max_input_seq_len, self.num_directions * self.encoder_size]
        :param decoder_state_sample: [batch_size (1), hidden_size]
        :return: score: [batch_size, max_input_seq_len]
        """
        batch_size, cur_node_num, memory_bank_size = list(memory_bank_samples.size())
        # memory_bank_size = hidden_size
        decoder_size = decoder_state_sample.size(1)

        # project memory_bank
        memory_bank_ = memory_bank_samples.view(-1, memory_bank_size)
        # [batch_size * cur_node_num, memory_bank_size]
        encoder_features = self.memory_project(memory_bank_)  # [batch_size * cur_node_num, hidden_size]
        # expand decoder state
        decoder_state_expanded = decoder_state_sample.unsqueeze(1).expand(batch_size, cur_node_num,
                                                                          decoder_size).contiguous()
        decoder_state_expanded = decoder_state_expanded.view(-1, decoder_size)
        # [batch_size * cur_node_num, decoder_size]

        # Perform bi-linear operation
        scores = th.bmm(decoder_state_expanded.unsqueeze(1),  # [batch_size * cur_node_num, 1, decoder_size]
                           encoder_features.unsqueeze(2))  # [batch_size * cur_node_num, decoder_size, 1]
        # scores = [batch_size * cur_node_num, 1, 1]

        scores = scores.view(-1, cur_node_num)  # [batch_size (1), cur_node_num]
        return scores

    def forward(self, memory_bank, decoder_state, tree_node_num_lst, src_mask=None):
        """
        :param tree_node_num_lst: number of ast nodes for a data instance
        :param decoder_state: [batch_size, hidden_size]
        :param memory_bank: [total node num, self.num_directions * self.hidden_size]
        :param src_mask: [batch_size, max_input_seq_len]
        :return: context: [batch_size, self.num_directions * self.hidden_size],
                 attn_dist: [batch_size, max_input_seq_len], coverage: [batch_size, max_input_seq_len]
        """
        node_num_offset = 0
        context_feat = None
        for idx in range(len(tree_node_num_lst)):
            memory_bank_samples = memory_bank[node_num_offset: node_num_offset + tree_node_num_lst[idx]].unsqueeze(0)
            node_num_offset += tree_node_num_lst[idx]
            # memory_bank_samples = [batch_size (1), cur_node_num, self.hidden_size]
            decoder_state_sample = decoder_state[idx].unsqueeze(0)
            # decoder_state_sample = [1, self.hidden_size]

            # init dimension info
            batch_size, cur_node_num, memory_bank_size = list(memory_bank_samples.size())

            # if src_mask is None:  # if it does not supply a source mask, create a dummy mask with all ones
            #     src_mask = memory_bank_samples.new_ones(batch_size, cur_node_num)

            scores = self.score(memory_bank_samples, decoder_state_sample)
            attn_dist = self.softmax(scores, mask=src_mask)
            # attn_dist = [batch_size (1), cur_node_num]

            # Compute weighted sum of memory bank features
            attn_dist = attn_dist.unsqueeze(1)  # [batch_size (1), 1, cur_node_num]
            memory_bank_samples = memory_bank_samples.view(-1, cur_node_num, memory_bank_size)
            # memory_bank_samples = [batch_size (1), cur_node_num, memory_bank_size]
            context = th.bmm(attn_dist, memory_bank_samples)  # [batch_size (1), 1, memory_bank_size]
            context = context.squeeze(1)  # [batch_size (1), memory_bank_size]

            assert context.size() == th.Size([batch_size, memory_bank_size])

            if context_feat is None:
                context_feat = context
            else:
                context_feat = th.cat((context_feat, context), dim=0)

        assert node_num_offset == memory_bank.size(0), 'Memory bank is not consumed thoroughly'

        return context_feat  # context = [batch_size, memory_bank_size]


class MaskedSoftmax(nn.Module):
    def __init__(self, dim):
        super(MaskedSoftmax, self).__init__()
        self.dim = dim

    def forward(self, logit, mask=None):
        if mask is None:
            dist = F.softmax(logit - th.max(logit, dim=self.dim, keepdim=True)[0], dim=self.dim)

        else:
            dist_ = F.softmax(logit - th.max(logit, dim=self.dim, keepdim=True)[0], dim=self.dim) * mask
            normalization_factor = dist_.sum(self.dim, keepdim=True)
            dist = dist_ / normalization_factor
        return dist