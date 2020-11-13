import time
import numpy as np

import torch as th

from dgl_treelstm.util import extract_root
import torch.nn.functional as F

class Trainer(object):
    def __init__(self, args, model, criterion, optimizer, device, metric, metric_name):
        super(Trainer, self).__init__()
        self.args = args
        self.model = model
        self.criterion = criterion
        self.optimizer = optimizer
        self.device = device
        self.epoch = 0
        self.metric = metric
        self.metric_name = metric_name

    # helper function for training
    def train(self, train_loader):
        self.model.train()
        total_loss = 0
        total_result = 0
        dur = []
        for step, batch in enumerate(train_loader):
            g = batch.graph
            n = g.number_of_nodes()
            h = th.zeros((n, self.args.h_size)).to(self.device)
            c = th.zeros((n, self.args.h_size)).to(self.device)
            if step >= 3:
                t0 = time.time()  # tik
            logits = self.model(batch, h, c)
            batch_label, logits = extract_root(batch, self.device, logits)
            if self.args.regression:
                logits = logits.reshape(-1)
                loss = self.criterion(logits, batch_label)
                total_loss += loss * g.batch_size
                pred = logits
            else:
                loss = self.criterion(logits, batch_label)
                total_loss += loss
                pred = th.argmax(F.log_softmax(logits), 1)
            self.optimizer.zero_grad()
            loss.backward()
            self.optimizer.step()

            if step >= 3:
                dur.append(time.time() - t0)  # tok

            metric_result = self.metric(pred, batch_label)
            total_result += metric_result

            if step > 0 and step % self.args.log_every == 0:
                # if self.epoch % 10 == 9:
                #     print(th.transpose(th.cat((pred, batch_label)).reshape(2,-1), 0, 1))
                print("Epoch {:05d} | Step {:05d} | Loss {:.4f} | {:s} {:.4f} | Time(s) {:.4f}".format(
                    self.epoch, step, loss.item(), self.metric_name, metric_result / g.batch_size, np.mean(dur)))
        self.epoch += 1
        return total_result, total_loss

    # helper function for testing
    def test(self, test_loader):
        # eval on dev set
        total_result = 0
        total_loss = 0
        self.model.eval()
        for step, batch in enumerate(test_loader):
            g = batch.graph
            n = g.number_of_nodes()
            with th.no_grad():
                h = th.zeros((n, self.args.h_size)).to(self.device)
                c = th.zeros((n, self.args.h_size)).to(self.device)
                logits = self.model(batch, h, c)
            batch_label, logits = extract_root(batch, self.device, logits)
            if self.args.regression:
                logits = logits.reshape(-1)
                loss = self.criterion(logits, batch_label)
                total_loss += loss * g.batch_size
                pred = logits
            else:
                loss = self.criterion(logits, batch_label)
                total_loss += loss
                pred = th.argmax(F.log_softmax(logits), 1)
            metric_result = self.metric(pred, batch_label)
            total_result += metric_result
            # if self.epoch % 10 == 0 and step == 0:
            #     print(th.transpose(th.cat((pred, batch_label)).reshape(2,-1), 0, 1))

        return total_result, total_loss
