import os
import torch

op = ["forall","exists","and","or","not","distinct","implies","iff","symbol","function","real_constant",
      "bool_constant","int_constant","str_constant","plus","minus","times","le","lt","equals",
      "ite","toreal","bv_constant","bvnot","bvand","bvor","bvxor","concat","extract","rotation",
      "extend","zero_extend","sign_extend","bvult","bvule","bvuge","bvugt","bvneg","bvadd","bvsub","bvmul","bvudiv",
      "bvurem","bvlshl","bvlshr","bvrol","bvror","bvzext","bvsext","bvslt","bvsle","bvcomp","bvsdiv",
      "bvsrem","bvashr","str_length","str_concat","str_contains","str_indexof","str_replace","str_substr",
      "str_prefixof","str_suffixof","str_to_int","int_to_str","str_charat","select","store","value",
      "div","pow","algebraic_constant","bvtonatural","_to_fp","=","bvsge","compressed_op","unknown"]

# op = ["not","bvadd","bvule","extract","ite","and","or","distinct","bvmul","concat","bvashr",
#       "bvuge","bvugt","bvnot","bvor","bvsle","bvsub","bvsgt","zero_extend","bvshl","bvsge","bvlshr","sign_extend",
#       "bvurem","bvudiv","bvxor","bvand"]

si_op = ["extract","zero_extend","sign_extend","_to_fp"]

tri_op = ["ite"]

bv_constant = "constant"
bool_constant = "constant"


class Tree:
    def __init__(self, val, left= None, mid= None, right= None):
        if isinstance(val, torch.Tensor):
            pass
        elif isinstance(val, str):
            if val in op:
                pass
            elif val == "constant":
                self.name = "constant"
            elif val.startswith("var"):
                self.name = "var"
            else:
                self.name = "mid_val"
        elif val != None:
            raise ValueError
        self.val = val
        for child in [left, mid, right]:
            if child and not isinstance(child,Tree):
                raise ValueError
        self.left = left
        self.mid = mid
        self.right = right
        self.name = None

    def set_name(self, name):
        self.name = name

    def __str__(self):
        left_val = ""
        if self.left and self.left.name:
            left_val = self.left.name
        mid_val = ""
        if self.mid and self.mid.name:
            mid_val = self.mid.name
        right_val = ""
        if self.right and self.right.name:
            right_val = self.right.name
        name = ""
        if self.name:
            name = self.name
        if self.val == "concat":
            mid_val = "mid_val"
        return (' '.join([name,"(",self.val, left_val, mid_val, right_val, ")"]))

class varTree(Tree):
    def __init__(self, val, left= None, mid= None, right= None):
        super(varTree,self).__init__(val, left, mid, right)
        self.var = set()
        self.depth = 0
        self.compress_depth = 0
        self.node = 1
        if val.startswith("var"):
            self.var.add(val)

    def cal(self):
        for child in [self.left, self.mid, self.right]:
            if child:
                self.update(child)
        if self.val == "concat":
            self.reduce_concat()
            self.compress_depth -= 1

    def update(self, child):
        self.depth = max(self.depth, child.depth + 1)
        self.compress_depth = max(self.compress_depth, child.compress_depth + 1)
        self.node = self.node + child.node
        self.var.update(child.var)


    def reduce_concat(self):
        if not self.left:
            raise ValueError
        if not self.mid:
            raise ValueError
        if self.right:
            raise ValueError
        var = set()
        var.update(self.left.var)
        var.update(self.mid.var)
        if self.left.var == var and self.left.depth >= self.mid.depth:
            self.replace_children(self.mid)
        elif self.mid.var == var and self.left.depth <= self.mid.depth:
            self.replace_children(self.left)
        elif self.left.depth > self.mid.depth:
            self.replace_children(self.left)
        else:
            self.replace_children(self.mid)

    # def reduce_ite(self):
    #     if not self.left:
    #         return
    #     if not self.mid:
    #         return
    #     if not self.right:
    #         return
    #     var = set()
    #     depth = 0
    #     for children in [self.left, self.mid, self.right]:
    #         var.update(children.var)
    #         depth = max(depth, children.depth)
    #     for children in [self.left, self.mid, self.right]:
    #         if var == children.var and depth == children.depth:
    #             self.replace_children(children)
    #             return
    #     for children in [self.left, self.mid, self.right]:
    #         if depth == children.depth:
    #             self.replace_children(children)

    def replace_children(self, tree):
        left, mid, right = tree.left, tree.mid, tree.right
        self.left, self.mid, self.right = left, mid, right

    def __str__(self):
        n = super(varTree, self).__str__()
        return " ".join([n, "depth:", str(self.depth), "compress_depth:" , str(self.compress_depth)])
