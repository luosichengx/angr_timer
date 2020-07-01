import random

class query_data:
    def __init__(self):
        # total solving time
        self.sol_time = 0
        # selected query list
        self.query_list = []
        # query list length
        self.list_num = 100
        # reduce writing output times
        self.time_list = []
        # query more than limits and before it
        self.timeout_list = []
        self.query_before_timeout = []
        self.mid_time_list = []
        self.last_query = None
        self.query_index = 1
        self.time_limit = 300
        self.time_output_addr = "/home/lsc/data/time/solver_time.log"

    def update(self, query, time_delta):
        # record time of query
        try:
            if len(self.time_list) < 100:
                self.time_list.append(str(time_delta) + "\n")
            else:
                with open(self.time_output_addr, "a") as f:
                    for time_data in self.time_list:
                        f.write(time_data)
                self.time_list = [str(time_delta) + "\n"]
        except:
            pass

        output = query + "time: " + str(time_delta) + "\n"
        try:
            # record query
            if time_delta > self.time_limit:
                self.timeout_list.append(output)
                self.query_before_timeout.append(self.last_query)
                # with open("/home/lsc/data/query/claripy.log", "a") as f:
                #     f.write(query_smt2)
                #     f.write("time: " + str(time_delta) + "\n\n")
            else:
                if time_delta > 10:
                    self.mid_time_list.append(output)
                if len(self.query_list) < self.list_num:
                    self.query_list.append(output)
                else:
                    pro = self.list_num / self.query_index
                    ran = random.random()
                    if ran < pro:
                        ran = random.randrange(0,self.list_num)
                        self.query_list[ran] = output
        except:
            pass
        if time_delta <= self.time_limit:
            self.last_query = output
        self.sol_time += time_delta
        self.query_index += 1
