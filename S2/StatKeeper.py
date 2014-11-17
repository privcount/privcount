
import time

class custom_protocol:
    def __init__(self, enter, exit):
        self.enter = enter
        self.exit = exit

    def __enter__(self):
        return self.enter(self)

    def __exit__(self, *a):
        return self.exit(*a)


class StatKeeper:
    def __init__(self):
        self.log = {}
        self.starts = {}
        self.order = []

        ## Self test
        for x in range(10000):
            with(self["overhead"]):
                pass

    def __getitem__(self, key):
        def myenter(x):
            self.start(key)
            return None

        def myexit(*a):
            return self.end(key)

        return custom_protocol(myenter, myexit)

    def start(self, action):
        assert action not in self.starts
        self.starts[action] = time.clock()

    def end(self, action):
        assert action in self.starts
        Dt = time.clock() - self.starts[action]
        if action not in self.log:
            self.order += [action]
        count, period = self.log.get(action, (0, 0.0))
        count += 1
        period += Dt
        self.log[action] = (count, period)
        del self.starts[action]

    def get_stats(self):
        assert len(self.starts) == 0
        return self.log

    def print_stats(self):
        ovcnt, ovtime = self.log["overhead"]
        overhead = 1000 * ovtime / ovcnt
        print "Statistics: Counts and Timings"
        print " "*20 + "\tCounter \tTotal   \tAverage"
        for k in self.order:
            cnt, tot = self.log[k]
            xtot = max(1000*tot - cnt*overhead, 0.0)
            xave = max(1000*tot/cnt - overhead, 0.0)
            print "%20s\t%8d\t%8.6f\t%8.6f" % (k, cnt, xtot, xave)
        print "\t\t\t\t\t\t(All times in miliseconds)"
