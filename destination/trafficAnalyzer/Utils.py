import datetime
import psutil

debug = False 

def sysUsage(info="Usage"):
    cpu_perc = psutil.cpu_percent()
    # you can convert that object to a dictionary 
    mem = dict(psutil.virtual_memory()._asdict())

    if debug:
        print("{}: Time: {} CPU: {} Mem: {}".format(info, datetime.datetime.now(), cpu_perc, mem))

