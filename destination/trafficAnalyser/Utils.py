import os, sys, psutil, datetime

debug = False 

def sysUsage(info = "Usage"):
  cpuPerc = psutil.cpu_percent()
  # you can convert that object to a dictionary 
  mem = dict(psutil.virtual_memory()._asdict())

  if debug:
    print ("{}: Time: {} CPU: {} Mem: {}".format(info, datetime.datetime.now(), cpuPerc, mem))
