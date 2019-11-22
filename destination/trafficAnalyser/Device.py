class Device(object):

  def __init__(self, mac, name):
    self.mac = Device.normaliseMac(mac)
    self.name = name

  @staticmethod
  def normaliseMac(mac):
    return ":".join([n.zfill(2) for n in mac.split(":")])

class Devices(object):

  def __init__(self, fileName):
    self.devices = {}
    self.fileName = fileName
    self.loadDevices()

  def loadDevices(self):
    with open(self.fileName) as f:
      lines = f.readlines()

    for line in lines:
      mac, name = line.strip().split()
      mac = Device.normaliseMac(mac)
      self.devices[mac] = Device(mac, name)
      
  def getDeviceName(self, mac):
    if mac in self.devices:
      return self.devices[mac].name
    return None

  def getDeviceMac(self, deviceName):
    return [mac for mac, device in self.devices.items() if device.name == deviceName][0]
