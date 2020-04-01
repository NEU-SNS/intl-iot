import sys

from trafficAnalyser import IP

if __name__ == "__main__":
    with open(sys.argv[1]) as f:
        lines = f.readlines()

    ripe = IP.RipeProbe()

    for line in lines:
        ip, _ = line.split()
        country = ripe.getIPLocation(ip.strip(), 'countryCodeAlpha2')

        print(ip, country)
