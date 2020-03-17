import geoip2.database
import socket, datetime
import urllib.request, json
import mysql.connector
import sys, operator, subprocess
import tldextract
import whois
import pandas as pd

class IPResolver(object):
    def __init__(self, ipMapping):
        self.ipCity = geoip2.database.Reader('./geoipdb/GeoLite2-City.mmdb')
        self.ipCountry = geoip2.database.Reader('./geoipdb/GeoLite2-Country.mmdb')
        self.ipMap = ipMapping
        #self.ripeProbe = RipeProbe() #RipeCountry argument to the -l option, commented out because SQL database missing

    def getCountryAndCity(self, ip):
        try:
            resp = self.ipCity.city(ip)
            return resp.country.iso_code, resp.subdivisions.most_specific.name, resp.city.name
        except geoip2.errors.AddressNotFoundError:
            return "N/A", "", ""
      
    def getHostByAddr(self, ip):
        try: 
            hostName, aliasList, ipAddrList = socket.gethostbyaddr(ip)
            hostName = self.extractDomain(hostName)
            return hostName, aliasList, ipAddrList
        except:
            return "N/A", [], []

    def getWhois(self, ip):
        w = whois.whois(ip)
        if isinstance(w.domain_name, (list,)):
            return w.domain_name[0].lower()
    
        if w.domain_name != "" and w.domain_name is not None:
            return w.domain_name.lower()
    
        if w.emails != "" and w.emails is not None:
            if isinstance(w.emails, (list,)):
                for email in reversed(w.emails):
                    ext = tldextract.extract(email)
                    if ext.domain.lower() != "apnic":
                        break
            else:
                ext = tldextract.extract(w.emails)

            return "{}.{}".format(ext.domain.lower(), ext.suffix.lower())

        return "N/A"

    def extractDomain(self, hostName):
        if hostName == "N/A":
            return hostName
        elif self.isIPAddr(hostName):
            return hostName

        ext = tldextract.extract(hostName)
        return "{}.{}".format(ext.domain, ext.suffix)

    def splitIPBy(self, ipDict, method, data = {}):
        for ip, val in ipDict.items():
            if not self.isIPAddr(ip):
                continue
      
            dataPoint = self.getDataPoint(ip, method)

            if dataPoint in data:
                data[dataPoint] += val
            else:
                data[dataPoint] = val

        return data

    def getDataPoint(self, ip, method, extractDomain = True, defaultToIP = True):
        if method == "IP":
            dataPoint = ip
        elif self.isLocalAddr(ip):
            dataPoint = ip
        elif self.isMulticastAddr(ip):
            dataPoint = ip
        elif method == "Country":
            dataPoint, _, _ = self.getCountryAndCity(ip)
            #print (ip, dataPoint)
        elif method == "Host":
            dataPoint, _, _ = self.getHostByAddr(ip)
        elif method == "TSharkHost":
            dataPoint = self.ipMap.getHost(ip)[0]
            if dataPoint == "N/A":
                dataPoint, _, _ = self.getHostByAddr(ip)
                if dataPoint == "N/A" or self.isIPAddr(dataPoint):
                    dataPoint = self.getWhois(ip)
        elif method == "RipeCountry":
            dataPoint = self.ripeProbe.getIPLocation(ip, 'countryCodeAlpha2')
            if dataPoint == "N/A":
                dataPoint, _, _ = self.getCountryAndCity(ip)
        elif method == "CountryMapping":
            dataPoint = self.ipMap.getCountry(ip)
            if dataPoint == "N/A":
                dataPoint, _, _ = self.getCountryAndCity(ip)
        elif method == "OrgMapping":
            dataPoint = self.ipMap.getOrg(ip)
        else:
            raise UndefinedMethodError('Undefined Method Error')
    
        if method.endswith("Host") and extractDomain:
            dataPoint = self.extractDomain(dataPoint)

        if not method.endswith("Mapping") and dataPoint == "N/A" and defaultToIP:
            dataPoint = ip

        return dataPoint

    def isIPAddr(self, ip):
        try: 
            socket.inet_aton(ip)
            return True
        except:
            return False

    def isLocalAddr(self, ip):
        if ip.startswith("10.") or ip.startswith("192.168."):
            return True
        return False

    def isMulticastAddr(self, ip):
        if ip.startswith("224.") or ip.startswith("255.") or ip.startswith("239."):
            return True
        return False

class RipeProbe(object):
    def __init__(self):
        self.cnx = mysql.connector.connect(user='meddle', password='meddle',
            host='127.0.0.1', database='MeddleDB')
        self.cursor = self.cnx.cursor(dictionary=True)
        self.url = "https://openipmap.ripe.net/api/v1/locate/{}/"

    def getIPLocation(self, ip, locType):
        loc = self.loadIP(ip, 1)
        if len(loc) == 0:
            loc = self.loadIP(ip, 0)
      
            if len(loc) == 0:
                loc = self.probe(ip)
                #print ("Probing, len loc: ", len(loc['locations']))

                if 'locations' in loc:
                    self.saveIPLocations(ip, loc['locations'])
                    self.chooseLocationForIP(ip)

        else:
            return loc[0][locType]

        return 'N/A'

    def loadIP(self, ip, chosen):
        query = "SELECT * FROM IPLocation WHERE ip = %s AND chosen = %s"
        try: 
            self.cursor.execute(query, (str(ip), chosen))
        except mysql.connector.errors.ProgrammingError as err:
            print(self.cursor.statement)
            print("Error: {}".format(err))
    
        try: 
            rows = self.cursor.fetchall()
        except mysql.connector.errors.InterfaceError as err:
            return []

        return rows

    def probe(self, ip):
        try:
            response = urllib.request.urlopen(self.url.format(ip), timeout=20)
            res = response.read()
            jRes = json.loads(res)
      
            return jRes
        except Exception as e:
            print ('RIPE Request fail...', e, self.url.format(ip))
            return {}

    def saveIPLocations(self, ip, locs):
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        for loc in locs:
            loc['ip'] = str(ip)
            loc['probedAt'] = timestamp
            loc['locationId'] = loc.pop('id')
            try:
                if loc['stateName'] == None:
                    loc['stateName'] = ""
            except KeyError:
                loc['stateNme'] = ""
            self.saveIPLocation(loc)

        self.cnx.commit()

    def saveIPLocation(self, loc):
        placeholders = ', '.join(["%s"] * len(loc))
        fields = ", ".join(list(loc.keys()))
        query = "INSERT INTO IPLocation ({}) VALUES({})".format(fields, placeholders)
        try: 
            self.cursor.execute(query, list(loc.values()))
        except  (mysql.connector.errors.ProgrammingError, mysql.connector.errors.IntegrityError) as err:
            print(self.cursor.statement)
            print("Error: {}".format(err))
            print(query, list(loc.values()))
            #sys.exit()

    def chooseLocationForIP(self, ip):
        query = "SELECT * FROM IPLocation WHERE ip = %s ORDER BY score DESC"
        chosenId = 0
    
        try: 
            self.cursor.execute(query, [str(ip)])
        except mysql.connector.errors.ProgrammingError as err:
            print(self.cursor.statement)
            print("Error: {}".format(err))
    
        try:
            rows = self.cursor.fetchall()
        except mysql.connector.errors.InterfaceError as err:
            # if there are no locations, return
            return
    
        # if there is at least 90% confidence, choose the location
        try:
            if rows[0]['score'] >= 90:
                self.selectChosenLocation(rows[0]['id'])
                return
        except IndexError:
            return 
    
        # if there are not enough records, try again later
        if len(rows) < 20:
            return

        # lets choose the country using weighted average and choose the location
        # with highest score from given country
        countries = {}
        for loc in rows:
            if loc['countryCodeAlpha2'] in countries:
                countries[loc['countryCodeAlpha2']] += loc['score']
            else:
                countries[loc['countryCodeAlpha2']] = loc['score']

        country = max(countries.items(), key=operator.itemgetter(1))[0]
    
        for loc in rows:
            if loc['countryCodeAlpha2'] == country:
                self.selectChosenLocation(loc['id'])
                return 

    def selectChosenLocation(self, locationId):
        query = "UPDATE IPLocation set chosen = 1 WHERE id = %s"
        self.cursor.execute(query, [locationId])
        self.cnx.commit()

class IPMapping(object):
    def __init__(self):
        self.host = {}
        self.ip = {}

    def extractFromFile(self, fileName):
        if fileName.endswith(".pcap"):
            p1 = subprocess.Popen(["tshark", "-r", fileName, "-q", "-z", "hosts"], stdout=subprocess.PIPE)
            p2 = subprocess.Popen(["awk", "NF && $1!~/^#/"], stdin=p1.stdout, stdout=subprocess.PIPE,
                universal_newlines=True)
            hosts = str(p2.communicate()[0][0:-1]).split("\n")
        else:
            with open(fileName) as f:
                hosts = f.readlines()

        #print(str(hosts))
        #for hostLine in str(hosts).split("\n"):
        for hostLine in hosts:
            try:
                ip, host = hostLine.split("\t")
                self.addHostIP(host.strip(), ip)
            except:
                print("Error: No hosts found in PCAP file")

    def addHostIP(self, host, ip):
        if ip not in self.ip:
            self.ip[ip] = []
        self.ip[ip].append(host)

        if host not in self.host:
            self.host[host] = []
        self.host[host].append(ip)

    def getHost(self, ip):
        if ip in self.ip:
            return self.ip[ip]
        return ["N/A"]

    def getIP(self, host):
        if host in self.host:
            return self.host[host]
        return ["N/A"]

    def loadOrgMapping(self, fileName):
        self.orgMapping = pd.read_csv(fileName)

    def loadCountryMapping(self, fileName):
        self.countryMapping = pd.read_csv(fileName)

    def getOrg(self, ip, column = "org"):
        org = self.orgMapping[self.orgMapping['ip'] == ip]
        if org.empty:
            return "N/A"
        return org.iloc[0][column]

    def getCountry(self, ip):
        country = self.countryMapping[self.countryMapping['ip'] == ip]

        if country.empty:
            country = self.getOrg(ip, 'country')
            if country != "None":
                return country
            return "N/A"

        return country.iloc[0]['country']

class UndefinedMethodError(Exception):
    pass
