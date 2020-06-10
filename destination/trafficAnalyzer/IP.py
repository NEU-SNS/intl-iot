import datetime
import json
import operator
import os
import socket
import subprocess
import urllib.request

import geoip2.database
import mysql.connector
import pandas as pd
import tldextract
import whois


class IPResolver(object):
    def __init__(self, ipMapping, geoDbCity, geoDbCountry):
        self.ipCity = geoip2.database.Reader(geoDbCity)
        self.ipCountry = geoip2.database.Reader(geoDbCountry)
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
            host_name, alias_list, ip_addr_list = socket.gethostbyaddr(ip)
            host_name = self.extractDomain(host_name)
            return host_name, alias_list, ip_addr_list
        except:
            return "N/A", [], []

    def getWhois(self, ip):
        w = whois.whois(ip)
        if isinstance(w.domain_name, (list,)):
            return w.domain_name[0].lower()
    
        if w.domain_name != "" and w.domain_name is not None:
            return w.domain_name.lower()
    
        if w.emails != "" and w.emails is not None:
            ext = ""
            if isinstance(w.emails, (list,)):
                for email in reversed(w.emails):
                    ext = tldextract.extract(email)
                    if ext.domain.lower() != "apnic":
                        break
            else:
                ext = tldextract.extract(w.emails)

            return "{}.{}".format(ext.domain.lower(), ext.suffix.lower())

        return "N/A"

    def extractDomain(self, host_name):
        if host_name == "N/A":
            return host_name
        elif self.isIPAddr(host_name):
            return host_name

        ext = tldextract.extract(host_name)
        return "{}.{}".format(ext.domain, ext.suffix)

    def splitIPBy(self, ip_dict, method, data=None):
        if data is None:
            data = {}

        for ip, val in ip_dict.items():
            if not self.isIPAddr(ip):
                continue
      
            data_point = self.getDataPoint(ip, method)

            if data_point in data:
                data[data_point] += val
            else:
                data[data_point] = val

        return data

    def getDataPoint(self, ip, method, extract_domain=True, default_to_ip=True):
        method = method.lower()
        if method == "ip":
            data_point = ip
        elif self.isLocalAddr(ip):
            data_point = ip
        elif self.isMulticastAddr(ip):
            data_point = ip
        elif method == "country":
            data_point, _, _ = self.getCountryAndCity(ip)
            #print (ip, data_point)
        elif method == "host":
            data_point, _, _ = self.getHostByAddr(ip)
        elif method == "tsharkhost":
            data_point = self.ipMap.getHost(ip)[0]
            if data_point == "N/A":
                data_point, _, _ = self.getHostByAddr(ip)
                if data_point == "N/A" or self.isIPAddr(data_point):
                    data_point = self.getWhois(ip)
        elif method == "ripecountry":
            data_point = self.ripeProbe.getIPLocation(ip, 'countryCodeAlpha2')
            if data_point == "N/A":
                data_point, _, _ = self.getCountryAndCity(ip)
        elif method == "countrymapping":
            data_point = self.ipMap.getCountry(ip)
            if data_point == "N/A":
                data_point, _, _ = self.getCountryAndCity(ip)
        elif method == "orgmapping":
            data_point = self.ipMap.getOrg(ip)
        else:
            print("No method %s" % method)
            raise UndefinedMethodError('Undefined Method Error')
    
        if method.endswith("host") and extract_domain:
            data_point = self.extractDomain(data_point)

        if not method.endswith("mapping") and data_point == "N/A" and default_to_ip:
            data_point = ip

        return data_point

    def isIPAddr(self, ip):
        try: 
            socket.inet_aton(ip)
            return True
        except OSError:
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

    def getIPLocation(self, ip, loc_type):
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
            return loc[0][loc_type]

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
        except mysql.connector.errors.InterfaceError:
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
                if loc['stateName'] is None:
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
        except(mysql.connector.errors.ProgrammingError, mysql.connector.errors.IntegrityError) as err:
            print(self.cursor.statement)
            print("Error: {}".format(err))
            print(query, list(loc.values()))
            #sys.exit()

    def chooseLocationForIP(self, ip):
        query = "SELECT * FROM IPLocation WHERE ip = %s ORDER BY score DESC"
    
        try: 
            self.cursor.execute(query, [str(ip)])
        except mysql.connector.errors.ProgrammingError as err:
            print(self.cursor.statement)
            print("Error: {}".format(err))
    
        try:
            rows = self.cursor.fetchall()
        except mysql.connector.errors.InterfaceError:
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

    #tshark -z option seems to return a CNAME but the A Record is wanted
    #However, the A Record is in the details of running "tshark -r [pcap_file]"
    #This method searches for the line containing the host name and checks
    #accuracy by making sure that the ip is also in that line
    def get_a_record(self, details, host, ip):
        for line in details.splitlines(): #loop through lines in detailed tshark output
            if host in line and ip in line:
                words = line.split()
                for idx, word in enumerate(words): #loop through words in line
                    if word == "A":
                        return words[idx + 1]

        return None

    def extractFromFile(self, file_name):
        details = ""
        if file_name.endswith(".pcap"):
            p1 = subprocess.Popen(["tshark", "-r", file_name, "-q", "-z", "hosts"],
                                  stdout=subprocess.PIPE)
            p2 = subprocess.Popen(["awk", "NF && $1!~/^#/"], stdin=p1.stdout, stdout=subprocess.PIPE,
                                  universal_newlines=True)
            hosts = str(p2.communicate()[0][0:-1]).split("\n")

            #run "tshark -r [pcap_file]" - gets the details which contain A Record
            details = str(os.popen("tshark -r %s" % file_name).read())
        else:
            with open(file_name) as f:
                hosts = f.readlines()

        for hostLine in hosts:
            try:
                ip, host = hostLine.split("\t")
                #Get the A Record host name
                if file_name.endswith(".pcap"):
                    tmp_host = self.get_a_record(details, host, ip)
                    if tmp_host is not None:
                        host = tmp_host

                self.addHostIP(host.strip(), ip)
            except ValueError:
                print("  Error: No hosts found in %s" % file_name)

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

    def loadOrgMapping(self, file_name):
        self.orgMapping = pd.read_csv(file_name)

    def loadCountryMapping(self, file_name):
        self.countryMapping = pd.read_csv(file_name)

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

