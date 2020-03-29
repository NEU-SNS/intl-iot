import requests
import json

import os
import time
import _config
import _util
import pandas as pd
import traceback
#from geoip import geolite2
import pickle
import ipwhois

"""
output column: ip,org,country,asn,asn_country_code,asn_description
"""

cache = _config.cachepassport
file_result = _config.outfileippassport
file_missing = _config.outfileippassportmissing
omitted_ip = _config.router_ip
omitted_ip.extend(['0.0.0.0', '255.255.255.255'])
REQUEST_URL = 'https://passport.ccs.neu.edu/api/v1/locateip'
start_ts = time.time()
def main():
    all_ip = pd.read_csv(_config.infile)['ip'].drop_duplicates().dropna()
    print('Number of total IPs: %s' % len(all_ip))

    filtered = filter_ip(all_ip)
    print('Number of filtered IPs: %s' % len(filtered))
    t0 = time.time()
    manual_whois = _util.load_dict(_config.manualfile, sep=',')
    finished = send_tasks(filtered)
    t1 = time.time()
    print('Done after %d seconds' % (t1-t0))


def send_tasks(list_ip):
    finished_ip = dict()
    list_result = []
    list_missing = []

    # with open(file_result, 'w') as ff:
    no = 0
    for ip in list_ip:
        no += 1
        print('%d %s (%ss)' % (no, time.time(), time.time()-start_ts))
        res = query_passport(ip)
        if res is not None:
            finished_ip[ip] = res
            rs_json = json.loads(res)
            if rs_json['classifier'] is None or len(rs_json['classifier']) < 1:
                list_missing.append(ip)
                continue
            classifier = rs_json['classifier'][0]
            # ff.write('%s,%s\n' % (ip, classifier))
            res = '%s,%s' % (ip, classifier)
            list_result.append(res)
        else:
            list_missing.append(ip)
        # break
    print('Saved to %s (%d identified) ' % (file_result, len(finished_ip)))
    print('Saved to %s (%d missing) ' % (file_missing, len(list_missing)))
    open(file_missing, 'w').write('%s\n' % '\n'.join(list_missing))
    open(file_result, 'w').write('%s\n' % '\n'.join(list_result))
    return finished_ip


def query_passport(ip):
    cf = '%s/pspt_%s.p' % (cache, ip)
    if os.path.exists(cf):
        return open(cf).read()

    print('Querying %s' % ip)
    data_ip = {"ip": ip}
    data_json = json.dumps(data_ip)
    r = requests.post(REQUEST_URL, data=data_json)
    result_text = r.text
    finished = False
    if result_text is not None:
        try:
            rs_json = json.loads(result_text)
            if rs_json['status'] == 'finished':
                finished = True
                print('\tFinished')
                open(cf, 'w').write(result_text)
        except:
            print(result_text)
            traceback.print_exc()
            return
    st = 1
    print('\tsleep for %ds...' % st)
    time.sleep(st)
    if finished:
        return result_text

def filter_ip(all_ip):
    filtered_ip = []
    for i in all_ip:
        if ':' in i:
            # TODO: about 1000 ipv6 ADDRESSES
            continue
        if i in omitted_ip:
            continue
        if i.startswith('192.168.') or i.startswith('17.16') or i.startswith('10.'):
            continue
        """
        mutlicast 224.0.0.0 - 239.255.255.255
        """
        if i.startswith('224.'):
            continue
        """
        Link local address: https://en.wikipedia.org/wiki/Link-local_address
        69.254.0.0/16
        """
        if i.startswith('169.254'):
            continue
        filtered_ip.append(i)
    return filtered_ip

if __name__ == '__main__':
    main()
