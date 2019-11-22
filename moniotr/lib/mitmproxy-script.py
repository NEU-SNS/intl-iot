#!/usr/bin/python3
#
# Date: 2016-07-04
# @author: JJ
#
# Function: on the fly generating http and https logs
# support mitmproxy version 4.x
from __future__ import (absolute_import, print_function, division)
import sys
import os
import urllib
import random, string
import collections
from enum import Enum
from datetime import datetime
from mitmproxy import ctx

enable_http = True
http_log_name = "http.log"
traffic_path = "/opt/moniotr/traffic/by-ip"
network_name = "unctrl"
mitm_exception = "/opt/moniotr/mitm-exception"

def load(l):
    l.add_option("http_log_name", str, http_log_name, "Name for HTTP log file")
    l.add_option("traffic_path", str, traffic_path, "Traffic path")
    l.add_option("network_name", str, network_name, "Network name")
    l.add_option("mitm_exception", str, mitm_exception, "Script for managing MITM exceptions")

def running():
    global enable_http
    global http_log_name
    global traffic_path
    global network_name
    enable_http = True
    http_log_name = ctx.options.http_log_name
    traffic_path = ctx.options.traffic_path
    network_name = ctx.options.network_name

def response(flow):
    f = flow

    if not enable_http and not f.client_conn.tls_established:
        # skip saving http request
        return
    try:
        ts = f.request.timestamp_start
        id_orig_h = f.client_conn.address[0]
        id_orig_p = f.client_conn.address[1]
        # Workaround for IPv4-compatible IPv6 addresses
        if id_orig_h[:7] == '::ffff:':
            id_orig_h = id_orig_h[7:]
        id_resp_h = f.request.host
        id_resp_p = f.request.port
        uid_seed = '%s%s%s%s%s' %(ts, id_orig_h, id_orig_p, id_resp_h, id_resp_p)
        bro_uid = '{0}'.format(''.join(random.choice(string.ascii_uppercase + string.ascii_lowercase + string.digits) for _ in range(17)))

        if f.client_conn.tls_established:
            bro_uid = 'S' + bro_uid
        else:
            bro_uid = 'C' + bro_uid

        # DONE: generate a unique id, 18-bit
        trans_depth = '-'
        method = f.request.method
        host = f.request.host
        if 'host' in f.request.headers:
            host = f.request.headers['host']
        uri = f.request.path
        referrer = '-'
        if 'referrer' in f.request.headers:
            referrer = f.request.headers['referrer']
            # DONE: TEST IF THIS FEILD IS CORRECT, YES!
        user_agent = '-'
        if 'User-Agent' in f.request.headers:
            user_agent = f.request.headers['User-Agent']
        request_body_len = 0  # TODO: HOW TO GET THIS VALUE?
        response_body_len = 0  # TODO: HOW TO GET THIS VALUE?
        status_code = f.response.status_code
        status_msg = f.response.reason
        info_code = '-'
        info_msg = '-'
        filename = '-'
        tags = '(empty)'
        username = '-'
        password = '-'
        proxied = '-'
        orig_fuids = '-'  #
        orig_mime_types = '-'  # TODO: figure out the corresponding field
        resp_fuids  = '-'
        resp_mime_types = '-'

        content_length = 0
        content_encoding = '-'
        content_type = '-'
        if 'content-type' in f.request.headers:
            content_type = f.request.headers['content-type']
        transfer_encoding = '-'
        post_body = '-'
        ctx.log.info(post_body)
        if f.request.content is not None:
            # make sure the content are in the same line, WHEN DECODING, replace /n with \n
            try:
                post_body = urllib.quote(str(f.request.content))
            except:
                pass

        client_header_names = ''
        client_header_values = ''
        for h_name in f.request.headers:
            client_header_names += str(h_name) + ','
            client_header_values += str(f.request.headers[h_name]) + ','

        client_header_values = client_header_values.strip(',')
        client_header_names = client_header_names.strip(',')
        server_header_names = ''
        server_header_values = ''

        for h_name in f.response.headers:
            server_header_names += str(h_name) + ','
            server_header_values += str(f.response.headers[h_name]) + ','
        server_header_names = server_header_names.strip(',')
        server_header_values = server_header_values.strip(',')

        http_entry = ''
        http_entry += '%.6f\t%s\t%s\t%s\t%s\t%s\t' % (ts, bro_uid, id_orig_h, id_orig_p, id_resp_h, id_resp_p)
        http_entry += '%s\t%s\t%s\t%s\t%s\t%s\t' % (trans_depth, method, host, uri, referrer, user_agent)
        http_entry += '%s\t%s\t%s\t%s\t%s\t%s\t' % (request_body_len, response_body_len, status_code, status_msg, info_code, info_msg)
        http_entry += '%s\t%s\t%s\t%s\t%s\t%s\t' % (filename, tags, username, password, proxied, orig_fuids)
        http_entry += '%s\t%s\t%s\t%s\t%s\t%s\t' % (orig_mime_types, resp_fuids, resp_mime_types, content_length, content_encoding, content_type)
        http_entry += '%s\t%s\t%s\t%s\t%s\t%s\n' % (transfer_encoding, post_body, client_header_names, client_header_values, server_header_names, server_header_values)

        http_log_name_traffic_path = traffic_path + '/' + id_orig_h + '/' + network_name + '/http-'
        https_log_name_traffic_path = traffic_path + '/' + id_orig_h + '/' + network_name + '/https-'
        http_log_name_traffic_path += "{:%Y-%m-%d}".format(datetime.now()) + '.log'
        https_log_name_traffic_path += "{:%Y-%m-%d}".format(datetime.now()) + '.log'

        with open(http_log_name, 'a') as hf:
            hf.write(http_entry)

        if f.client_conn.tls_established:
            with open(https_log_name_traffic_path, 'a') as hf:
                hf.write(http_entry)
        else:
            with open(http_log_name_traffic_path, 'a') as hf:
                hf.write(http_entry)


        ctx.log.info('Flow written.')
    except Exception as e:
        ctx.log.info("Something wrong happened while saving flow.")
        ctx.log.info(str(e))


def responseheaders(flow):
    """
    Enables streaming for all responses.
    """
    flow.response.stream = True
