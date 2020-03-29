"""
Created by JJ
Created at 2/11/2019

CSVFILE: ip_src,ip_dst,srcport,dstport,tp_proto,data_proto,data_type,data_len,entropy,reason
"""
import json
import os
import sys
import pprint
import math
import pandas as pd
import traceback


SUFIX_RAW = '_raw'
LAYER_TCP = 'tcp'
LAYER_UDP = 'udp'
LAYER_TP_OTHER = 'tp-other'

LAYER_HTTP = 'http'
LAYER_SSL = 'ssl'
LAYER_DNS = 'dns'
LAYER_NTP = 'ntp'

K_LAYER = 'layers'
DT_UNKNOWN = 'unknown'
DT_TEXT = 'text'
DT_MEDIA = 'media'
DT_COMPRESSED = 'compressed'
DT_ENCRYPTED = 'encrypted'
DT_OMIT = 'omit'

result_header = 'ip_src,ip_dst,srcport,dstport,tp_proto,data_proto,data_type,data_len,entropy,reason'
list_possible_data_layers = ['http', 'dns', 'ntp', 'bootp', 'ssl', 'rtp',
                             'mqtt', 'rtc', 'rtsp', 'bootp', 'dtls', 'mdns',
                             'thrift', 'ssdp', 'stun']
list_media_proto = ['media', 'image', 'mp4', 'png', 'image-gif', 'websocket', 'gif', 'jpg', 'tif', 'bmp', 'mp3']
list_text_proto = ['json', 'xml', 'urlencoded-form']
# Reference 1: https://www.garykessler.net/library/file_sigs.html
# Reference 2: https://asecuritysite.com/forensics/magic
# Reference 3: https://gist.github.com/trentm/9968c2fc43d630e3cdad
dict_magic_numbers = {'1f8b08': 'gzip',
                      '425a68': 'bzip2',
                      'fd377a585a00':'xz',
                      '7573746172': 'tar',
                      '526172211a0700': 'rar',
                      '504b0304140008000800': 'jar',
                      '47494638': 'gif',
                      '667479704d534e56': 'mp4',
                      '6674797069736f6d': 'mp4',
                      '494433': 'mp3',
                      '52494646': 'avi',
                      '89504e47': 'png',
                      'ffd8': 'jpg',
                      '424d': 'bmp',
                      '4949': 'tif'}
list_compressed = ['gzip', 'tar']
"""
If save to a smaller JSON file, by default is False
"""
saveSmaller = False
TH_DATA_LEN = 4
TH_HIGH = 0.9
TH_LOW = 0.4
TH_ENCRYPTED = 0.8
enc_port = 12345
plain_port = 12346
video_port = 12347
venc_port = 12348
ssl_port = 8443
ssl_real_port = 443

def main():
    if len(sys.argv) < 4:
        print('Usage: %s bigjsonfile tinyjsonfile rowcsvfile' % sys.argv[0])
        exit(0)
    print('Filter and compute entropy of %s ...' % sys.argv[1])
    forout, forpd = split_layers(sys.argv[1])
    outfile = sys.argv[2]
    csvfile = sys.argv[3]
    if len(forpd) > 0:
        # open(outfile, 'w').write('\n'.join(forout))
        with open(csvfile, 'w') as cf:
            cf.write(result_header+'\n')
            for row in forpd:
                if row is not None:
                    cf.write('%s\n' % ','.join(map(str, row)))
            print('Result -> %s' % csvfile)
    if len(forout) > 0:
        open(outfile, 'w').write('\n'.join(forout))

def split_layers(infile):
    if not os.path.exists(infile):
        return []
    """
    infile is the ek output from .pcap file
    """
    for_out = []
    for_pd = []
    num_orginal_pkt = 0
    num_udp_tcp_only = 0
    num_omit_filter = 0
    with open(infile) as sf:
        for line in sf.readlines():
            line = line.strip()
            if line.startswith('{"timestamp"'):
                """
                For each frame 
                """
                num_orginal_pkt += 1
                res = process_pkt(line, infile)
                # print(len(line))
                if res is None or len(res) < 2:
                    continue
                if res[0] is not None:
                    """
                    Save smaller JSON if not None
                    """
                    for_out.append(res[0])
                """
                Agg result of rows 
                """
                for_pd.append(res[1])
    return for_out, for_pd

def get_layers(ek_obj):
    layers = set()
    if 'layers' in ek_obj:
        layers = set(ek_obj['layers'].keys())
    return layers


def process_pkt(line, infile):
    try:
        """
        Decode a line of ek formatted info
        list of detected layers -> list_detected_layers
        transport layer -> tp_layer
        """
        ek_obj = json.loads(line)
        list_detected_layers = get_layers(ek_obj)
        tp_layer = determine_transport_layer(list_detected_layers)
        # print(layer)
        """
        KEEP ONLY TCP & UDP FRAMES 
        """
        if tp_layer == LAYER_TP_OTHER: return

        selected = False
        data_proto = 'data'
        if saveSmaller:
            shrinked_obj = shrink_pkt(ek_obj)
            shrinked_obj = json.dumps(shrinked_obj)
        else:
            shrinked_obj = None
        result = compute_pkt(ek_obj, tp_layer, list_detected_layers)
        # print(result)
        if result is None: return
        return shrinked_obj, result
    except:
        print("Err At file: %s" % (infile))
        print(line[:40])
        traceback.print_exc()


def shrink_pkt(ek_obj):
    shrinked_obj = {}
    # TODO: check and fix
    """
    Only keep necessary information to shrink the size of JSON file, ~10 times smaller
    Determine data protocol
    """
    if LAYER_HTTP in list_detected_layers:
        """
        HTTP, keep basic info for http
        """
        shrinked_obj['http'] = shrink_http_layer(ek_obj[K_LAYER]['http'])
        selected = True
        data_proto = LAYER_HTTP
    elif LAYER_DNS in list_detected_layers:
        """
        DNS
        """
        selected = True
        data_proto = LAYER_DNS
    elif 'ntp' in list_detected_layers:
        data_proto = 'ntp'
    elif 'bootp' in list_detected_layers:
        data_proto = 'bootp'
    elif 'ssl' in list_detected_layers:
        data_proto = 'ssl'
    elif 'rtp' in list_detected_layers:
        data_proto = 'rtp'

    """
    Shrink information to save space, do Frame, IP, TCP/UDP for all packets  
    """

    shrinked_obj['frame'] = shrink_frame_layer(ek_obj[K_LAYER]['frame'])
    shrinked_obj['ip'] = shrink_ip_layer(ek_obj[K_LAYER]['ip'])
    shrinked_obj[tp_layer] = shrink_transport_layer(ek_obj, tp_layer)
    return shrinked_obj

def compute_pkt(ek_obj, tp_layer, list_detected_layers):
    layers_obj = ek_obj[K_LAYER]
    """
    Determine the data protocol, the data type
    """
    timestamp = ek_obj['timestamp']
    if 'ip' not in list_detected_layers: return
    """
    Determine the protocol of application layer  
    """
    data_proto = 'data'
    reason = 'info:'
    # eth:ethertype:ip:tcp:http
    frame_number = layers_obj['frame']['frame_frame_number']
    frame_protocols = layers_obj['frame']['frame_frame_protocols'].split(':')
    if len(frame_protocols) > 4:
        data_proto = frame_protocols[4]
    if data_proto == 'data':
        for dl in list_possible_data_layers:
            if dl in list_detected_layers:
                data_proto = dl
                break
    ip_src = layers_obj['ip']['ip_ip_src']
    ip_dst = layers_obj['ip']['ip_ip_dst']
    tp_srcport = layers_obj[tp_layer]['%s_%s_srcport' % (tp_layer, tp_layer)]
    tp_dstport = layers_obj[tp_layer]['%s_%s_dstport' % (tp_layer, tp_layer)]
    """
    Entropy of UDP/TCP payload raw, after hex decoding. 
    """
    if tp_layer == 'tcp':
        if 'tcp_tcp_payload_raw' in layers_obj[tp_layer]:
            data_stream = layers_obj[tp_layer]['tcp_tcp_payload_raw']
        else:
            if 'tcp_tcp_len' in layers_obj[tp_layer]:
                if layers_obj[tp_layer]['tcp_tcp_len'] == 0:
                    return
            return
    elif tp_layer == 'udp':
        data_stream = ek_obj[K_LAYER]['frame_raw'][84:]
        # print(data_stream)
        # print('TOUCH')
        # exit(0)
    """
    1 char of hex code = 4bit of data, thus the byte is /2
    data_bytes: bytes of udp/tcp payload
    """
    data_bytes = len(data_stream) / 2
    if data_bytes < TH_DATA_LEN:
        etp = -1
        data_type = DT_OMIT
        reason += 'small payload (%dB)' % data_bytes
        result = [ip_src, ip_dst, tp_srcport, tp_dstport, tp_layer, data_proto, data_type, data_bytes, etp, reason]
        return result
    etp = entropy_after_decode(data_stream)
    """
    Determine data type: unknown, text, media, compressed, encrypted
    
    """
    data_type = 'unknown'
    """
    when destination port matches our predefined enc/plain ports, label the flow
    """
    tmp_dst_port = int(tp_dstport)
    if tmp_dst_port == enc_port:
        data_type = DT_ENCRYPTED
    elif tmp_dst_port == plain_port:
        data_type = DT_TEXT
    elif tmp_dst_port == video_port:
        data_type = DT_MEDIA
    elif tmp_dst_port == venc_port:
        data_type = DT_ENCRYPTED + '+' + DT_MEDIA
    elif tmp_dst_port == ssl_port or tmp_dst_port == ssl_real_port or data_proto == 'ssl':
        pass
    else:
        return


    if data_proto == 'http':
        if data_type == 'unknown':
            if 'http_http_content_encoding' in layers_obj[LAYER_HTTP]:
                http_ce = layers_obj[LAYER_HTTP]['http_http_content_encoding']
                if http_ce in list_compressed:
                    reason += 'http+content encoding=%s' % http_ce
                    data_type = DT_COMPRESSED
        if data_type == 'unknown':
            if 'http_http_content_type' in layers_obj[LAYER_HTTP]:
                http_ct = layers_obj[LAYER_HTTP]['http_http_content_type']
                if http_ct.startswith('text'):
                    data_type = DT_TEXT
                    reason += 'http_content_type (%s)' % http_ct
                elif http_ct.startswith('image') or http_ct.startswith('video'):
                    data_type = DT_MEDIA
                    reason += 'http_content_type (%s)' % http_ct

        if data_type == 'unknown':
            for mt in list_media_proto:
                if mt in list_detected_layers:
                    data_type = DT_MEDIA
                    reason += 'http+media(%s)' % mt
                    break
        if data_type == 'unknown':
            for tt in list_text_proto:
                if tt in list_detected_layers:
                    data_type = DT_TEXT
                    reason += 'http+text'
                    break

    elif data_proto == 'ssl':
        if etp > TH_ENCRYPTED:
            reason += 'ssl'
            data_type = DT_ENCRYPTED
        elif 'ssl_handshake_text' in ek_obj['layers'][LAYER_SSL] or 'ssl_record_ssl_app_data' in ek_obj['layers'][LAYER_SSL]:
            """
            EDIT remove handshake text 
            """
            data_type = DT_TEXT
            reason += 'ssl+handshake'
            # print(ek_obj)
            # exit(0)
            return
        else:
            # print(layers_obj[LAYER_SSL].keys())
            # print(layers_obj[LAYER_SSL])
            # print(timestamp)
            pass
    elif data_proto == 'dns':
        reason += 'dns'
        data_type = DT_TEXT
        if 'text_dns_dnskey_protocol' in layers_obj[LAYER_DNS]:
            data_type = DT_ENCRYPTED
            reason += ':dnskey'
    elif data_proto == 'rtp':
        reason += 'rtp:'
        # eth:ethertype:ip:udp:rtp:srp:ccsrl:h245
        reason += layers_obj['frame']['frame_frame_protocols'][25:]
        data_type = DT_MEDIA

    """
    Check Magic Number or other file signature
    """
    if data_type == DT_UNKNOWN:
        magic_type = check_magic_number(data_stream)
        if magic_type is not None:
            reason +='magic (%s)' % magic_type
            if magic_type in list_compressed:
                """
                is a compressed type
                """
                data_type = DT_COMPRESSED
                print('%s COMPRESSED: %s - %s %s' % (timestamp, data_proto, tp_layer, magic_type))
            elif magic_type in list_media_proto:
                """
                is a media type
                """
                print('%s MEDIA: %s - %s %s' % (timestamp, data_proto, tp_layer, magic_type))
                data_type = DT_MEDIA

    """
    Guess from <data_bytes, entropy>  
    """
    if data_type == DT_UNKNOWN:
        if etp > TH_HIGH:
            """
            SUPER HIGH
            """
            data_type = DT_ENCRYPTED
            reason += 'high entropy'
        elif etp < TH_LOW:
            if data_bytes > 100:
                data_type = DT_TEXT
                reason += 'low entropy'
    """
    Result: ip_src,ip_dst,srcport,dstport,tp_proto,data_proto,data_type,data_len,entropy,reason
    """
    result = [ip_src, ip_dst, tp_srcport, tp_dstport, tp_layer, data_proto, data_type, data_bytes, etp, reason]
    return result


def determine_transport_layer(layers):
    if 'udp_raw' in layers:
        return LAYER_UDP
    elif 'tcp_raw' in layers:
        return LAYER_TCP
    else:
        return LAYER_TP_OTHER

def shrink_frame_layer(ek_frame):
    list_frame = ['frame_frame_time_epoch', 'frame_frame_len', 'frame_frame_number']
    return copy_sub_fields(ek_frame, list_frame)

def shrink_ip_layer(ek_ip):
    list_ip = ['ip_ip_src', 'ip_ip_dst', 'ip_ip_src_host', 'ip_ip_dst_host']
    return copy_sub_fields(ek_ip, list_ip)

def shrink_transport_layer(ek_obj, tp_layer):
    if tp_layer == LAYER_TCP:
        return shrink_tcp_layer(ek_obj[K_LAYER][tp_layer])
    elif tp_layer == LAYER_UDP:
        """
        UDP does not have udp_udp_payload_raw, so we cut the whole header from frame_raw
        """
        udp_meta = shrink_udp_layer(ek_obj[K_LAYER][tp_layer])
        udp_meta['udp_udp_payload_raw'] = ek_obj[K_LAYER]['frame_raw'][84:]
        return udp_meta

def shrink_tcp_layer(ek_tcp, keep_raw=True):
    list_tcp = ['tcp_tcp_srcport', 'tcp_tcp_dstport']
    """
    TCP Layer: Keep the Raw payload
    """
    if keep_raw:
        list_tcp.append('tcp_tcp_payload_raw')
    return copy_sub_fields(ek_tcp, list_tcp)

def shrink_udp_layer(ek_udp):
    # todo: add udp raw extraction by split frame_raw 42:
    list_udp = ['udp_udp_srcport', 'udp_udp_dstport', 'udp_udp_length']
    return copy_sub_fields(ek_udp, list_udp)

def shrink_http_layer(ek_http):
    list_http = ['http_http_host', 'http_http_request_full_uri',
                 'http_http_request_line', 'http_http_response_line']
    """
    Shrink HTTP
    """
    return copy_sub_fields(ek_http, list_http)

def copy_sub_fields(old_obj, list_fields):
    new_obj = {}
    """
    Generic function to copy given fields only 
    """
    for f in list_fields:
        if f in old_obj:
            new_obj[f] = old_obj[f]
    return new_obj

def check_magic_number(data_stream):
    for magic in dict_magic_numbers:
        if magic in data_stream[:80]:
            """
            Only check first 40 bytes to save time
            """
            mt = dict_magic_numbers[magic]
            print('Found magic: %s (%s)' % (magic, mt))
            return dict_magic_numbers[magic]

def entropy_after_decode(data_stream):
    try:
        """
        raw is hex-decoded according to tshark ek -x option 
        Hex notation represents 4 bits as one char, 
        so 3 random bytes encoded in hex results in a string of 6 chars.  
        """
        tmp = bytearray.fromhex(data_stream).decode(errors='ignore')
        return my_byte_entropy(tmp)
    except:
        traceback.print_exc()
        return my_byte_entropy(data_stream)

def my_byte_entropy(data_stream):
    """Return the Byte Entropy of the sample data.

    Args:
        data_stream: Vector or string of the sample data

    Returns:
        The Byte Entropy as float value
    """

    # Check if string
    if not isinstance(data_stream, str):
        data_stream = list(data_stream)

    """
    Create a frequency data 
    """

    data_set = list(set(data_stream))
    freq_list = []
    num_ts = len(data_stream)
    if num_ts < 2:
        return -1
    for entry in data_set:
        counter = 0.
        for i in data_stream:
            if i == entry:
                counter += 1
        freq_list.append(float(counter) / num_ts)

    """
    Shannon entropy
    """

    ent = 0.0
    for freq in freq_list:
        ent += freq * math.log(freq, 256)
    ent = -ent
    return ent


if __name__ == '__main__':
    main()
