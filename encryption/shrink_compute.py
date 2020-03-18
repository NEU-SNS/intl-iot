"""
Created by JJ
Created at 2/11/2019

CSVFILE: ip_src,ip_dst,srcport,dstport,tp_proto,data_proto,data_type,data_len,entropy,reason
"""
import json
import os
import sys
import math
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
DT_MEDIA_RTP = 'media-rtp'
DT_MEDIA_MAGIC = 'media-magic'

DT_COMPRESSED = 'compressed'
DT_ENCRYPTED = 'encrypted'
DT_OMIT='omit'

result_header='ip_src,ip_dst,srcport,dstport,tp_proto,data_proto,data_type,data_len,entropy,reason'
list_possible_data_layers = ['http', 'dns', 'ntp', 'bootp', 'ssl', 'rtp',
                             'mqtt', 'rtc', 'rtsp', 'bootp', 'dtls', 'mdns',
                             'thrift', 'ssdp', 'stun']
list_media_proto = ['media', 'image', 'mp4', 'png', 'image-gif', 'websocket', 'gif', 'jpg', 'tif', 'bmp', 'mp3']
list_text_proto = ['json', 'xml', 'urlencoded-form', 'text']
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
saveSmaller=False
TH_DATA_LEN_EMPTY=4
TH_DATA_LEN_OMIT=20
TH_DATA_LEN_MEANINGFUL=100
TH_HIGH=0.9
TH_LOW=0.4
TH_ENCRYPTED=0.8

def usage():
    print("Usage: %s json_file csv_file\n" % sys.argv[0])
    print("Uses the JSON file to output a CSV file that includes the entropy of each packet and its classification (encrypted, text, media, unknown).\n")
    print("Example: %s output/traffic.json output/traffic.csv\n" % sys.argv[0])
    print("Arguments:")
    print("  json_file: The output json file from running TShark")
    print("  csv_file: The output csv file of this script")
    exit(0)

def main():
    print("Running %s..." % sys.argv[0])
    jsonfile = sys.argv[1]
    csvfile = sys.argv[2]
    
    print("Performing error checking on command line arguments...")
    if len(sys.argv) != 3:
        print("\033[31mError: 2 arguments expected. %s arguments found.\033[39m" % len(sys.argv))
        usage()

    done = False
    if not jsonfile.endswith(".json"):
        done = True
        print("\033[31mError: The file \"%s\" is not a JSON file.\033[39m" % jsonfile)
    elif not os.path.isfile(jsonfile):
        done = True
        print("\033[31mError: The file \"%s\" does not exist.\033[39m" % jsonfile)
    if not csvfile.endswith(".csv"):
        done = True
        print("\033[31mError: The file \"%s\" is not a CSV file.\033[39m" % csvfile)

    if done:
        usage()

    print('Shrink and compute entropy of %s...' % jsonfile)
    forpd = split_layers(jsonfile)
    if len(forpd) > 0:
        # open(outfile, 'w').write('\n'.join(forout))
        print("Writing to \"%s\"..." % csvfile)
        dirname = os.path.dirname(csvfile)
        if not os.path.isdir(dirname):
            os.makedirs(dirname)

        with open(csvfile, 'w') as cf:
            cf.write(result_header+'\n')
            n_rows = 0
            for row in forpd:
                if row is not None:
                    n_rows+=1
                    cf.write('%s\n' % ','.join(map(str, row)))
            print('Results -> %s (%s packets)' % (csvfile, n_rows))

def split_layers(infile):
    """
    infile is the ek output from .pcap file
    """
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
                if res is None:
                    continue
                """
                Agg result of rows 
                """
                for_pd.append(res)
    return for_pd

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

        result = compute_pkt(ek_obj, tp_layer, list_detected_layers)
        # print(result)
        if result is None: return
        return result
    except:
        print("Err At file: %s" % (infile))
        print(line)
        traceback.print_exc()


def compute_pkt(ek_obj, tp_layer, list_detected_layers):
    layers_obj = ek_obj[K_LAYER]
    """
    Determine the data protocol, the data type
    """
    timestamp = ek_obj['timestamp']
    if 'ip' not in list_detected_layers: return
    """
    Determine the protocol of application layer by looking at 5th protocol in the frame    
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
    if data_bytes < TH_DATA_LEN_EMPTY:
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
    Step 1. Known protocols, currently HTTP, SSL, DNS, RTP
    """
    if data_proto == 'http':
        """
        Use Content-Encoding in http header
        """
        if 'http_http_content_encoding' in layers_obj[LAYER_HTTP]:
            http_ce = layers_obj[LAYER_HTTP]['http_http_content_encoding']
            if http_ce in list_compressed:
                reason += 'http+content encoding=%s' % http_ce
                data_type = DT_COMPRESSED
        if data_type == 'unknown':
            """
            Use content type in HTTP header
            """
            if 'http_http_content_type' in layers_obj[LAYER_HTTP]:
                http_ct = layers_obj[LAYER_HTTP]['http_http_content_type']
                if http_ct.startswith('text'):
                    data_type = DT_TEXT
                    reason += 'http_content_type (%s)' % http_ct
                elif http_ct.startswith('image') or http_ct.startswith('video'):
                    data_type = DT_MEDIA_MAGIC
                    reason += 'http_content_type (%s)' % http_ct
        if data_type == 'unknown':
            """
            If wireshark identified certain media types
            """
            for mt in list_media_proto:
                if mt in list_detected_layers:
                    data_type = DT_MEDIA_MAGIC
                    reason += 'http+media(%s)' % mt
                    break
        if data_type == 'unknown':
            """
            If wireshark identified certain text types: text, json, xml
            """
            for tt in list_text_proto:
                if tt in list_detected_layers:
                    data_type = DT_TEXT
                    reason += 'http+text'
                    break
    elif data_proto == 'ssl':
        if etp > TH_ENCRYPTED:
            reason += 'ssl+etp>%s' % TH_ENCRYPTED
            data_type = DT_ENCRYPTED
        elif 'ssl_handshake_text' in layers_obj[LAYER_SSL]:
            data_type = DT_TEXT
            reason += 'ssl+handshake'
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
        data_type = DT_MEDIA_RTP
    elif data_proto == 'gquic':
        reason +='gquic'
        data_type = DT_ENCRYPTED

    """
    Step 2. Check Magic Number or other file signature
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
                data_type = DT_MEDIA_MAGIC

    """
    Step 3. Guess from <data_bytes, entropy>  
    """
    if data_type == DT_UNKNOWN:
        if etp > TH_HIGH:
            """
            SUPER HIGH
            """
            data_type = DT_ENCRYPTED
            reason += 'high entropy'
        elif etp < TH_LOW:
            """
            Low entropy 
            """
            if data_bytes > TH_DATA_LEN_MEANINGFUL:
                data_type = DT_TEXT
                reason += 'low entropy'
    """
    Step 4. Omit small unknown packets
    """
    if data_type == DT_UNKNOWN and data_bytes < TH_DATA_LEN_OMIT:
        reason += ' small omit'
        data_type = DT_OMIT

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
