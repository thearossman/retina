import yaml
import sys

IP_CLIENT_START = "16.0.0."
IP_SERVER_START = "48.0.0."
IP_CLIENT_FAKE = "15.0.0."
IP_SERVER_FAKE = "40.0.0."
IP_CLIENT_CB = "ip_src"
IP_SERVER_CB = "ip_dst"
TCP_CB = "tcp_port_80"
HTTP_CB = "http"
SUBSCRIBED = "SavedFiveTuple"

NUM_SUBSCRIPTIONS = 50
FP = "../subscription.yml"
idx = 0

EXP = "non_overlapping"

filters = {}
cbs = { IP_CLIENT_CB: [],
        IP_SERVER_CB: [],
        TCP_CB: [],
        HTTP_CB: [] }

def gen_filters(dir, cond, IP_START, IP_CB):
    global idx
    i = 0
    while idx < NUM_SUBSCRIPTIONS and i < 50: 
        s = "ipv4." + dir + "_addr = " + IP_START + str(i) + cond
        filters[s] = [idx]
        cbs[IP_CB].append(idx)
        idx += 1
        i += 1

def build_non_overlapping_filters(broad=True, include_http=True, ip_pref=""):
    global idx
    client_ip_start = IP_CLIENT_START if broad else IP_CLIENT_FAKE
    server_ip_start = IP_SERVER_START if broad else IP_SERVER_FAKE
    
    if include_http and broad: 
        filters["http"] = [idx]
        cbs[HTTP_CB].append(idx)
        idx += 1

        filters["http.method = \'GET\'"] = [idx]
        cbs[HTTP_CB].append(idx)
        idx += 1

        filters["http.request_version = \'HTTP/1.1\'"] = [idx]
        cbs[HTTP_CB].append(idx)
        idx += 1

    if not broad: 
        pref = ("0/" + ip_pref) if (ip_pref != "") else str(2)
        filters["ipv4.src_addr = " + IP_CLIENT_START + pref + " and http"] = [idx]
        cbs[IP_CLIENT_CB].append(idx)
        idx += 1
        filters["ipv4.dst_addr = " + IP_SERVER_START + pref + " and http"] = [idx]
        cbs[IP_SERVER_CB].append(idx)
        idx += 1
        if pref != "":
            filters["tls"] = [idx]
            cbs[HTTP_CB].append(idx)
            idx += 1
            if include_http:
                filters["http.user_agent = \'asdfg\'"] = [idx]
                cbs[HTTP_CB].append(idx)
                idx += 1

    if broad:
        filters["tcp.port = 80"] = [idx]
        cbs[TCP_CB].append(idx)
        idx += 1

    gen_filters("src", " and http", client_ip_start, IP_CLIENT_CB)
    gen_filters("dst", " and http", server_ip_start, IP_SERVER_CB)
    gen_filters("src", "", client_ip_start, IP_CLIENT_CB)
    gen_filters("dst", "", server_ip_start, IP_SERVER_CB)
    gen_filters("src", " and http.request_version = \'HTTP/1.1\'", client_ip_start, IP_CLIENT_CB)
    gen_filters("dst", " and http.request_version = \'HTTP/1.1\'", IP_SERVER_START, IP_SERVER_CB)
    if idx < NUM_SUBSCRIPTIONS:
        gen_filters("src", " or ipv4.dst_addr in 1.0.0.0/8", client_ip_start, IP_CLIENT_CB)
        gen_filters("dst", " or ipv4.dst_addr in 1.0.0.0/8", IP_SERVER_START, IP_SERVER_CB)
        gen_filters("src", " or udp", client_ip_start, IP_CLIENT_CB)
        gen_filters("dst", " or udp", IP_SERVER_START, IP_SERVER_CB)

def build(data, broad, include_http, ip_pref = ""):
    global idx

    build_non_overlapping_filters(broad, include_http, ip_pref)

    data['filters'] = filters
    data['callbacks'] = cbs
    data['num_subscriptions'] = idx
    data['subscribed'][SUBSCRIBED]['idx'] = [i for i in range(idx)]
    if (idx < NUM_SUBSCRIPTIONS):
        print("Note: only " + str(idx) + " subscriptions generated")
    
    with open(FP, 'w') as f:
        yaml.safe_dump(data, f)

def build_overlapping(data):
    global idx
    s = "ipv4.src_addr = " + IP_CLIENT_START + "2" + " and http"
    filters_overlapping = { s: [] }
    cbs_overlapping = { HTTP_CB: [] }
    while idx < NUM_SUBSCRIPTIONS:
        filters_overlapping[s].append(idx)
        cbs_overlapping[HTTP_CB].append(idx)
        idx += 1
    
    data['filters'] = filters_overlapping
    data['callbacks'] = cbs_overlapping
    data['num_subscriptions'] = idx
    data['subscribed'][SUBSCRIBED]['idx'] = [i for i in range(idx)]

    with open(FP, 'w') as f:
        yaml.safe_dump(data, f)

def build_filter_str():
    global idx
    filter_str = ""
    build_non_overlapping_filters()
    filter_strs = list(set(list(filters.keys())))
    filter_str += "(" + filter_strs[0] + ")"
    for f in filter_strs[1:]:
        filter_str += " or (" + f + ")"
    print("\"" + filter_str + "\"")
    
if len(sys.argv) > 1:
    NUM_SUBSCRIPTIONS = int(sys.argv[1])
    EXP = sys.argv[2]

print("Building subscription config with num subscriptions: " + str(NUM_SUBSCRIPTIONS))

with open("subscription-cpy.yml") as f: 
    data = yaml.safe_load(f)

if EXP == "non_overlapping":
    build(data)
elif EXP == "non_overlapping_narrow":
    build(data, False, False)
elif EXP == "non_overlapping_misses":
    build(data, False, True)
elif EXP == "overlapping_narrow":
    build_overlapping(data)
elif EXP == "non_overlapping_narrowish":
    count = sys.argv[3]
    if len(sys.argv) > 4 and sys.argv[4] == "http":
        build(data, False, True, str(count))
    else:
        build(data, False, False, str(count))
else: 
    print("Error!")
#build_filter_str()