import os
import math
import ipaddress
import argparse
import yaml

root_dir = os.getenv("RETINA_HOME")
if not root_dir:
    raise RuntimeError("Set $RETINA_HOME")

out_fp = os.getenv("IN_FILE")
if not out_fp:
    raise RuntimeError("Set $IN_FILE")

def build_ipv4_filters(n):
    if not (n > 0 and (n & (n - 1)) == 0):
        raise ValueError(f"{n} is not a power of 2")
    new_prefix = int(math.log2(n))
    net = ipaddress.IPv4Network("0.0.0.0/0")
    subnets = list(net.subnets(new_prefix=new_prefix))
    out = {}
    for idx in range(0, len(subnets)):
        s = f"ipv4.addr = {subnets[idx]} and (http or tls or dns)"
        out[s] = [idx]
    return out

if __name__ == "__main__":

    parser = argparse.ArgumentParser(
        prog='Filter String Generator',
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    parser.add_argument('-n',
        type=int,
        default=2,
        help='Number of filter strings to generate')

    args = parser.parse_args()
    print(f"Generating {args.n} subscriptions")

    filters = build_ipv4_filters(args.n)
    data = {}
    data['filters'] = build_ipv4_filters(args.n)
    data['callbacks'] = { 'conn_cb': [i for i in range(0, args.n)] }
    data['subscribed'] = { 'SubscribedConn': { 'idx' : [i for i in range(0, args.n)], 'fields' : {'connection': []} } }
    data['num_subscriptions'] = args.n

    with open(out_fp, 'w') as f:
        yaml.safe_dump(data, f)
