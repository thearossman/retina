import re
import os
import math
import ipaddress
from pathlib import Path
import argparse

root_dir = os.getenv("RETINA_HOME")
if not root_dir:
    raise RuntimeError("Set $RETINA_HOME")
main_fp = f"{root_dir}/examples/basic/src/main.rs"

subscriptions_pref = 3
filters_pref = 0
callbacks_pref = 3

subscription_pattern = r"(subscriptions:\s*vec!\[)(\s*.*?\s*)(\])"
callback_pattern = r"(callbacks:\s*vec!\[)(\s*.*?\s*)(\])"
filter_pattern = r"(#\[filter\()(\s*.*?\s*)(\)\])"

def replace(path, pattern, new_lines):
    orig = path.read_text()
    matches = re.search(pattern, orig, re.DOTALL) # match newlines
    if not matches:
        raise RuntimeError("Can't find subscription vector in file")
    replaced = matches.group(1) + new_lines + matches.group(3)
    replaced = orig[:matches.start()] + replaced + orig[matches.end():]
    path.write_text(replaced)

def build_subscriptions(n):
    s = "\n"
    prefix = "\t" * subscriptions_pref
    for i in range(0, n):
        s += prefix + "SubscribableTypeId::Connection,\n"
    s += "\t" * (subscriptions_pref - 1)
    return s

def build_ipv4_filters(n):
    # Shard IPv4 address space
    if not (n > 0 and (n & (n - 1)) == 0):
        raise ValueError(f"{n} is not a power of 2")
    new_prefix = int(math.log2(n))
    net = ipaddress.IPv4Network("0.0.0.0/0")
    subnets = list(net.subnets(new_prefix=new_prefix))
    s = "\""
    for subnet in subnets:
        s += f"ipv4.addr = {subnet} and (http or tls or dns or quic)\n" # tmp
    s = s[:-1] # remove last newline
    s += "\""
    return s

def build_callbacks(n):
    s = ""
    pref = "\t" * callbacks_pref
    for i in range(0, n):
        s += pref + "Box::new(|d| {\n"
        s += pref + "\t" + "if let SubscribedData::Connection(conn) = d {\n"
        s += pref + "\t" + "\t" + "callback_conn(conn);\n"
        s += pref + "\t" + "}\n"
        s += pref + "}),\n"
    s += "\t" * (callbacks_pref - 1)
    return s

if __name__ == "__main__":

    parser = argparse.ArgumentParser(
        prog='Subscription Generator',
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    parser.add_argument('-n',
        type=int,
        default=2,
        help='Number of subscriptions to generate')

    args = parser.parse_args()
    print(f"Generating {args.n} subscriptions")

    subscriptions_str = build_subscriptions(args.n)
    callbacks_str = build_callbacks(args.n)
    filters_str = build_ipv4_filters(args.n)

    path = Path(main_fp)

    replace(path, subscription_pattern, subscriptions_str)
    replace(path, callback_pattern, callbacks_str)
    replace(path, filter_pattern, filters_str)