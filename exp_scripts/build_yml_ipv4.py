import yaml
import sys
import ipaddress

prefix_len = 0
FP = "/home/tcr6/retina/subscription.yml"
FP_IN = "/home/tcr6/retina/exp_scripts/subscription-cpy-ipv4.yml"

CB = "eth"
DATATYPE = "SubscribedConnection"

if len(sys.argv) > 1:
    prefix_len = int(sys.argv[1])

num_subscriptions = 2**prefix_len
if num_subscriptions > 128:
    assert False

print(f"Building config with prefix len {prefix_len} ({num_subscriptions} subscriptions)")

with open(FP_IN) as f: 
    data = yaml.safe_load(f)

data['callbacks']['eth'] = [i for i in range(num_subscriptions)]
data['subscribed'][DATATYPE]['idx'] = [i for i in range(num_subscriptions)]
data['num_subscriptions'] = num_subscriptions

subnets = list(ipaddress.ip_network('0.0.0.0/0').subnets(new_prefix=prefix_len))

data['filters'] = { }

for i in range(len(subnets)):
    subnet = subnets[i]
    as_str = 'ipv4.dst_addr = ' + str(subnet)
    data['filters'][as_str] = [i]

with open(FP, 'w') as f:
    yaml.safe_dump(data, f)