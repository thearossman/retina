import sys
import ipaddress


prefix_len = 2

if len(sys.argv) > 1:
    prefix_len = int(sys.argv[1])

subnets = list(ipaddress.ip_network('0.0.0.0/0').subnets(new_prefix=prefix_len))

filter_str = f"({str(subnets[0])})"
filter_vec = f"\"{str(subnets[0])}\".parse().unwrap()"

for i in range(1, len(subnets)):
    filter_str += f" or ({str(subnets[i])})"
    filter_vec += f",\n\"{str(subnets[i])}\".parse().unwrap()"

print(filter_str)
print("----")
print(filter_vec)

# SocketAddr