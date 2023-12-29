import os 
import sys
from datetime import datetime
import time


# print experiment type
# run experiment

# read output (reverse list ./logs, then read most recent directory, then get throughput)

# os.system("cargo build --bin spin --release")

def run_cycles():
    for spin in [0]:
        print("Starting exp with " + str(spin) + " cycles at " + str(datetime.now()))
        os.system("sudo env LD_LIBRARY_PATH=$LD_LIBRARY_PATH RUST_LOG=error ./target/release/spin --config configs/online_exp.toml --spin " + str(spin))
        print("Done running retina")
        print("------")

# run_cycles()

def run_multi(arg=""):
    # for exp in ["non_overlapping_narrow", "overlapping_narrow"]:
    exp = "non_overlapping_narrowish"
    for multi in [10, 25, 50, 100, 128]:
        os.system("python3 build_yml.py " + str(multi) + " " + exp + " " + arg)
        os.system("cargo build --bin spin --release")
        print("Running Retina with num subscriptions: " + str(multi) + ", exp: " + exp + ", arg: " + arg)
        run_cycles()
        print("********************************")

def run_narrowish():
    # 16.0.0.1 - 16.0.1.255 == /23 subnet 
    for ip_prefix in [27, 29, 31]:
        print("Starting IP Prefix ***with tls*** " + str(ip_prefix))
        run_multi(str(ip_prefix))
        print("********************************")
        print("Starting IP Prefix ***with tls and http user-agent*** " + str(ip_prefix))
        run_multi(str(ip_prefix) + " http")
        print("********************************")

# run_multi()
run_narrowish()
