import os
import sys
import subprocess
import time
import random
import binascii

from w32vrf_device import w32vrf_device
#from w32vrf_log_parser import w32vrf_log_parser

def start_w32_verifier(driver_path, process_binary_path):

    w32vrf = w32vrf_device()

    w32vrf.start_w32vrf(driver_path)
    w32vrf.w32vrf_enable_hook()

    for proc_name in process_binary_path:
        w32vrf.w32vrf_add_process(proc_name)

    w32vrf.w32vrf_close_device()

def parse_w32vrf_log(path_to_dump, path_to_log):

    log_parser = w32vrf_log_parser()

    log_parser.load_dump("srv*C:\\symbols*http://msdl.microsoft.com/download/symbols", path_to_dump)

    log = log_parser.parse_log()

    log_parser.save_log_to_file(path_to_log)

    log_parser.close_dump()

    return log
     

def print_usage():
    print("Usage:\nRestart W32VrfDrv: \n\W32VrfDrv.py start_w32vrf W32VrfDrv.sys Process1.exe Process2.exe ...\nParse dump:\n\W32VrfDrvControl.py parse_w32vrf_log path_to_dump.dmp")

def main():

    if len(sys.argv) < 2:
        print("Invalid args")
        print_usage()
        return

    if sys.argv[1] == "start_w32vrf" and len(sys.argv) > 3:
        start_w32_verifier(sys.argv[2], sys.argv [3:])
    elif sys.argv[1] == "parse_w32vrf_log" and len(sys.argv) > 3:
        parse_w32vrf_log(sys.argv[2], sys.argv[3])
    else:
        print("Invalid args")
        print_usage()
        return

if __name__ == '__main__':
    main()