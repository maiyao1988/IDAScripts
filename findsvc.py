import logging
import posixpath
import sys
import os
import traceback

def find_bytes(f, target):
    addrs = []
    f.seek(0, 0)
    step = len(target)
    off = 0
    while True:
        b = f.read(step)
        if (b == target):
            addrs.append(off)
        #
        if (len(b) == 0):
            break
        off += step
    #
    return addrs
#

if __name__ == "__main__":
    if (len(sys.argv) < 2):
        print ("usage %s <soname> "%sys.argv[0])
        sys.exit(1)
    #
    soname = sys.argv[1]
    svc_arm = bytearray([00, 00, 00, 0xef])
    svc_thumb = bytearray([00, 0xdf])
    with open(soname, "rb") as f:
        svcs_arm = find_bytes(f, svc_arm)
        print ("svc arm:")
        for svc in svcs_arm:
            print(hex(svc))
        #
        print ("svc thumb:")
        svcs_thumb = find_bytes(f, svc_thumb)
        for svc in svcs_thumb:
            print(hex(svc))
        #
    #
#