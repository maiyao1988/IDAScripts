#!/usr/bin/env python
# -*- coding: utf-8 -*-

import sys
from idaapi import *
import idc
from idc import *


class Tracer(DBG_Hooks):
    def __init__(self):
        DBG_Hooks.__init__(self)

    #

    def dbg_process_exit(self, pid, tid, ea, code):
        print("Process exited pid=%d tid=%d ea=0x%x code=%d" % (pid, tid, ea, code))

    def dbg_process_attach(self, pid, tid, ea, name, base, size):
        print("Process attach pid=%d tid=%d ea=0x%x name=%s base=%x size=%x" % (pid, tid, ea, name, base, size))

    def dbg_library_load(self, pid, tid, ea, name, base, size):
        print ("Library loaded: pid=%d tid=%d name=%s base=%x" % (pid, tid, name, base))

    def dbg_bpt(self, tid, ea):
        
        base = int(get_imagebase())
        addr = int(ea)
        #print ("Break point at 0x%x pid=%d" % (ea, tid))
        name = idc.get_root_filename()
        disasm_str = GetDisasm(ea)

        buf = idc.GetManyBytes(ea, ItemSize(ea))
        
        instruction_str = ''.join('{:02X} '.format(ord(x)) for x in buf)
        line = "(%20s[0x%08X])[%-12s]0x%08X:\t%s"%(name, base, instruction_str, addr-base, disasm_str)
        print(line)
        # return values:
        #   -1 - to display a breakpoint warning dialog
        #        if the process is suspended.
        #    0 - to never display a breakpoint warning dialog.
        #    1 - to always display a breakpoint warning dialog.
        return 0

    def dbg_suspend_process(self):
        pass
        #print "Process suspended"
    #



# Remove an existing debug hook
try:
    if debughook:
        print("Removing previous hook ...")
        debughook.unhook()
except:
    pass
#


funName = "JNI_OnLoad"
funAddr = LocByName(funName)
if funAddr == BADADDR:
    print("funName %s not found"%funName)
    raise RuntimeError("funName %s not found"%funName)
#

funEndAddr = FindFuncEnd(funAddr)
    
if funAddr == BADADDR:
    raise RuntimeError("funName %s end not found"%funName)
#

for ea in Heads(funAddr, funEndAddr):
    AddBpt( ea )
    SetBptAttr( ea, BPTATTR_FLAGS, BPT_ENABLED|BPT_TRACE)
#


# Install the debug hook
debughook = Tracer()
debughook.hook()
debughook.steps = 0
print ("script run...")

