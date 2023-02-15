#!/usr/bin/env python
# -*- coding: utf-8 -*-

import sys
import os
import os.path
from idaapi import *
import time
import idc
from idc import *

def my_get_reg_value(register):
    rv = ida_idd.regval_t()
    ida_dbg.get_reg_val(register, rv)
    regval = rv.ival
    return regval

class MyDbgHooks(DBG_Hooks):
    def __init__(self, output_path, fetch_ea):
        DBG_Hooks.__init__(self)
        self.__output_path = output_path
        self.__output = None
        self.__ea_prev = 0
        self.__cur_blist = []
        self.__cur_opcode = None
        self.__mlist = {}
        self.__fetch_ea = fetch_ea
        
    #

    def dbg_process_attach(self, pid, tid, ea, name, base, size):
        print("Process attach pid=%d tid=%d ea=0x%x name=%s base=%x size=%x" % (pid, tid, ea, name, base, size))
        self.__output = open(self.__output_path, "w")
        self.__tm = time.time()
    #

    def dbg_bpt(self, tid, ea):
        if (ea == self.__ea_prev):
            #不知道为何ida大多数指令会这个回调会调用两次
            return 0
        #
        self.__ea_prev = ea
        base = int(get_imagebase())
        addr = int(ea)
        #print ("Break point at 0x%x pid=%d" % (ea, tid))
        name = idc.get_root_filename()
        disasm_str = GetDisasm(ea)
        print("0x%08x %s hit"%(ea, disasm_str))
        fetch_abs_ea = base + self.__fetch_ea
        #print("%x %x"%(addr, fetch_abs_ea))
        if (addr == fetch_abs_ea):
            if (not len(self.__cur_blist) == 0 and self.__cur_opcode != None):
                tu = tuple(self.__cur_blist)
                if (tu not in self.__mlist):
                    self.__mlist[tu] = self.__cur_opcode
                print("get distinct opcode %d"%len(self.__mlist))
            #
            self.__cur_blist = []
            self.__cur_opcode = my_get_reg_value("R5")
        #
        else:
            self.__cur_blist.append(addr)
        # # return values:
        # #   -1 - to display a breakpoint warning dialog
        # #        if the process is suspended.
        # #    0 - to never display a breakpoint warning dialog.
        # #    1 - to always display a breakpoint warning dialog.
        return 0
    #
    
    def __print_res(self):
        base = int(get_imagebase())
        print("base %s"%hex(base))
        if (self.__output != None):
            self.__output.close()
        #
        nmlist = 0
        for baddrs in self.__mlist:
            opcode = self.__mlist[baddrs]
            print("opcode %s reach block:"%(hex(opcode),))
            for baddr in baddrs:
                print("block %s"%(hex(baddr), ))
            #
            print("end block")
            nmlist = nmlist + 1
        #
        print("after print res %d distinct opcode..."%nmlist)
        t = time.time() - self.__tm
        print("time use %.3f"%t)
    #

    def dbg_suspend_process(self):
        print ("Process suspended")
        self.__print_res()
    #

    def dbg_process_exit(self, pid, tid, ea, code):
        print("call Process exited pid=%d tid=%d ea=0x%x code=%d" % (pid, tid, ea, code))
        self.__print_res()
    #
    
#

if __name__ == "__main__":

    # Remove an existing debug hook
    try:
        if debughook:
            print("Removing previous hook ...")
            debughook.unhook()
        #
    #
    except:
        pass
    #

    funName = idc.AskStr("vmp", "function name")
    funAddr = LocByName(funName)
    if funAddr == BADADDR:
        print("funName %s not found"%funName)
        raise RuntimeError("funName %s not found"%funName)
    #

    funEndAddr = FindFuncEnd(funAddr)
    if funAddr == BADADDR:
        raise RuntimeError("funName %s end not found"%funName)
    #
    function = idaapi.get_func(funAddr)

    nBpt = 0
    flowchart = idaapi.FlowChart(function)
    for bb in flowchart:
        ea = bb.startEA
        AddBpt(ea)
        SetBptAttr(ea, BPTATTR_FLAGS, BPT_ENABLED|BPT_TRACE)
        nBpt = nBpt + 1
    print(nBpt)

    script_path = os.path.split(os.path.realpath(__file__))[0]
    name = os.path.splitext(idc.get_root_filename())[0]
    file_path = "%s/log-%s.txt"%(script_path, name)
    
    fetch_ea = 0x0004C0CC
    fetch_abs_ea = get_imagebase() + fetch_ea
    AddBpt(fetch_abs_ea)
    SetBptAttr(fetch_abs_ea, BPTATTR_FLAGS, BPT_ENABLED|BPT_TRACE)

    
    #Install the debug hook
    debughook = MyDbgHooks(file_path, fetch_ea)
    debughook.hook()
    debughook.steps = 0
    print ("script run...")
#
