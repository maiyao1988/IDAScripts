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
    def __init__(self, output_path, enter_ea, fetch_ea, exit_ea):
        DBG_Hooks.__init__(self)
        self.__output_path = output_path
        self.__output = None
        self.__cur_opset = None
        self.__opstack = []
        self.__enter_ea = enter_ea
        self.__fetch_ea = fetch_ea
        self.__exit_ea = exit_ea
        
    #

    def dbg_process_attach(self, pid, tid, ea, name, base, size):
        print("Process attach pid=%d tid=%d ea=0x%x name=%s base=%x size=%x" % (pid, tid, ea, name, base, size))
        self.__output = open(self.__output_path, "w")
        self.__tm = time.time()
    #

    def __print_res(self):        
        base = int(get_imagebase())
        tmp_list = list(self.__cur_opset)
        tmp_list.sort()
        
        head = "begin dump opcode base 0x%08x\n"%int(base)
        self.__output.write(head)
        for opcode in tmp_list:
            line = "0x%08x\n"%int(opcode)
            self.__output.write(line)
        
        if (self.__output != None):
            self.__output.flush()
        #
    #
    
    def dbg_bpt(self, tid, ea):
        base = int(get_imagebase())
        addr = int(ea)
        fetch_abs_ea = base + self.__fetch_ea
        enter_abs_ea = base + self.__enter_ea
        exit_abs_ea = base + self.__exit_ea
        #print("%x %x"%(addr, fetch_abs_ea))
        if (addr == enter_abs_ea):
            print("enter vmp...")
            if (self.__cur_opset != None):
                self.__opstack.append(self.__cur_opset) 
            #
            self.__cur_opset = set()
            
        elif (addr == fetch_abs_ea):
            cur_opcode = my_get_reg_value("R0")
            self.__cur_opset.add(cur_opcode)
            print("opcode off 0x%08x"%int(cur_opcode))
        #
        elif (addr == exit_abs_ea):
            print("exit vmp dump...")
            self.__print_res()
            self.__cur_opset = self.__opstack.pop()
            if (len(self.__opstack) == 0):
                print("finish...")
            #
        #
        return 0
    #
    

    def dbg_suspend_process(self):
        print ("Process suspended")
        
        if (self.__output != None):
            self.__output.flush()
        #
    #

    def dbg_process_exit(self, pid, tid, ea, code):
        print("call Process exited pid=%d tid=%d ea=0x%x code=%d" % (pid, tid, ea, code))
        
        if (self.__output != None):
            self.__output.close()
        #
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

    script_path = os.path.split(os.path.realpath(__file__))[0]
    name = os.path.splitext(idc.get_root_filename())[0]
    file_path = "%s/opcodes-%s.txt"%(script_path, name)
    
    fetch_ea = 0x0004C0CC
    fetch_abs_ea = get_imagebase() + fetch_ea
    AddBpt(fetch_abs_ea)
    SetBptAttr(fetch_abs_ea, BPTATTR_FLAGS, BPT_ENABLED|BPT_TRACE)
    
    enter_ea = 0x0004C028
    enter_abs_ea = get_imagebase() + enter_ea
    AddBpt(enter_abs_ea)
    SetBptAttr(enter_abs_ea, BPTATTR_FLAGS, BPT_ENABLED|BPT_TRACE)
    
    #用0x4DDB4会崩溃
    exit_ea = 0x4DDB0
    exit_abs_ea = get_imagebase() + exit_ea
    AddBpt(exit_abs_ea)
    SetBptAttr(exit_abs_ea, BPTATTR_FLAGS, BPT_ENABLED|BPT_TRACE)
    
    #Install the debug hook
    debughook = MyDbgHooks(file_path, enter_ea, fetch_ea, exit_ea)
    debughook.hook()
    debughook.steps = 0
    print ("script run...")
#
