#!/usr/bin/env python
# -*- coding: utf-8 -*-

import idaapi
import idc
import re
import ida_dbg
import ida_idd
from idaapi import *
from collections import OrderedDict
import logging
import time
import datetime
import os

debughook = None

def set_breakpoint(ea):
    idc.add_bpt(ea)

def my_get_reg_value(register):
    rv = ida_idd.regval_t()
    ida_dbg.get_reg_val(register, rv)
    current_addr = rv.ival
    return current_addr

############
def suspend_other_thread():
    current_thread = idc.get_current_thread()
    thread_count = idc.get_thread_qty()
    for i in range(0, thread_count):
        other_thread = idc.getn_thread(i)
        if other_thread != current_thread:
            idc.suspend_thread(other_thread)
        #
    #
#


def resume_other_thread():
    current_thread = idc.get_current_thread()
    thread_count = idc.get_thread_qty()
    for i in range(0, thread_count):
        other_thread = idc.getn_thread(i)
        if other_thread != current_thread:
            idc.resume_thread(other_thread)
    #idc.resume_thread(current_thread)
    #idc.resume_process()
#

class MyDbgHook(DBG_Hooks):
    """ Own debug hook class that implementd the callback functions """

    def __init__(self, modules_info, skip_functions, start_ea, end_ea):
        super(MyDbgHook, self).__init__()
        self.modules_info = modules_info
        self.skip_functions = skip_functions
        self.trace_step_into_count = 0
        self.trace_step_into_size = 1
        self.trace_total_size = 300000000
        self.trace_size = 0
        self.trace_lr = 0
        self.end_ea = end_ea
        self.start_ea = start_ea
        self.line_trace = 0
        print("__init__")

    def start_line_trace(self):
        self.line_trace = 1
        self.start_hook()

    def start_hook(self):
        self.hook()
        print("start_hook")

    def dbg_process_start(self, pid, tid, ea, name, base, size):
        print("Process started, pid=%d tid=%d name=%s" % (pid, tid, name))

    def dbg_process_exit(self, pid, tid, ea, code):
        self.unhook()
        print("Process exited pid=%d tid=%d ea=0x%x code=%d" % (pid, tid, ea, code))

    def dbg_process_detach(self, pid, tid, ea):
        self.unhook()
        return 0

    def dbg_bpt(self, tid, ea):
        print("Break point at 0x%x tid=%d" % (ea, tid))
        if (ea == self.start_ea):
            print("auto suspend_other_thread")
            suspend_other_thread()
            ida_dbg.request_clear_trace()
            ida_dbg.run_requests()

            ida_dbg.enable_insn_trace(True)
            ida_dbg.enable_step_trace(True)
        #
        if ea in self.end_ea:
            ida_dbg.enable_insn_trace(False)
            ida_dbg.enable_step_trace(False)
            #ida_dbg.suspend_process()
            print("auto resume_other_thread")
            resume_other_thread()
        #
        return 0

    def dbg_trace(self, tid, ea):
        #print("Trace tid=%d ea=0x%x" % (tid, ea))
        # return values:
        #   1  - do not log this trace event;
        #   0  - log it
        lr = hex(my_get_reg_value("LR"))
        print("%s  %s"%(hex(ea), lr))
        if self.line_trace:
            in_mine_so = False
            for module_info in self.modules_info:
                # print (module_info)
                so_base = module_info["base"]
                so_size = module_info["size"]
                if so_base <= ea <= (so_base + so_size):
                    in_mine_so = True
                    return 0
        
        return 1
        '''
        self.trace_size += 1
        if (not in_mine_so) or (ea in self.skip_functions):
            if (self.trace_lr != 0) and (self.trace_step_into_count < self.trace_step_into_size):
                self.trace_step_into_count += 1
                return 0

            if (self.trace_lr != 0) and (self.trace_step_into_count == self.trace_step_into_size):
                ida_dbg.enable_insn_trace(False)
                ida_dbg.enable_step_trace(False)
                ida_dbg.suspend_process()
                if self.trace_size > self.trace_total_size:
                    self.trace_size = 0
                    ida_dbg.request_clear_trace()
                    ida_dbg.run_requests()

                ida_dbg.request_run_to(self.trace_lr & 0xFFFFFFFE)
                ida_dbg.run_requests()
                self.trace_lr = 0
                self.trace_step_into_count = 0
                return 0

            if self.trace_lr == 0:
                self.trace_lr = my_get_reg_value("LR")
        return 0
        '''

    def dbg_run_to(self, pid, tid=0, ea=0):
        # print("dbg_run_to 0x%x pid=%d" % (ea, pid))
        if self.line_trace:
            ida_dbg.enable_insn_trace(True)
            ida_dbg.enable_step_trace(True)
            ida_dbg.request_continue_process()
            ida_dbg.run_requests()


def unhook():
    global debughook
    # Remove an existing debug hook
    try:
        if debughook:
            print("Removing previous hook ...")
            debughook.unhook()
    except:
        pass


def starthook():
    global debughook
    if debughook:
        debughook.start_line_trace()

def main():
    global debughook
    #ida7 debug 中有bug,弹AskStr会卡死
    #基本流程
    #1.需要手动调整下面三个参数
    target1 = "libmetasec_ml.so"
    start_off_in_target = 0x0004C028
    end_off_in_target = 0x0004DDB4
    #2.需要在Debugger->Tracing->Tracing option 关闭Trace over debugger segments,并在这个页面输入Trace File路径
    #脚本会在开始和结束下断点,点击continue运行.开始trace,命中结束断点trace自动结束,trace结果保存在设置的Trace File路径中

    unhook()
    skip_functions = []
    modules_info = []
    start_ea = 0
    end_ea = []
    so_modules = [target1]
    for module in idc._get_modules():
        module_name = os.path.basename(module.name)
        # print("enum: %s" % module_name)
        for so_module in so_modules:
            if re.search(so_module, module_name, re.IGNORECASE):
                print("modules_info append %08X %s %08X" % (module.base, module.name, module.size))
                if module_name == target1:
                    # module.size = 98304
                    modules_info.append({"base": module.base, "size": module.size, "name": module.name})
                    start_ea = (module.base + start_off_in_target)      #encode_func_2
                    end_ea = [((module.base + end_off_in_target))]
                    break
                #
            #
        #
    #
    
    if start_ea:    # start address
        set_breakpoint(start_ea)
    if end_ea:      # end address
        for ea in end_ea:
            set_breakpoint(ea)

    if skip_functions:
        print("skip_functions")
        for skip_function in skip_functions:
            print ("%08X" % skip_function)
    
    debughook = MyDbgHook(modules_info, skip_functions, start_ea, end_ea)
    idaapi.jumpto(start_ea)
    starthook()
    pass


if __name__ == "__main__":
    main()
    pass