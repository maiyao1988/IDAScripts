# -*- coding:utf-8 -*-
import idc
import os
import ida_idaapi

if __name__ == "__main__":
    start = read_selection_start()
    end = read_selection_end()
    if start != ida_idaapi.BADADDR:
        addr = start
        print("set thumb 0x%08x - 0x%08x"%(start, end))
        while addr != idc.BADADDR and addr < end:
            #改tf寄存器成1
            idc.split_sreg_range(addr, "T", 1, SR_user)
            addr = idc.next_head(addr)
        #
    else:
        print("start is BADADDR please select a range")
