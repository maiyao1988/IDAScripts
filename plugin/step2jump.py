# -*- coding:utf-8 -*-
import idautils
import idaapi
import idc
import ida_dbg

def my_get_reg_value(register):
    rv = ida_idd.regval_t()
    ida_dbg.get_reg_val(register, rv)
    regval = rv.ival
    return regval

def is_modify_pc(addr):
    opnd = GetOpnd(addr, 0)
    if (opnd == "PC"):
        return True
    mnem = GetMnem(addr)
    if (mnem.startswith("POP")):
        i = 0
        while True:
            opnd = GetOpnd(addr, i)
            
            if (opnd == ""):
                return False
            elif (opnd.find("PC") >-1):
                return True
            #
            i = i + 1
        #
    #
    return False
#

def is_jump(addr):
    mnem = GetMnem(addr)
    if (mnem.startswith("B") and mnem not in ("BFC", "BFI", "BIC") or mnem.startswith("IT")):
        return True
    #
    elif (is_modify_pc(addr)):
        return True
    #
    return False
#

#runto to jump instruction when debugging
class Step2Jump(idaapi.plugin_t):
    flags=0                       #插件类别 或者特性
    wanted_name="step to jump"  #展示名称
    wanted_hotkey="6"        #其快捷键
    comment="debug step to jump"         #插件描述
    help="Something helpful"     #帮助信息
 
    #初始化时运行的，可以判断是否要启用这个插件，比如你这个插件主要是针对x86的，
    #那你就要判断当前分析的是不是x86，然后在决定是否要显示或者启用这个插件
    def init(self):
        return idaapi.PLUGIN_OK
 
    #插件退出时要做的操作，比如说你打开了某个文件，要到插件结束时才能关闭，
    #这里就给你这个机会
    def term(self):
        pass
 
    #按快捷键等 插件运行时 的地方
    def run(self,arg):
        if (not ida_dbg.is_debugger_on()):
            print("[step to jump] should run in debug mode.")
        else:
            curentEA = my_get_reg_value("PC")                
            if (is_jump(curentEA)):
                #当前是一个jump或者函数调用，直接做一个step_over
                ida_dbg.step_over()
            #
            else:
                addr = idc.next_head(curentEA)
                while addr != idc.BADADDR:
                    if (not idaapi.isCode(idaapi.getFlags(addr))):
                        line = "next_addr Find 0x%08x is not code addr, can not do anything"%addr
                        print(line)
                        break
                    #
                    if (is_jump(addr)):
                        ida_dbg.run_to(addr)
                        print("run to break")
                        break
                    #
                    addr = idc.next_head(addr)
                #
            #
            #两个dbg事件之间要加上这句话才两个都生效
            #ida_dbg.wait_for_next_event(ida_dbg.WFNE_SUSP, -1)
    #
#插件入口      
def PLUGIN_ENTRY():
    return Step2Jump()
#