# -*- coding:utf-8 -*-
import idautils
import idaapi
import idc
import ida_dbg
#alias of continue except hotkey because of hhkb layout

class MyContinue(idaapi.plugin_t):
    flags=0                       #插件类别 或者特性
    wanted_name="my continue"  #展示名称
    wanted_hotkey="9"        #其快捷键
    comment="my continue"         #插件描述
    help="Something helpful"     #帮助信息
 
    def init(self):
        return idaapi.PLUGIN_OK
 
    #插件退出时要做的操作，比如说你打开了某个文件，要到插件结束时才能关闭，
    #这里就给你这个机会
    def term(self):
        pass
 
    #按快捷键等 插件运行时 的地方
    def run(self,arg):
        if (not ida_dbg.is_debugger_on()):
            print("[my continue] should run in debug mode.")
            return
        ida_dbg.continue_process()
    #
#插件入口      
def PLUGIN_ENTRY():
    return MyContinue()
#