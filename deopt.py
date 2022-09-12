# 去除虚假控制流 idapython脚本
import ida_xref
import ida_idaapi
from ida_bytes import get_bytes, patch_bytes
 
# 将 mov 寄存器, 不透明谓词 修改为 mov 寄存器, 0
def do_patch(ea):
    if get_bytes(ea, 1) == b"\x8B": # mov eax-edi, dword
        reg = (ord(get_bytes(ea + 1, 1)) & 0b00111000) >> 3
        patch_bytes(ea, (0xB8 + reg).to_bytes(1,'little') + b'\x00\x00\x00\x00\x90')
    else:
        print('error')
 
# 不透明谓词在.bss段的范围
start = 0x00428298
end = 0x00428384
 
for addr in range(start,end,4):
    ref = ida_xref.get_first_dref_to(addr)
    print(hex(addr).center(20,'-'))
    # 获取所有交叉引用
    while(ref != ida_idaapi.BADADDR):
        do_patch(ref)
        print('patch at ' + hex(ref))
        ref = ida_xref.get_next_dref_to(addr, ref)
    print('-' * 20)
