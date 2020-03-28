import idc
import os
 
somodule = AskStr('libcms.so', 'module name')

off_str = AskStr('0x0', 'in hex')

off = int(off_str, 16)
modulebase = GetFirstModule()
 
while (modulebase != None) and (GetModuleName(modulebase).find(somodule) == -1):
        modulebase = GetNextModule(modulebase)
 
if modulebase == None:
        print ('failed to find module:' , somodule)
 
else:
        abs_off = modulebase + off
        print ('module of %s base address is: 0x%08X'%(somodule, modulebase))
        print("jump to 0x%08X"%abs_off)
        Jump(abs_off)
#