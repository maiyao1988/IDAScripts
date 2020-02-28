



funName = idc.AskStr("JNI_OnLoad", "function name")
funAddr = LocByName(funName)
if funAddr == BADADDR:
    print("funName %s not found"%funName)
    raise RuntimeError("funName %s not found"%funName)
#

funEndAddr = FindFuncEnd(funAddr)

heads = Heads(funAddr, funEndAddr)

script_path = os.path.split(os.path.realpath(__file__))[0]
name = os.path.splitext(idc.get_root_filename())[0]
out_path = "%s/codes-%s-%s.txt"%(script_path, name, funName)
count = 0
with open(out_path, "w") as f:
    for h in heads:
        if GetMnem(h) != '':
            line = "[0x%08X] %s\n"%(h, GetDisasm(h))
            f.write(line)
            count = count+1
        #
    #
#
print("ins count %d"%count)
print("file output to %s"%out_path)