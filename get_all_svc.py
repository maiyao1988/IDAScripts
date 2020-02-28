
#find all system call in moudle, and and break point on it
form = idaapi.find_tform("Output window")
idaapi.switchto_tform(form, True)
idaapi.process_ui_action("msglist:Clear")

for ea in Segments():
    heads = Heads(SegStart(ea), SegEnd(ea))
    for h in heads:
        if GetMnem(h) != '':
            asm = GetDisasm(h)
            if (asm.startswith("SVC")):
                print ("[0x%08X][%40s] %s"%(h, GetFunctionName(h), asm))
                AddBpt(h)
            #
        #
    #
#
print ("Add break point on all svc ok...")