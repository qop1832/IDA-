from idautils import *
from idc import *

func_num = 0
# 1 = Success, 0 = Failure
def rename_func(dw_address, s_function):
    global func_num
    dw_ret = None
    part = get_func_name(dw_address)[:7]

    if part != "Script_":
        old_name = get_func_name(dw_address)
        dw_ret = set_name(dw_address, s_function, SN_NOWARN)

        if dw_ret == 0:
            for i in range(1, 32):
                s_temp = "%s_%i" % (s_function, i)

                dw_ret = set_name(dw_address, s_temp, SN_NOWARN)
                if dw_ret != 0:
                    #print("Info: Renamed to %s instead of %s" % (s_temp, s_function))
                    break
            if i == 31:
                print("-- Error --: Failed to rename %s -> %s" % (old_name, s_function))
        else:
            print("%s 0x%X" % (s_function, dw_address))
            func_num += 1

    return dw_ret

def luafunc_get_name(struct_addr):
    return get_strlit_contents( get_qword( struct_addr ), -1).decode('utf-8')
    
def luafunc_get_func(struct_addr):
    return get_qword(struct_addr + 8)

def handle_lua_func(struct_base):
    func_name = luafunc_get_name(struct_base)
    func_addr = luafunc_get_func(struct_base)
    rename_func(func_addr, f"Script_{func_name}")

# ToDo: Add a check for these 2 types
# UnitExists
# SetTaxiMap

def main():
    register_func = find_binary(0, SEARCH_DOWN, "48 89 5c 24 ?? 57 48 83 ec ?? 48 8b ?? ?? ?? ?? ?? 48 8b ?? 48 8b ?? 45 33 c0")
    print(f"FrameScript__RegisterFunction at 0x{register_func:X}")

    for x_ref in XrefsTo(register_func, flags=0):
        # if x_ref != BADADDR:
        #    continue
        struct_base = None
        num_funcs = 0
        operand_value = get_operand_value(x_ref.frm - 0x1D, 0)

        if operand_value == 0x3:
            struct_base = get_operand_value(x_ref.frm - 0x1D, 1)
            num_funcs = get_operand_value(x_ref.frm - 0x16, 1)
        else:
            continue
            #struct_base = get_operand_value(x_ref.frm - 0x14, 1)
            #num_funcs = get_operand_value(x_ref.frm + 0xB, 1)
        #print( "Found 0x%x, count: 0x%x" %(struct_base, num_funcs))
        if 0 < num_funcs < 1000 and 100000 < struct_base < 0xFFFFFFFFFFFFFFFF:
            #print( "Found 0x%x, count: 0x%x" %(struct_base, num_funcs))
            for i in range(num_funcs):
                handle_lua_func(struct_base)
                struct_base += 0x10

    print("结束,共找到 %d 个函数." % func_num)

# Entry point
if __name__ == "__main__":
    main()
