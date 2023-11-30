from idautils import *
from idc import *

"""************************************************************************
   Desc:		Label each lua function based on its appropriate name
   Author:  kynox 
   Credit:	bobbysing for RenameFunc
   Website: http://www.gamedeception.net
*************************************************************************"""


# 1 = Success, 0 = Failure
def rename_func(dw_address, s_function):
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
                    # print("Info: Renamed to %s instead of %s" % (s_temp, s_function))
                    break

            if i == 31:
                print("-- Error --: Failed to rename %s -> %s" % (old_name, s_function))
        else:
            print("%s 0x%X" % (s_function, dw_address))

    return dw_ret


def luafunc_get_name(struct_addr):
    return get_strlit_contents(get_qword(struct_addr), -1).decode('utf-8')


def luafunc_get_func(struct_addr):
    return get_qword(struct_addr + 8)


def handle_lua_func(struct_base):
    func_name = luafunc_get_name(struct_base)
    func_addr = luafunc_get_func(struct_base)
    # print("funcName %s, funcAddr: 0x%X" % (func_name, func_addr))
    rename_func(func_addr, "CSimpleSlider_%s" % func_name)
    pass


def main():
    register_func = find_binary(0, SEARCH_DOWN,
                                "48 89 5c 24 ?? 57 48 83 ec ?? 48 8b 3d ?? ?? ?? ?? 48 8b d9 48 8b cf e8")
    print("FrameScript_Object__FillScriptMethodTable at 0x%X" % register_func)

    for x_ref in XrefsTo(register_func, flags=0):
        struct_base = None
        num_funcs = None
        i = 0

        blahh = x_ref.frm - 0xF
        operand_value = get_operand_value(blahh, 0)  # 获取操作数字符串
        # print("ref -> 0x%x >> blahh -> 0x%x >> operand -> %d" % (x_ref.frm,blahh,operand_value))

        if operand_value == 3:
            struct_base = get_operand_value(x_ref.frm - 0xF, 1)
            num_funcs = get_operand_value(x_ref.frm - 0x8, 1)
        else:
            continue
            # struct_base = get_operand_value(x_ref.frm - 0x7, 1)
            # num_funcs = get_operand_value(x_ref.frm - 0xD, 1)

        # print( "flag -> %d >> 地址 -> 0x%x >> 数量 -> %d"% (operand_value, struct_base, num_funcs))

        if 0 < num_funcs < 2000 and 1 < struct_base < 0xFFFFFFFFFFFFFFFF:
            # print( "x_ref ->%x >> flag -> %d >> 地址 -> 0x%x >> 数量 -> %d"% (x_ref.frm, operand_value, struct_base, num_funcs))
            for i in range(num_funcs):
                # print(struct_base)
                handle_lua_func(struct_base)
                struct_base += 0x10


if __name__ == "__main__":
    main()
