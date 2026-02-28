import ida_funcs
import ida_idaapi

ida_idaapi.require("pyclassinformer")
ida_idaapi.require("pyclassinformer.qtutils")

def get_libfunc():
    for n in range(ida_funcs.get_func_qty()):
        f = ida_funcs.getn_func(n)
        if f is None:
            continue
        if f.flags & ida_funcs.FUNC_LIB:
            return f
    return None

def get_genfunc():
    for n in range(ida_funcs.get_func_qty()):
        f = ida_funcs.getn_func(n)
        if f is None:
            continue
        if not f.flags & ida_funcs.FUNC_LIB and not f.flags & ida_funcs.FUNC_LUMINA and not f.flags & ida_funcs.FUNC_THUNK:
            return f
    return None

def get_default_func_colors():
    gen_func_color = 0xffffffff
    lib_func_color = 0xffffffe9

    dark = False
    try:
        dark = pyclassinformer.qtutils.dark_mode_checker_t.is_dark_mode()
    except Exception:
        pass

    if dark:
        lib_func_color = 0xff685328

    return gen_func_color, lib_func_color

def get_gen_lib_func_colors():
    return get_default_func_colors()

#print([hex(x) for x in get_gen_lib_func_colors()])
