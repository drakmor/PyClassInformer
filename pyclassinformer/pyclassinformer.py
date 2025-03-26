import ida_idaapi
import ida_kernwin

ida_idaapi.require("pyclassinformer")
ida_idaapi.require("pyclassinformer.msvc_rtti")
ida_idaapi.require("pyclassinformer.pci_config")
ida_idaapi.require("pyclassinformer.pci_chooser")
ida_idaapi.require("pyclassinformer.method_classifier")
ida_idaapi.require("pyclassinformer.lib_classes_checker")
ida_idaapi.require("pyclassinformer.get_func_colors")

def run_pci(config=None, icon=-1):
    print("Starting PyClassInformer")
    if config is None:
        config = pyclassinformer.pci_config.pci_config()
    
    # find vftables with relevant structures
    result = pyclassinformer.msvc_rtti.rtti_parser.run(alldata=config.alldata, icon=-1)
    
    # show results
    tree = None
    if result:
        if config.rtti:
            pyclassinformer.msvc_rtti.rtti_parser.show(result)
        pyclassinformer.lib_classes_checker.set_libflag(result)
        gen_func_color, lib_func_color = pyclassinformer.get_func_colors.get_gen_lib_func_colors()
        pyclassinformer.pci_chooser.show_pci_chooser_t(result, icon=icon, libcolor=lib_func_color, defcolor=gen_func_color)
        tree = pyclassinformer.method_classifier.method_classifier(result, config=config, icon=icon)
        
        # dock the tree to next to functions
        if tree:
            # On ida 9.0, if the tree wdiget is directly docked in the same tab,
            # the Functions subview will freeze. I think it is a bug.
            # To avoid it, once create it as a floating widget, then dock it to
            # the Functions subview.
            ida_kernwin.set_dock_pos(tree.title, None, ida_kernwin.DP_FLOATING)
            ida_kernwin.set_dock_pos(tree.title, 'Functions', ida_kernwin.DP_TAB)
    else:
        print("Nothing found. RTTI might be disabled or it is not a Windows C++ program.")
    print("Done")
    
    return tree


def main():
    run_pci()

if __name__ == '__main__':
    main()
