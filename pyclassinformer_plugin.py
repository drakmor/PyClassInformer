import ida_idaapi
import ida_kernwin

import os
import sys

dirpath = os.path.dirname(os.path.abspath(__file__))
script_dir = os.path.join(dirpath, "pyclassinformer")
if not os.path.isdir(script_dir):
    script_dir = os.path.join(dirpath, "..", "pyclassinformer")

ida_idaapi.require("pyclassinformer")
ida_idaapi.require("pyclassinformer.qtutils")

# for IDA 7.4 or earlier
try:
    g_flags = ida_idaapi.PLUGIN_MULTI
except AttributeError:
    g_flags = ida_idaapi.PLUGIN_DRAW

# for IDA 7.4 or earlier
try:
    g_obj = ida_idaapi.plugmod_t
except AttributeError:
    g_obj = object

g_plugmod_flag = False
if g_flags != ida_idaapi.PLUGIN_DRAW and g_obj != object:
    g_plugmod_flag = True

class pci_plugin_t(ida_idaapi.plugin_t):
    flags = g_flags
    comment = "Yet Another RTTI Parser"
    wanted_name = "PyClassInformer"
    wanted_hotkey = "Alt-Shift-L"
    help = "Press '" + wanted_hotkey + "' to display the " + wanted_name + " result."
    
    toolbar_displayed_name = wanted_name
    toolbar_name = toolbar_displayed_name + 'Toolbar'
    
    action_name = "pyclassinformer:execute"
    menu_path = "Edit/Plugins/"
    
    icon_data = open(os.path.join(script_dir, "pci_icon.png"), "rb").read()
    act_icon = ida_kernwin.load_custom_icon(data=icon_data, format="png")
    
    class exec_pci_action(ida_kernwin.action_handler_t):
        def __init__(self, plugin):
            ida_kernwin.action_handler_t.__init__(self)
            import weakref
            self.v = weakref.ref(plugin)
        
        def activate(self, ctx):
            self.v().plugin_mod.run(None)
            
        def update(self, ctx):
            return ida_kernwin.AST_ENABLE_ALWAYS
        
    def attach_to_menu_and_toolbar(self):
        # insert the action
        ida_kernwin.register_action(
            ida_kernwin.action_desc_t(
            self.action_name,
            self.comment,
            self.exec_pci_action(self),
            None,
            self.wanted_name,
            self.act_icon))
        
        # attach the action to menu
        ida_kernwin.attach_action_to_menu(
            self.menu_path,
            self.action_name,
            ida_kernwin.SETMENU_APP)

        # create the toolbar and attach the action to the toolbar
        ida_kernwin.create_toolbar(self.toolbar_name, self.toolbar_displayed_name)
        ida_kernwin.attach_action_to_toolbar(self.toolbar_name, self.action_name)
        
        # install ui hook to enable toolbar later
        self.ph = pyclassinformer.qtutils.enable_toolbar_t(self.toolbar_name)
        
    @staticmethod
    class register_icon(ida_kernwin.UI_Hooks):
        def updated_actions(self):
            if ida_kernwin.update_action_icon(pci_plugin_t.menu_path + pci_plugin_t.wanted_name, pci_plugin_t.act_icon):
                # unhook this if it's successful
                self.unhook()

    def init(self):
        ida_kernwin.msg("############### %s (%s) ###############%s" % (self.wanted_name, self.comment, os.linesep))
        ida_kernwin.msg("%s%s" % (self.help, os.linesep))

        # attach action to menu and toolbar
        self.attach_to_menu_and_toolbar()
        
        r = self.flags
        self.plugin_mod = pci_plugmod_t()
        if g_plugmod_flag:
            r = self.plugin_mod
        return r
    
    # for old IDA til 7.6
    def run(self, arg):
        self.plugin_mod.run(arg)
        
    # for old IDA til 7.6
    def term(self):
        self.plugin_mod.term()
        

class pci_plugmod_t(g_obj):
    toolbar_name = pci_plugin_t.toolbar_name
    menu_path = pci_plugin_t.menu_path
    action_name = pci_plugin_t.action_name
    act_icon = pci_plugin_t.act_icon
    
    def __del__(self):
        self.term()
        
    def run(self, arg):
        pci_plugmod_t.run_pci(icon=self.act_icon)
        
    def term(self):
        self.detatch_from_menu_and_toolbar()
        
    def detatch_from_menu_and_toolbar(self):
        ida_kernwin.detach_action_from_toolbar(self.toolbar_name, self.action_name)
        ida_kernwin.delete_toolbar(self.toolbar_name)
        ida_kernwin.detach_action_from_menu(self.menu_path, self.action_name)
        ida_kernwin.free_custom_icon(self.act_icon)
        ida_kernwin.unregister_action(self.action_name)
        
    @staticmethod
    def run_pci(icon=-1):
        ida_idaapi.require("pyclassinformer.pci_config_form")
        config = pyclassinformer.pci_config_form.pci_form_t.show()
        if config is not None:
            ida_idaapi.require("pyclassinformer.pyclassinformer")
            pyclassinformer.pyclassinformer.run_pci(config=config, icon=icon)
        else:
            print("PyClassInformer: Canceled")


def PLUGIN_ENTRY():
    return pci_plugin_t()


# install a UI hook to add icon in the plugin menu
ri = pci_plugin_t.register_icon()
ri.hook()
