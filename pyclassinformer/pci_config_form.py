import ida_idaapi
import ida_kernwin


# --------------------------------------------------------------------------
class pci_form_t(ida_kernwin.Form):

    def __init__(self, dirtree=True, config=None):
        self.invert = False
        self.config = config
        F = ida_kernwin.Form
        F.__init__(
            self,
            r"""PyClassInformer Options

{FormChangeCb}

<##Search area##Only .rdata section:{rdata}> <##All data sections:{alldata}>{search_area}>

<##Actions##Display RTTI parsed results on the Output window:{rtti}>
<##Display extra analysis result (IDA 7.7 or later):{exana}>
<##Create folders for classes and move virtual methods to them in Functions and Names subviews (IDA 7.7 or later):{mvvm}>
<##Move functions refer vftables to "possible ctors or dtors" folder under each class folder in Functions and Names subviews (IDA 7.7 or later):{mvcd}>
<##Rename virtual methods:{rnvm}>
<##Rename possible constructors and destructors:{rncd}>
<##Improve decompilation by generating helper types, signatures and comments:{decomp}>{acts}>
<##Decompilation mode##Safe:{decomp_safe}> <Balanced:{decomp_balanced}> <Aggressive:{decomp_aggressive}>{decomp_mode}>
""", {
            'FormChangeCb': F.FormChangeCb(self.OnFormChange),
            'search_area': F.RadGroupControl(("rdata", "alldata")),
            'acts': F.ChkGroupControl(("rtti", "exana", "mvvm", "mvcd", "rnvm", "rncd", "decomp")),
            'decomp_mode': F.RadGroupControl(("decomp_safe", "decomp_balanced", "decomp_aggressive")),
        })
        
        self.dirtree = dirtree
        self.executed = False
        
        # Compile (in order to populate the controls)
        self.Compile()
        self.set_default_settings(config)
        
    def OnFormChange(self, fid):
        # set only once when it is called
        if not self.executed:
            self.change_dirtree_settings()
            self.executed = True
        return 1
        
    def change_dirtree_settings(self):
        if not self.dirtree:
            self.EnableField(self.exana, False)
            self.EnableField(self.mvvm, False)
            self.EnableField(self.mvcd, False)
            self.SetControlValue(self.exana, False)
            self.SetControlValue(self.mvvm, False)
            self.SetControlValue(self.mvcd, False)
        else:
            self.EnableField(self.exana, True)
            self.EnableField(self.mvvm, True)
            self.EnableField(self.mvcd, True)

    def set_default_settings(self, config=None):
        if config is None:
            config = self.config
        if config is None:
            import pyclassinformer.pci_config
            config = pyclassinformer.pci_config.pci_config()

        self.rdata.selected = not bool(getattr(config, "alldata", False))
        self.alldata.selected = bool(getattr(config, "alldata", False))
        self.rtti.checked = bool(getattr(config, "rtti", True))
        self.exana.checked = bool(getattr(config, "exana", True))
        self.mvvm.checked = bool(getattr(config, "mvvm", True))
        self.mvcd.checked = bool(getattr(config, "mvcd", True))
        self.rnvm.checked = bool(getattr(config, "rnvm", True))
        self.rncd.checked = bool(getattr(config, "rncd", True))
        self.decomp.checked = bool(getattr(config, "decomp", True))
        decomp_mode = getattr(config, "decomp_mode", "balanced")
        if decomp_mode == "safe":
            self.decomp_safe.selected = True
        elif decomp_mode == "aggressive":
            self.decomp_aggressive.selected = True
        else:
            self.decomp_balanced.selected = True
        
    @staticmethod
    def show():
        ida_idaapi.require("pyclassinformer")
        ida_idaapi.require("pyclassinformer.pci_config")
        pcic = pyclassinformer.pci_config.pci_config()
        f = pci_form_t(dirtree=pcic.dirtree, config=pcic)

        # Execute the form
        ok = f.Execute()
        if ok == 1:
            decomp_mode = "balanced"
            if f.decomp_safe.selected:
                decomp_mode = "safe"
            elif f.decomp_aggressive.selected:
                decomp_mode = "aggressive"
            pcic = pyclassinformer.pci_config.pci_config(alldata=f.alldata.selected, rtti=f.rtti.checked, exana=f.exana.checked, mvvm=f.mvvm.checked, mvcd=f.mvcd.checked, rnvm=f.rnvm.checked, rncd=f.rncd.checked, decomp=f.decomp.checked, decomp_mode=decomp_mode)
        else:
            return None

        # Dispose the form
        f.Free()
        return pcic

"""
ida_idaapi.require("pci_config")
pcic = pci_form_t.show()
if pcic is not None:
    print(pcic.alldata, pcic.exana, pcic.mvvm, pcic.mvcd, pcic.rnvm, pcic.rncd)
"""
