try:
    ModuleNotFoundError
except NameError:
    ModuleNotFoundError = ImportError

class pci_config(object):
    
    alldata = False
    rtti = True
    exana = True
    mvvm = True
    mvcd = True
    rnvm = True
    rncd = True
    decomp = True
    decomp_mode = "balanced"
    dirtree = True
    
    def __init__(self, alldata=None, rtti=None, exana=None, mvvm=None, mvcd=None, rnvm=None, rncd=None, decomp=None, decomp_mode=None):
        cls = type(self)
        if alldata is None:
            alldata = cls.alldata
        if rtti is None:
            rtti = cls.rtti
        if exana is None:
            exana = cls.exana
        if mvvm is None:
            mvvm = cls.mvvm
        if mvcd is None:
            mvcd = cls.mvcd
        if rnvm is None:
            rnvm = cls.rnvm
        if rncd is None:
            rncd = cls.rncd
        if decomp is None:
            decomp = cls.decomp
        if decomp_mode is None:
            decomp_mode = cls.decomp_mode

        self.alldata = alldata
        self.rtti = rtti
        self.exana = exana
        self.mvvm = mvvm
        self.mvcd = mvcd
        self.rnvm = rnvm
        self.rncd = rncd
        self.decomp = decomp
        if decomp_mode not in ("safe", "balanced", "aggressive"):
            decomp_mode = "balanced"
        self.decomp_mode = decomp_mode
        self.check_dirtree()
        self.remember()
        
    def check_dirtree(self):
        try:
            import ida_dirtree
            ida_dirtree.dirtree_t.find_entry
        # for IDA 7.x
        except (ModuleNotFoundError, AttributeError) as e:
            self.exana = False
            self.mvvm = False
            self.mvcd = False
            self.dirtree = False

    def remember(self):
        cls = type(self)
        cls.alldata = self.alldata
        cls.rtti = self.rtti
        cls.exana = self.exana
        cls.mvvm = self.mvvm
        cls.mvcd = self.mvcd
        cls.rnvm = self.rnvm
        cls.rncd = self.rncd
        cls.decomp = self.decomp
        cls.decomp_mode = self.decomp_mode
        cls.dirtree = self.dirtree
