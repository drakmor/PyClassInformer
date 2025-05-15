import idc
import ida_kernwin
import ida_idaapi

ida_idaapi.require("pyclassinformer")
ida_idaapi.require("pyclassinformer.pci_utils")
u = pyclassinformer.pci_utils.utils()

class pci_chooser_t(ida_kernwin.Choose):

    def __init__(self, title, data, icon=-1, libcolor=0xffffffe9, defcolor=0xffffffff):
        ida_kernwin.Choose.__init__(
            self,
            title,
            [
                ["Vftable",   10 | ida_kernwin.Choose.CHCOL_EA],
                ["Methods",   4  | ida_kernwin.Choose.CHCOL_DEC],
                ["Flags",     4  | ida_kernwin.Choose.CHCOL_PLAIN],
                ["Type",      30 | ida_kernwin.Choose.CHCOL_PLAIN],
                ["Hierarchy", 50 | ida_kernwin.Choose.CHCOL_PLAIN],
                ["Offset",    4  | ida_kernwin.Choose.CHCOL_HEX],
                ["Hierarchy Order", 50  | ida_kernwin.Choose.CHCOL_PLAIN],
            ],
            flags=ida_kernwin.CH_MULTI|ida_kernwin.CH_ATTRS,
            icon=icon
        )
        self.items = [
            [
                hex(vftable_ea),
                "{}".format(len(data[vftable_ea].vfeas)),
                data[vftable_ea].chd.flags,
                data[vftable_ea].name,
                self.get_hierarychy(data, vftable_ea),
                hex(data[vftable_ea].offset),
                self.get_hierarychy_order(data, vftable_ea),
                data[vftable_ea].libflag,
                vftable_ea
            ] for vftable_ea in data
        ]
        self.libcolor = libcolor
        self.defcolor = defcolor
        self.libflag = data[next(iter(data))].LIBLIB
            
    def get_hierarychy(self, data, vftable_ea):
        col = data[vftable_ea]
        # get the actual base classes mainly for multiple inheritance
        bases = u.get_col_bases(col, data)
        
        result = "{}: ".format(col.name)
        if len(bases) > 0:
            # replace the class name with the first BCD's class name if they are different from each other.
            # it occurs when the class is multiple inheritance with multiple vftables
            i = 1
            if bases[0].name != col.name:
                result = "{}: ".format(bases[0].name)
                #i = 0

            # get the result related to the offset of the COL
            result += ", ".join([x.name for x in bases][i:]) + ";" if len(bases) > 1 else ""
        return result
        
    def get_hierarychy_order(self, data, vftable_ea):
        col = data[vftable_ea]
        result = []
        if len(col.chd.bca.bases) > 0:
            for off in col.chd.bca.paths:
                # output each path
                for p in col.chd.bca.paths[off]:
                    # get only the target COL related result
                    if col.offset == off:
                        result.append(" -> ".join([x.name + " ({},{},{})".format(x.mdisp, x.pdisp, x.vdisp) for x in p]))

        return ", ".join(result)
        
    def OnInit(self):
        return True

    def OnGetSize(self):
        return len(self.items)

    def OnGetLine(self, n):
        if isinstance(n, list):
            n = n[0]
        return self.items[n]
    
    # for old versions of IDA
    def OnSelectLine(self, n):
        # CH_MULTI passes a list.
        # Change it to integer before passing to jumpto.
        if isinstance(n, list):
            n = n[0]
        idc.jumpto(self.items[n][-1])
        return (ida_kernwin.Choose.NOTHING_CHANGED, )

    def OnGetEA(self, n):
        if isinstance(n, list):
            n = n[0]
        return self.items[n][-1]
    
    def OnGetLineAttr(self, n):
        # change the line color if a class is a part of static linked libraries
        vftable_ea = self.items[n][-1]
        color = self.defcolor
        if self.items[n][-2] == self.libflag:
            color = self.libcolor
        return (color, 0)


def show_pci_chooser_t(data, icon=-1, modal=False, libcolor=0xffffffe9, defcolor=0xffffffff):
    c = pci_chooser_t("[PyClassInformer]", data, icon, libcolor, defcolor)
    c.Show(modal=modal)

