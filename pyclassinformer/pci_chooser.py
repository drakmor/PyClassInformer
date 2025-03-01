import idc
import ida_kernwin
import ida_idaapi

ida_idaapi.require("pci_utils")
u = pci_utils.utils()

class pci_chooser_t(ida_kernwin.Choose):

    def __init__(self, title, data, icon=-1):
        ida_kernwin.Choose.__init__(
            self,
            title,
            [
                ["Vftable",   10 | ida_kernwin.Choose.CHCOL_HEX],
                ["Methods",   4  | ida_kernwin.Choose.CHCOL_DEC],
                ["Flags",     4  | ida_kernwin.Choose.CHCOL_PLAIN],
                ["Type",      30 | ida_kernwin.Choose.CHCOL_PLAIN],
                ["Hierarchy", 50 | ida_kernwin.Choose.CHCOL_PLAIN],
                ["Offset",    4  | ida_kernwin.Choose.CHCOL_HEX],
                ["Hierarchy Order", 50  | ida_kernwin.Choose.CHCOL_PLAIN],
            ],
            flags=ida_kernwin.CH_MULTI,
            icon=icon
        )
        self.items = [
            [
                hex(vftable_ea),
                "{}".format(len([x for x in pci_utils.get_vtbl_methods(vftable_ea)])),
                data[vftable_ea].chd.flags,
                data[vftable_ea].name,
                self.get_hierarychy(data, vftable_ea),
                hex(data[vftable_ea].offset),
                self.get_hierarychy_order(data, vftable_ea),
                vftable_ea
            ] for vftable_ea in data
        ]
            
    def get_hierarychy(self, data, vftable_ea):
        col = data[vftable_ea]
        col_offs, curr_off = u.get_col_offs(col, data)
        result = "{}: ".format(col.name)
        if len(col.chd.bca.bases) > 0:
            idx = 0
            if col.chd.bca.bases[0].name == col.name:
                idx = 1
            # get the result related to the offset of the COL
            result += ", ".join([x.name for x in col.chd.bca.bases[idx:] if u.does_bcd_append(col_offs, x, curr_off)]) + ";" if len(col.chd.bca.bases) > 1 else ""
        return result
        
    def get_hierarychy_order(self, data, vftable_ea):
        col = data[vftable_ea]
        col_offs, curr_off = u.get_col_offs(col, data)
        result = []
        if len(col.chd.bca.bases) > 0:
            for off in col.chd.bca.paths:
                target_off = off
                if off not in col_offs:
                    # sometimes, mdisp is not included in COLs.
                    # in those cases, get the least offset in COLs and it is treated as the offset.
                    target_off = 0
                    if len(col_offs) > 0:
                        target_off = sorted(col_offs)[0]
                for p in col.chd.bca.paths[off]:
                    #if curr_off == target_off or col.chd.flags.find("V") >= 0 or len(list(filter(lambda x: x.pdisp >= 0, p))) > 0:
                    if curr_off == target_off:
                        result.append("{:#x}: ".format(off) + " -> ".join([x.name + " ({},{},{})".format(x.mdisp, x.pdisp, x.vdisp) for x in p]))

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
    

def show_pci_chooser_t(data, icon=-1, modal=False):
    c = pci_chooser_t("[PyClassInformer]", data, icon)
    c.Show(modal=modal)

