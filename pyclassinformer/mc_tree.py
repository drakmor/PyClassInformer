import idc
import ida_kernwin
import ida_idaapi
import ida_dirtree
import ida_name
import idautils
import ida_funcs

ida_idaapi.require("pyclassinformer")
ida_idaapi.require("pyclassinformer.pci_utils")
ida_idaapi.require("pyclassinformer.dirtree_utils")

# dirspec for the dirtree
class my_dirspec_t(ida_dirtree.dirspec_t):
    def __init__(self, chooser):
        ida_dirtree.dirspec_t.__init__(self)
        self.chooser = chooser
        
        self.inodes = []
        self.name_index = {}

    def add_entry(self, dirpath, name):
        if (dirpath, name) not in self.inodes:
            new_inode = len(self.inodes)
            self.inodes.append((dirpath, name))
            self.name_index[dirpath, name] = new_inode
        # inode has already been inserted
        else:
            new_inode = -1
        return new_inode
    
    def update_parent_dir(self, inode, new_dirpath):
        # get old dir and node name by inode
        old_dirpath, name = self.get_name_idx(inode)
        
        # change dir entry to new one
        if old_dirpath != new_dirpath:
            del self.name_index[old_dirpath, name]
            self.name_index[new_dirpath, name] = inode
            self.inodes[inode] = (new_dirpath, name)

    def get_name_idx(self, inode):
        if inode >= 0 and inode < len(self.inodes):
            #print("get_name", self.inodes[inode])
            return self.inodes[inode]

    def get_name(self, inode, flags=0):
        return self.get_name_idx(inode)[1]

    def get_inode(self, dirpath, name):
        #print("get_inode", dirpath, name, self.name_index.get((dirpath, name), ida_dirtree.direntry_t.BADIDX))
        return self.name_index.get((dirpath, name), ida_dirtree.direntry_t.BADIDX)

    def n_inodes(self):
        return len(self.inodes)
    
    def rename_inode(self, inode, newname):
        #print("rename_inode", inode, newname)
        return ida_dirtree.dirspec_t.rename_inode(self, inode, newname)
    
    def get_attrs(self, inode):
        pass

    def unlink_inode(self, inode):
        pass


class mc_tree_t(ida_kernwin.Choose):

    def __init__(self, title, data, base_class_paths, icon=-1):
        self.dirspec = my_dirspec_t(self)
        self.dirtree = ida_dirtree.dirtree_t(self.dirspec)

        self.data = data
        self.base_class_paths = base_class_paths
        
        ida_kernwin.Choose.__init__(
            self,
            title,
            [
                ["EA",   15 | ida_kernwin.Choose.CHCOL_EA|ida_kernwin.CHCOL_FNAME],
                ["Name",   50  | ida_kernwin.Choose.CHCOL_PLAIN|ida_kernwin.Choose.CHCOL_INODENAME],
                ["Offset",     4  | ida_kernwin.Choose.CHCOL_HEX],
                ["CdOffset",   4 | ida_kernwin.Choose.CHCOL_HEX],
            ],
            flags=ida_kernwin.CH_TM_FULL_TREE|ida_kernwin.CH_NON_PERSISTED_TREE|ida_kernwin.CH_RENAME_IS_EDIT,
            icon=icon
        )
        self.items = []
            
    def process_data(self):
        for vftable_ea in self.data:
            col = self.data[vftable_ea]
            class_name = col.name
            
            # for creating a directory of a class name
            dirtree_path = "/" + class_name + "/" # needs the last slash for a directory
            self.dirtree.mkdir(dirtree_path)
            
            bc_path = self.base_class_paths[vftable_ea]
            if not bc_path:
                continue
            actual_class_name = bc_path[-1].name

            # for vftable folder
            dp = dirtree_path + "vftable/" # needs the last slash for a directory
            self.dirtree.mkdir(dp)
                
            # for vftable with COL info
            # get demangled name
            name = ida_name.get_short_name(vftable_ea)
            # add the actual class name information
            if class_name != actual_class_name:
                name += " for {} ({})".format(actual_class_name, col.offset)
            inode, r = self.add_item(dp, vftable_ea, name, col.offset, col.cdOffset)
            
            # for virtual methods folder
            dp = dirtree_path + "virtual methods/" # needs the last slash for a directory
            self.dirtree.mkdir(dp)
            
            # if the class has multiple vftables, create a nested folder
            col_offs = pyclassinformer.pci_utils.utils.get_col_offs(col, self.data)
            if len(col_offs) > 1:
                # if the class has multiple vftables, create a nested folder with the actual class name
                if class_name != actual_class_name:
                    dp += "virtual methods for {} ({})/".format(actual_class_name, col.offset) # needs the last slash for a directory
                else:
                    dp += "virtual methods/" # needs the last slash for a directory
                self.dirtree.mkdir(dp)
            
            # add virtual methods to the folder
            for vfea in col.vfeas:
                name = ida_name.get_short_name(vfea)
                inode, r = self.add_item(dp, vfea, name, ida_idaapi.BADADDR, ida_idaapi.BADADDR)
                
            # add functions that refer to vftable
            dp = dirtree_path + "possible ctors or dtors/" # needs the last slash for a directory
            self.dirtree.mkdir(dp)
            for refea in idautils.DataRefsTo(vftable_ea):
                f = ida_funcs.get_func(refea)
                if f:
                    name = ida_name.get_short_name(f.start_ea)
                    inode, r = self.add_item(dp, f.start_ea, name, ida_idaapi.BADADDR, ida_idaapi.BADADDR)
            
            # for hierarchy path
            for off in col.chd.bca.paths:
                for path in col.chd.bca.paths[off]:
                    dpath = [dirtree_path+"hierarchy"]
                    dp = "/".join(dpath)
                    self.dirtree.mkdir(dp + "/") # needs the last slash for a directory
                    for bcd in path:
                        # make directory for a BCD
                        dpath.append(bcd.name + " ({},{},{})".format(bcd.mdisp, bcd.pdisp, bcd.vdisp))
                        dp = "/".join(dpath)
                        self.dirtree.mkdir(dp + "/") # needs the last slash for a directory
                        
                        # IDA seems not to apply quick filter to directories.
                        # to avoid that, insert a text node as well if you want.
                        #name = bcd.name + " ({},{},{})".format(bcd.mdisp, bcd.pdisp, bcd.vdisp)
                        #inode, r = self.add_item(dp, bcd.ea, name, ida_idaapi.BADADDR, ida_idaapi.BADADDR)
                        #print(dp, name, inode, r, self.dirtree.getcwd(), len(self.items), self.dirspec.n_inodes())
                        
    def add_item(self, dirtree_path, ea, name, offset, cdoffset):
        r = -1
        inode = self.dirspec.add_entry(dirtree_path, name)
        if inode >= 0:
            self.items.append([hex(ea) if ea != ida_idaapi.BADADDR else "", name, hex(offset) if offset != ida_idaapi.BADADDR else "", hex(cdoffset) if cdoffset != ida_idaapi.BADADDR else "", ea])
            self.dirtree.chdir(dirtree_path)
            r = self.dirtree.link(inode)
        return inode, r
    
    def OnInit(self):
        self.process_data()
        return True

    def OnGetSize(self):
        return self.dirspec.n_inodes()

    def OnGetLine(self, n):
        #inode = self.OnIndexToInode(n)
        return self.items[n]
        
    # for old versions of IDA
    def OnSelectLine(self, n):
        idc.jumpto(self.items[n][-1])
        return (ida_kernwin.Choose.NOTHING_CHANGED, )

    def OnGetEA(self, n):
        return self.items[n][-1]
    
    def OnInsertLine(self, sel):
        #print("OnInsertLine", sel)
        pass

    def OnDeleteLine(self, sel):
        #print("OnDeleteLine", sel)
        pass

    def OnEditLine(self, sel):
        #print("OnEditLine", sel)
        pass
        
    def OnSelectionChange(self, sel):
        # get inode and get the current dir and the cached entry
        inode = self.OnIndexToInode(sel)
        curr_dir, name = self.dirspec.get_name_idx(inode)
        abs_path = pyclassinformer.dirtree_utils.get_abs_path_by_inode(self.dirtree, inode)
        parent_dir = pyclassinformer.dirtree_utils.get_parent_dir_by_inode(self.dirtree, inode) + "/" # add slash at the end
        
        # need to update the directory in the cached inodes if the current dir and the parent dir of the selection are not matched.
        #print("OnSelectionChange", sel, inode, curr_dir, name, abs_path, parent_dir)
        if parent_dir != curr_dir:
            #print("update the parent dir {} to {} for {} ({})".format(curr_dir, parent_dir, name, inode))
            self.dirspec.update_parent_dir(inode, parent_dir)

    def OnRefresh(self, sel):
        #print("OnRefresh", sel)
        pass

    def OnGetDirTree(self):
        return self.dirspec, self.dirtree

    def OnIndexToInode(self, n):
        return n


def show_mc_tree_t(data, paths, icon=-1, modal=False):
    tree = mc_tree_t("[MethodClassifier]", data, paths, icon)
    tree.Show(modal=modal)
    return tree

