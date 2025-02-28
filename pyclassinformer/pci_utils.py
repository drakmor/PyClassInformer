import struct

import idc
import idautils
import ida_bytes
import ida_search
import ida_idaapi
import ida_segment
import ida_xref
import ida_typeinf
import ida_nalt
import ida_offset
import ida_name
import ida_ida

try:
    from ida_struct import get_member_by_name
except ModuleNotFoundError:
    # for IDA 9.0
    def get_member_by_name(tif, name):
        if not tif.is_struct():
            return None
    
        udm = ida_typeinf.udm_t()
        udm.name = name
        idx = tif.find_udm(udm, ida_typeinf.STRMEM_NAME)
        if idx != -1:
            return udm
        return None


class utils(object):
    text = 0
    data = 0
    rdata = 0
    valid_ranges = []
    within = lambda self, x, rl: any([True for r in rl if r[0]<=x<=r[1]])

    REF_OFF = 0
    x64 = 0
    PTR_TYPE = 0
    PTR_SIZE = 0

    def __init__(self):
        self.text = ida_segment.get_segm_by_name(".text")
        self.data = ida_segment.get_segm_by_name(".data")
        self.rdata = ida_segment.get_segm_by_name(".rdata")
        # try to use rdata if there actually is an rdata segment, otherwise just use data
        if self.rdata is not None:
            self.valid_ranges = [(self.rdata.start_ea, self.rdata.end_ea), (self.data.start_ea, self.data.end_ea)]
        else:
            self.valid_ranges = [(self.data.start_ea, self.data.end_ea)]

        self.x64 = (ida_segment.getnseg(0).bitness == 2)
        if self.x64:
            self.PTR_TYPE = ida_bytes.FF_QWORD
            self.REF_OFF = ida_nalt.REF_OFF64
            self.PTR_SIZE = 8
            self.get_ptr = ida_bytes.get_64bit
        else:
            self.PTR_TYPE = ida_bytes.FF_DWORD
            self.REF_OFF = ida_nalt.REF_OFF32
            self.PTR_SIZE = 4
            self.get_ptr = ida_bytes.get_32bit

    # for 32-bit binaries, the RTTI structs contain absolute addresses, but for
    # 64-bit binaries, they're offsets from the image base.
    def x64_imagebase(self):
        if self.x64:
            return ida_nalt.get_imagebase()
        else:
            return 0

    def mt_rva(self):
        ri = ida_nalt.refinfo_t()
        ri.flags = self.REF_OFF|ida_nalt.REFINFO_RVAOFF
        ri.target = 0
        mt = ida_nalt.opinfo_t()
        mt.ri = ri
        return mt

    def mt_address(self):
        ri = ida_nalt.refinfo_t()
        ri.flags = self.REF_OFF
        ri.target = 0
        mt = ida_nalt.opinfo_t()
        mt.ri = ri
        return mt

    def mt_ascii(self):
        ri = ida_nalt.refinfo_t()
        ri.flags = ida_nalt.STRTYPE_C
        ri.target = -1
        mt = ida_nalt.opinfo_t()
        mt.ri = ri
        return mt

    def get_strlen(self, addr, max_len=500):
        # 50 is sometimes too short. I increased a number here.
        strlen = 0
        #while get_byte(addr+strlen) != 0x0 and strlen < 50:
        while ida_bytes.get_byte(addr+strlen) != 0x0 and strlen < max_len:
            strlen+=1
        #assume no names will ever be longer than 50 bytes
        #if strlen == 50:
        if strlen == max_len:
            return None
        return strlen

    def is_vtable(self, addr):
        function = self.get_ptr(addr)
        # Check if vtable has ref and its first pointer lies within code segment
        if ida_bytes.has_xref(ida_bytes.get_full_flags(addr)) and function >= self.text.start_ea and function <= self.text.end_ea:
            return True
        return False

    @staticmethod
    def to_signed32(n):
        n = n & 0xffffffff
        return n | (-(n & 0x80000000))

    @staticmethod
    def get_refs_to(ea):
        for xref in idautils.XrefsTo(ea, 0):
            yield xref.frm

    @staticmethod
    def get_refs_to_by_type_name(name):
        tif = ida_typeinf.tinfo_t()
        if tif.get_named_type(None, name, ida_typeinf.BTF_STRUCT):
            for xref in utils.get_refs_to(tif.get_tid()):
                yield xref
                
    def add_ptr_or_rva_member(self, sid, name):
        if self.x64:
            idc.add_struc_member(sid, name, ida_idaapi.BADADDR, ida_bytes.FF_DATA|ida_bytes.FF_DWORD|ida_bytes.FF_0OFF, self.mt_rva().tid, 4, reftype=ida_nalt.REFINFO_RVAOFF|self.REF_OFF)
        else:
            idc.add_struc_member(sid, name, ida_idaapi.BADADDR, ida_bytes.FF_DATA|ida_bytes.FF_DWORD|ida_bytes.FF_0OFF, self.mt_address().tid, 4)
        
    @staticmethod
    def get_moff_by_name(struc, name):
        try:
            offset = get_member_by_name(struc, name).soff
        except AttributeError:
            # for ida 9.0
            offset = get_member_by_name(struc, name).offset // 8
        return offset
        
    @staticmethod
    def does_bcd_append(col_offs, bcd, curr_off):
        append = False
        # for single inheritance
        if len(col_offs) <= 1:
            append = True
        # for multiple inheritance
        elif bcd.mdisp in col_offs:
            if bcd.mdisp == curr_off:
                append = True
        # for items that are not matched with COL offsets
        # they are treated as a part of COL offset 0
        elif curr_off == 0:
            append = True
        return append
        
    @staticmethod
    def get_col_offs(col, vftables):
        # get offsets in COLs by finding xrefs for multiple inheritance
        x = set([xrea for xrea in utils.get_refs_to(col.tdea)])
        y = set([xrea for xrea in utils.get_refs_to(col.tid)])
        # If the target is a multi inheritance class, TD or CHD has multiple xrefs from multiple COLs.
        # Here, get the COLs
        coleas = (x&y)
        cols = list(filter(lambda x: x.ea in coleas, vftables.values()))
        # get the offsets in COLs
        col_offs = [ida_bytes.get_32bit(x.ea+utils.get_moff_by_name(x.struc, "offset")) for x in cols]
        curr_off = col.offset
        return col_offs, curr_off


def add_struc_by_name_and_def(name, struc_def):
    tif = ida_typeinf.tinfo_t(struc_def)
    tif.set_named_type(None, name, ida_typeinf.NTF_REPLACE)
    return tif


def build_udm(name, msize=0, mtype=ida_typeinf.BTF_INT, moffset=-1, vrepr=None):
    # create a struct member
    udm = ida_typeinf.udm_t()
    udm.name = name
    if msize > 0:
        udm.size = msize * 8
        
    udm.offset = tif.get_unpadded_size() * 8
    if moffset >= 0:
        udm.offset = moffset * 8
        
    udm.type = ida_typeinf.tinfo_t(mtype)
    
    if vrepr:
        udm.set_value_repr(vrepr)
        
    return udm

def add_struc(name):
    tif = ida_typeinf.tinfo_t()
    udt = ida_typeinf.udt_type_data_t()
    # add the structure to local types
    if tif.create_udt(udt):
        tif.set_named_type(None, name)
    return tif


def add_struc_member(tif, name, msize=0, mtype=None, moffset=-1, vrepr=None):
    udm = build_udm(name, msize, mtype, moffset, vrepr)
    tif.add_udm(udm, ida_typeinf.ETF_MAY_DESTROY|ida_typeinf.ETF_FORCENAME)
    return udm


def create_ptr_attr(data_type=ida_typeinf.BTF_INT, attr=ida_typeinf.TAPTR_PTR32):
    # pointer description
    pi = ida_typeinf.ptr_type_data_t()
    pi.obj_type = ida_typeinf.tinfo_t(data_type)
    pi.taptr_bits = attr
    # pointer type
    mtif = ida_typeinf.tinfo_t()
    mtif.create_ptr(pi)
    return mtif


def get_ptr_type(type_name, ptr_size=ida_typeinf.TAPTR_PTR32):
    mtif = ida_typeinf.tinfo_t()
    if mtif.get_named_type(None, type_name):
        mtif = create_ptr_attr(ida_typeinf.BTF_INT, ptr_size)
        return mtif
    return None


"""
def get_refinfo(reftype=ida_nalt.REF_OFF64, flags=ida_nalt.REFINFO_RVAOFF):
    ri = ida_nalt.refinfo_t()
    ri.flags = flags
    ri.target = 0
    ri.set_type(reftype)
    return ri


def get_offset_refinfo(reftype=ida_nalt.REF_OFF64, flags=ida_nalt.REFINFO_RVAOFF):
    ri = get_refinfo(reftype, flags)
    vr = ida_typeinf.value_repr_t()
    vr.set_vtype(ida_typeinf.FRB_OFFSET)
    vr.ri = ri
    return vr


def set_opinfo(tif, udt, udt_idx):
    oi = ida_nalt.opinfo_t()
    oi.ri = get_refinfo(reftype=ida_nalt.REF_OFF64, flags=ida_nalt.REFINFO_RVAOFF)
    mtif = create_ptr_attr(ida_typeinf.BTF_INT, ida_typeinf.TAPTR_PTR32)
    flags = ida_bytes.off_flag()
    # Apply the offset and RVA attributes to udm target.
    udt[udt_idx].repr.from_opinfo(flags, 0, oi, None)
    tif.set_udm_repr(udt_idx, udt[udt_idx].repr)
    tif.set_udm_type(udt_idx, mtif)
"""


def get_val_repr(vtype=-1, flags=ida_nalt.REF_OFF64|ida_nalt.REFINFO_RVAOFF):
    if vtype < 0:
        vtype = ida_typeinf.FRB_OFFSET
    r = ida_typeinf.value_repr_t()
    r.set_vtype(vtype)
    r.ri.init(flags)
    return r


"""
struc_def = '''
struct RTTICompleteObjectLocator
{
  int signature;
  int offset;
  int cdOffset;
  int pTypeDescriptor;
  int pClassDescriptor;
  int pSelf;
};
'''
name = "RTTICompleteObjectLocator"
tif = add_struc_by_name_and_def(name, struc_def)

r = get_val_repr(ida_typeinf.FRB_OFFSET, ida_nalt.REF_OFF64|ida_nalt.REFINFO_RVAOFF)
mtif = create_ptr_attr(ida_typeinf.BTF_INT, ida_typeinf.TAPTR_PTR32)
for i in range(3, 6):
    tif.set_udm_type(i, mtif, 0, r)
ida_typeinf.apply_tinfo(here(), tif, ida_typeinf.TINFO_DEFINITE)
"""


def get_value_with_size(val, vsize):
    off_v = ida_idaapi.BADADDR
    if vsize == 8:
        off_v = ida_bytes.get_qword(val)
    elif vsize == 4:
        off_v = ida_bytes.get_dword(val)
    elif vsize == 2:
        off_v = ida_bytes.get_word(val)
    elif vsize == 1:
        off_v = ida_bytes.get_byte(val)
    return off_v


def get_offset_ptr(v, force_bitness=False):
    target_ea = ida_idaapi.BADADDR
    if v == ida_idaapi.BADADDR:
        return target_ea
    flags = ida_bytes.get_full_flags(v)
    if not force_bitness and ida_bytes.is_qword(flags):
        target_ea = get_value_with_size(v, 8)
    elif not force_bitness and ida_bytes.is_dword(flags):
        target_ea = get_value_with_size(v, 4)
    else:
        seg = ida_segment.getseg(v)
        if seg is None:
            return target_ea
        off_size = 1<<(seg.bitness+1)
        target_ea = get_value_with_size(v, off_size)
    return target_ea


def get_offset_fptr(v, force_bitness=False):
    target_ea = ida_idaapi.BADADDR
    tmp_ea = get_offset_ptr(v, force_bitness)
    flags = ida_bytes.get_full_flags(tmp_ea)
    if ida_bytes.is_code(flags):
        target_ea = tmp_ea
    return target_ea


def get_vtbl_methods(target_ea):
    orig_target_ea = target_ea
    prev_target_ea = target_ea
    item_diff = 8
    seg = ida_segment.getseg(target_ea)
    next_name_ea = ida_ida.inf_get_max_ea()
    if seg:
        item_diff = 1<<(seg.bitness+1)
        # get next label that has a xref
        next_name_ea = ida_bytes.next_that(target_ea, seg.end_ea, ida_bytes.has_xref)
        if next_name_ea == ida_idaapi.BADADDR:
            next_name_ea = seg.end_ea
    
    ea = get_offset_fptr(target_ea, force_bitness=True)
    while target_ea != ida_idaapi.BADADDR and target_ea < next_name_ea and ea != ida_idaapi.BADADDR:
        flags = ida_bytes.get_full_flags(ea)
        if ida_bytes.is_code(flags):
            yield ea
        else:
            break
        
        prev_target_ea = target_ea
        target_ea = ida_search.find_data(target_ea, ida_search.SEARCH_DOWN|ida_search.SEARCH_NEXT)
        if target_ea - prev_target_ea != item_diff:
            break
        ea = get_offset_fptr(target_ea, force_bitness=True)

