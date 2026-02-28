import binascii
import re
import idc
import ida_bytes
import ida_idaapi
import ida_funcs
import ida_nalt
import ida_typeinf
import ida_idp
import ida_name
import ida_ua
import idautils

try:
    ModuleNotFoundError
except NameError:
    ModuleNotFoundError = ImportError

tree_categorize = True
try:
    import ida_dirtree
    ida_dirtree.dirtree_t.find_entry
# For IDA 7.4 and 7.5
except ModuleNotFoundError:
    tree_categorize = False
# For IDA 7.6
except AttributeError:
    tree_categorize = False

ida_idaapi.require("pyclassinformer")
ida_idaapi.require("pyclassinformer.pci_utils")
ida_idaapi.require("pyclassinformer.pci_config")
u = pyclassinformer.pci_utils.utils()
if tree_categorize:
    ida_idaapi.require("pyclassinformer.mc_tree")
    ida_idaapi.require("pyclassinformer.dirtree_utils")

try:
    import ida_hexrays
except Exception:
    ida_hexrays = None

hexrays_initialized = False

AUTO_RENAME_PREFIXES = ("sub_", "unknown_", "nullsub_", "j_", "thunk_")
AUTO_GENERATED_NAMES = ("virtual_method_", "possible_ctor_or_dtor", "possible_constructor", "possible_destructor", "destructor", "scalar_deleting_destructor", "vector_deleting_destructor")
CTOR_DTOR_REF_MNEMS = set(["mov", "lea", "adr", "adrp", "add", "str", "stp"])
THUNK_BRANCH_MNEMS = set(["jmp", "b", "bra"])
CALL_MNEMS = set(["call", "bl", "blx", "blr"])
DELETE_CALLEE_HINTS = ("??3", "operator delete", "__imp_??3", " free", "_free", "j_j_free", " delete")
ALLOC_CALLEE_HINTS = ("??2", "operator new", "malloc", "calloc", "realloc", "HeapAlloc")
TYPE_PREFIX = "pci__"
COMMENT_TAG = "PyClassInformer"
AUTO_LOCAL_PTR_RE = re.compile(r"^(v\d+|ptr|p|obj|object|result)$", re.IGNORECASE)
THIS_REG_NAMES = ("ecx", "rcx", "r0", "x0")


def is_auto_named(func_name):
    if not func_name:
        return False
    leaf = func_name.split("::")[-1]
    return leaf.startswith(AUTO_RENAME_PREFIXES + AUTO_GENERATED_NAMES)


def normalize_identifier(text, fallback="item", max_len=64):
    cleaned = []
    for ch in text:
        if ch.isalnum() or ch == "_":
            cleaned.append(ch)
        else:
            cleaned.append("_")

    result = "".join(cleaned).strip("_")
    while "__" in result:
        result = result.replace("__", "_")
    if not result:
        result = fallback
    if result[0].isdigit():
        result = "_" + result
    return result[:max_len]


def build_generated_type_name(kind, class_name, offset=None):
    suffix = kind
    if offset is not None:
        suffix = "%s_%x" % (kind, offset & 0xffffffff)
    raw = "%s__%s" % (suffix, class_name)
    digest = binascii.crc32(raw.encode("utf-8")) & 0xffffffff
    safe = normalize_identifier(raw, fallback=kind, max_len=72)
    return "%s%s_%08x" % (TYPE_PREFIX, safe, digest)


def ensure_generated_struct(type_name):
    sid = idc.get_struc_id(type_name)
    if sid == ida_idaapi.BADADDR:
        sid = idc.add_struc(0xFFFFFFFF, type_name, False)
    return sid


def add_generated_ptr_member(sid, member_name, offset, target_type_name=None):
    try:
        existing_off = idc.get_member_offset(sid, member_name)
    except Exception:
        existing_off = ida_idaapi.BADADDR

    if existing_off != ida_idaapi.BADADDR:
        if target_type_name:
            u.set_ptr_member(sid, member_name, target_type_name)
        return 0

    r = idc.add_struc_member(sid, member_name, offset, ida_bytes.FF_DATA | u.PTR_TYPE, -1, u.PTR_SIZE)
    if r == 0 and target_type_name:
        u.set_ptr_member(sid, member_name, target_type_name)
    return r


def ensure_generated_member(sid, member_name, offset):
    try:
        existing_off = idc.get_member_offset(sid, member_name)
    except Exception:
        existing_off = ida_idaapi.BADADDR
    if existing_off != ida_idaapi.BADADDR:
        return 0
    return idc.add_struc_member(sid, member_name, offset, ida_bytes.FF_DATA | u.PTR_TYPE, -1, u.PTR_SIZE)


def ensure_generated_byte_member(sid, member_name, offset, size):
    if size <= 0:
        return 0

    try:
        existing_off = idc.get_member_offset(sid, member_name)
    except Exception:
        existing_off = ida_idaapi.BADADDR

    if existing_off != ida_idaapi.BADADDR:
        return 0
    return idc.add_struc_member(sid, member_name, offset, ida_bytes.FF_DATA | ida_bytes.FF_BYTE, -1, size)


def append_comment(ea, text, repeatable=1):
    current = idc.get_cmt(ea, repeatable) or ""
    if text in current:
        return
    if current:
        text = current + " | " + text
    idc.set_cmt(ea, text, repeatable)


def initialize_hexrays():
    global hexrays_initialized
    if ida_hexrays is None:
        return False
    if hexrays_initialized:
        return True
    try:
        hexrays_initialized = bool(ida_hexrays.init_hexrays_plugin())
    except Exception:
        hexrays_initialized = False
    return hexrays_initialized


def refresh_hexrays_function(func_ea):
    if not initialize_hexrays():
        return False

    try:
        ida_hexrays.mark_cfunc_dirty(func_ea, False)
    except Exception:
        pass

    try:
        cfunc = ida_hexrays.decompile(func_ea)
    except Exception:
        return False
    return cfunc is not None


def parse_decl_tinfo(decl):
    tif = ida_typeinf.tinfo_t()
    flags = getattr(ida_typeinf, "PT_SIL", 0)
    candidates = [decl]
    stripped = decl.strip()
    if stripped.endswith(";") and "(*" not in stripped and "(" not in stripped:
        candidates.append("%s __pci_tmp;" % stripped[:-1].rstrip())

    for candidate in candidates:
        try:
            if ida_typeinf.parse_decl(tif, None, candidate, flags):
                return tif
        except Exception:
            pass

        try:
            if ida_typeinf.parse_decl(tif, None, candidate, 0):
                return tif
        except Exception:
            pass
    return None


def get_function_tinfo(func_ea):
    tif = ida_typeinf.tinfo_t()
    try:
        if ida_nalt.get_tinfo(tif, func_ea):
            return tif
    except Exception:
        pass
    return None


def build_function_ptr_tinfo(func_ea, fallback_decl):
    func_tif = get_function_tinfo(func_ea)
    if func_tif is not None:
        ptr_tif = ida_typeinf.tinfo_t()
        try:
            ptr_tif.create_ptr(func_tif)
            return ptr_tif
        except Exception:
            return None
    return parse_decl_tinfo(fallback_decl)


def decode_instruction(ea):
    insn = ida_ua.insn_t()
    try:
        if ida_ua.decode_insn(insn, ea):
            return insn
    except Exception:
        pass
    return None


def parse_int_literal(token):
    token = (token or "").strip().lower()
    if not token:
        return None
    if token.startswith("#"):
        token = token[1:]
    try:
        if token.endswith("h") and token[:-1]:
            return int(token[:-1], 16)
        return int(token, 0)
    except Exception:
        return None


def contains_this_reg(op_text):
    op_text = (op_text or "").lower()
    if not op_text:
        return False
    return any(reg in op_text for reg in THIS_REG_NAMES)


def extract_this_offset_from_operand(ea, op_idx):
    op_text = (idc.print_operand(ea, op_idx) or "").lower()
    if not op_text or not contains_this_reg(op_text):
        return None

    value = None
    try:
        value = idc.get_operand_value(ea, op_idx)
    except Exception:
        value = None

    if value in (None, ida_idaapi.BADADDR):
        value = 0

    match = re.search(r"([+-])\s*(?:#)?(0x[0-9a-f]+|[0-9a-f]+h|\d+)", op_text)
    if match:
        parsed = parse_int_literal(match.group(2))
        if parsed is not None:
            value = parsed
            if match.group(1) == "-":
                value = -value

    if value < 0:
        return None
    return int(value)


def get_register_size(op_text):
    op_text = (op_text or "").strip().lower()
    if not op_text:
        return 0
    op_text = op_text.split(",")[0]
    op_text = op_text.split()[0]

    if op_text.startswith(("xmm", "ymm", "zmm")):
        return 16
    if re.match(r"^(rax|rbx|rcx|rdx|rsi|rdi|rbp|rsp|rip|r\d+)$", op_text):
        return 8
    if re.match(r"^(eax|ebx|ecx|edx|esi|edi|ebp|esp|eip|w\d+|r\d+d)$", op_text):
        return 4
    if re.match(r"^(ax|bx|cx|dx|si|di|bp|sp|r\d+w)$", op_text):
        return 2
    if re.match(r"^(al|ah|bl|bh|cl|ch|dl|dh|spl|bpl|sil|dil|r\d+b)$", op_text):
        return 1
    if re.match(r"^(x\d+)$", op_text):
        return 8
    if re.match(r"^(w\d+)$", op_text):
        return 4
    if re.match(r"^(s\d+)$", op_text):
        return 4
    if re.match(r"^(d\d+)$", op_text):
        return 8
    return 0


def get_operand_size(ea, op_idx, fallback_text=""):
    insn = decode_instruction(ea)
    if insn is not None:
        try:
            size = ida_ua.get_dtype_size(insn[op_idx].dtype)
            if size > 0:
                return int(size)
        except Exception:
            pass

    op_text = (fallback_text or idc.print_operand(ea, op_idx) or "").lower()
    if "byte ptr" in op_text:
        return 1
    if "word ptr" in op_text:
        return 2
    if "dword ptr" in op_text:
        return 4
    if "qword ptr" in op_text:
        return 8
    if "xmmword ptr" in op_text:
        return 16

    return get_register_size(op_text)


def get_this_store_info(ea):
    mnem = (idc.print_insn_mnem(ea) or "").lower()
    ops = [(idc.print_operand(ea, i) or "") for i in range(4)]

    if ops[0] and contains_this_reg(ops[0]):
        src_idxs = [i for i in range(1, 4) if ops[i]]
        if src_idxs:
            return 0, src_idxs, ops, mnem

    if mnem.startswith("st"):
        for mem_idx in (2, 1, 3):
            if mem_idx < len(ops) and ops[mem_idx] and contains_this_reg(ops[mem_idx]):
                src_idxs = [i for i in range(mem_idx) if ops[i]]
                if src_idxs:
                    return mem_idx, src_idxs, ops, mnem

    return None, [], ops, mnem


def get_store_size(ea, mnem, mem_idx, src_idxs, ops):
    size = get_operand_size(ea, mem_idx, ops[mem_idx])
    if size > 0:
        if mnem.startswith("stp") and len(src_idxs) >= 2 and size <= u.PTR_SIZE:
            return size * 2
        return size

    if mnem.startswith("stp") and src_idxs:
        pair_size = 0
        for src_idx in src_idxs[:2]:
            pair_size += max(1, get_operand_size(ea, src_idx, ops[src_idx]))
        if pair_size:
            return pair_size

    if src_idxs:
        reg_size = get_operand_size(ea, src_idxs[0], ops[src_idxs[0]])
        if reg_size:
            return reg_size
    return u.PTR_SIZE


def get_field_kind(ea, mnem, src_idxs, ops, vtable_eas, size):
    refs = set(idautils.DataRefsFrom(ea))
    if refs & vtable_eas:
        return None

    if src_idxs:
        src_text = (ops[src_idxs[0]] or "").lower()
        if "offset " in src_text:
            return "ptr"

        if get_register_size(src_text) == u.PTR_SIZE and size == u.PTR_SIZE:
            return "ptr"

        if re.match(r"^(s\d+|xmm\d+)$", src_text):
            return "float"
        if re.match(r"^(d\d+)$", src_text):
            return "double"

        try:
            value = idc.get_operand_value(ea, src_idxs[0])
        except Exception:
            value = None
        if value not in (None, ida_idaapi.BADADDR):
            try:
                if ida_bytes.is_loaded(value) and size == u.PTR_SIZE:
                    return "ptr"
            except Exception:
                pass

    if size == 4 and mnem in ("movss",):
        return "float"
    if size == 8 and mnem in ("movsd",):
        return "double"
    return "scalar"


def merge_field_kind(existing_kind, new_kind):
    ranks = {
        None: 0,
        "scalar": 1,
        "float": 2,
        "double": 3,
        "ptr": 4,
    }
    if ranks.get(new_kind, 0) >= ranks.get(existing_kind, 0):
        return new_kind
    return existing_kind


def ensure_generated_sized_member(sid, member_name, offset, size):
    if size <= 0:
        return 0
    if size == u.PTR_SIZE:
        return ensure_generated_member(sid, member_name, offset)
    if size == 1:
        return ensure_generated_byte_member(sid, member_name, offset, 1)

    try:
        existing_off = idc.get_member_offset(sid, member_name)
    except Exception:
        existing_off = ida_idaapi.BADADDR
    if existing_off != ida_idaapi.BADADDR:
        return 0

    flag = ida_bytes.FF_DATA | ida_bytes.FF_BYTE
    if size == 2:
        flag = ida_bytes.FF_DATA | ida_bytes.FF_WORD
    elif size == 4:
        flag = ida_bytes.FF_DATA | ida_bytes.FF_DWORD
    elif size == 8:
        flag = ida_bytes.FF_DATA | ida_bytes.FF_QWORD
    return idc.add_struc_member(sid, member_name, offset, flag, -1, size)


def clear_generated_layout_members(sid):
    generated_names = (
        "vfptr",
        "gap_",
        "field_",
        "ptr_",
        "float_",
        "double_",
        "vbptr_",
    )
    members = list(idautils.StructMembers(sid))
    for offset, name, _ in reversed(members):
        if not name:
            continue
        if name == "vfptr" or name.startswith(generated_names) or name.endswith("_tail"):
            try:
                idc.del_struc_member(sid, offset)
            except Exception:
                pass


def get_code_ref_targets(ea):
    return [x for x in idautils.CodeRefsFrom(ea, 0) if x != ida_idaapi.BADADDR]


def get_prev_code_items(ea, max_count=6):
    items = []
    cur = ea
    for _ in range(max_count):
        cur = idc.prev_head(cur, 0)
        if cur == ida_idaapi.BADADDR:
            break
        items.append(cur)
    return items


def is_operator_new_like_target(target):
    name = ida_name.get_short_name(target) or ida_name.get_name(target) or ""
    demangled = ida_name.demangle_name(name, 0) or name
    lname = demangled.lower()
    return any(token.lower() in lname for token in ALLOC_CALLEE_HINTS)


def format_signed_offset(value):
    if value == 0:
        return "+0x0"
    if value < 0:
        return "-0x%x" % (-value)
    return "+0x%x" % value


def set_member_comment(sid, member_name, text):
    try:
        moff = idc.get_member_offset(sid, member_name)
    except Exception:
        return
    if moff == ida_idaapi.BADADDR:
        return
    try:
        idc.set_member_cmt(sid, moff, text, 1)
    except Exception:
        pass


def get_function_items(func_ea, max_items=None):
    f = ida_funcs.get_func(func_ea)
    if not f:
        return []

    items = []
    for item in idautils.FuncItems(f.start_ea):
        mnem = idc.print_insn_mnem(item)
        if not mnem:
            continue
        items.append(item)
        if max_items is not None and len(items) >= max_items:
            break
    return items


def get_thunk_target(func_ea):
    f = ida_funcs.get_func(func_ea)
    if not f:
        return ida_idaapi.BADADDR

    items = get_function_items(f.start_ea, max_items=4)
    if not items:
        return ida_idaapi.BADADDR

    for item in items:
        mnem = idc.print_insn_mnem(item).lower()
        refs = [x for x in idautils.CodeRefsFrom(item, 0) if x != f.start_ea]
        if mnem in THUNK_BRANCH_MNEMS and refs:
            return refs[0]

    if f.flags & ida_funcs.FUNC_THUNK:
        for item in items:
            refs = [x for x in idautils.CodeRefsFrom(item, 0) if x != f.start_ea]
            if refs:
                return refs[0]
    return ida_idaapi.BADADDR


def get_thunk_adjustment(func_ea):
    f = ida_funcs.get_func(func_ea)
    if not f:
        return 0

    for item in get_function_items(f.start_ea, max_items=5):
        mnem = (idc.print_insn_mnem(item) or "").lower()
        op0 = (idc.print_operand(item, 0) or "").lower()
        op1 = idc.print_operand(item, 1) or ""
        op2 = idc.print_operand(item, 2) or ""
        if mnem in ("add", "sub") and op0 in ("ecx", "rcx", "r0", "x0"):
            try:
                value = idc.get_operand_value(item, 1)
            except Exception:
                value = None
            if value is None:
                continue
            if mnem == "sub":
                value = -value
            return value
        if mnem == "lea" and op0 in ("ecx", "rcx"):
            imm = extract_this_offset_from_operand(item, 1)
            if imm is not None:
                return imm
            if "-" in op1:
                try:
                    imm = idc.get_operand_value(item, 1)
                    return -imm
                except Exception:
                    pass
        if mnem.startswith("adr") and op0 in ("x0", "r0"):
            imm = extract_this_offset_from_operand(item, 1)
            if imm is not None:
                return imm
        if mnem in ("stp", "str", "stur") and contains_this_reg(op2):
            imm = extract_this_offset_from_operand(item, 2)
            if imm:
                return imm
    return 0


def function_calls_delete_like(func_ea, max_items=32):
    f = ida_funcs.get_func(func_ea)
    if not f:
        return False

    for item in get_function_items(f.start_ea, max_items=max_items):
        refs = [x for x in idautils.CodeRefsFrom(item, 0) if x != ida_idaapi.BADADDR]
        if not refs:
            continue
        mnem = idc.print_insn_mnem(item).lower()
        if mnem not in CALL_MNEMS and mnem not in THUNK_BRANCH_MNEMS:
            continue
        for target in refs:
            name = ida_name.get_short_name(target) or ida_name.get_name(target) or ""
            demangled = ida_name.demangle_name(name, 0) or name
            lname = demangled.lower()
            if any(token in lname for token in DELETE_CALLEE_HINTS):
                return True
    return False


def get_virtual_method_kind(func_ea, slot_index):
    name = ida_funcs.get_func_name(func_ea) or ida_name.get_name(func_ea) or ""
    demangled = ida_name.demangle_name(name, 0) or name
    lname = demangled.lower()
    thunk_target = get_thunk_target(func_ea)
    analysis_ea = thunk_target if thunk_target != ida_idaapi.BADADDR else func_ea

    if name.startswith("??_G") or "scalar deleting destructor" in lname:
        return "scalar_deleting_destructor", thunk_target
    if name.startswith("??_E") or "vector deleting destructor" in lname:
        return "vector_deleting_destructor", thunk_target
    if name.startswith("??1") or "`destructor'" in lname or " destructor" in lname:
        return "destructor", thunk_target
    if slot_index in (0, 1) and function_calls_delete_like(analysis_ea):
        if slot_index == 0:
            return "scalar_deleting_destructor", thunk_target
        return "vector_deleting_destructor", thunk_target
    if thunk_target != ida_idaapi.BADADDR:
        return "thunk", thunk_target
    return "virtual_method", thunk_target


def get_ctor_dtor_kind(func_ea):
    thunk_target = get_thunk_target(func_ea)
    analysis_ea = thunk_target if thunk_target != ida_idaapi.BADADDR else func_ea
    if function_calls_delete_like(analysis_ea):
        return "possible_destructor"
    return "possible_constructor"


def get_virtual_stub_name(kind, slot_index, thunk_target, thunk_adjust=0):
    if kind in ("scalar_deleting_destructor", "vector_deleting_destructor", "destructor"):
        return kind
    if kind == "thunk":
        target_name = ida_name.get_short_name(thunk_target) or ida_funcs.get_func_name(thunk_target) or ("slot_%u" % slot_index)
        target_name = target_name.split("::")[-1]
        adj = ""
        if thunk_adjust:
            adj = "_adj_%x" % (abs(thunk_adjust) & 0xffffffff)
            if thunk_adjust < 0:
                adj = "_sub_%x" % (abs(thunk_adjust) & 0xffffffff)
        return "thunk%s_%s" % (adj, normalize_identifier(target_name, fallback="slot_%u" % slot_index, max_len=36))
    return ""


def get_vtable_member_name(func_ea, slot_index, kind, thunk_target, used_names, thunk_adjust=0):
    if kind in ("scalar_deleting_destructor", "vector_deleting_destructor", "destructor"):
        base = kind
    elif kind == "thunk":
        target_name = ida_name.get_short_name(thunk_target) or ida_funcs.get_func_name(thunk_target) or ("slot_%u" % slot_index)
        target_name = target_name.split("::")[-1]
        adj = ""
        if thunk_adjust:
            adj = "_adj_%x" % (abs(thunk_adjust) & 0xffffffff)
            if thunk_adjust < 0:
                adj = "_sub_%x" % (abs(thunk_adjust) & 0xffffffff)
        base = "thunk%s_%s" % (adj, normalize_identifier(target_name, fallback="slot_%u" % slot_index, max_len=36))
    else:
        func_name = ida_name.get_short_name(func_ea) or ida_funcs.get_func_name(func_ea) or ("slot_%u" % slot_index)
        func_name = func_name.split("::")[-1]
        base = normalize_identifier(func_name, fallback="slot_%u" % slot_index, max_len=48)

    candidate = base
    idx = 2
    while candidate in used_names:
        candidate = "%s_%u" % (base, idx)
        idx += 1
    used_names.add(candidate)
    return candidate


def get_vfptr_member_name(offset):
    if offset == 0:
        return "vfptr"
    return "vfptr_%x" % offset


def get_gap_member_name(offset):
    return "gap_%x" % offset


def build_method_decl(class_type_name, kind, func_token="pci_method"):
    class_ref = "struct %s" % class_type_name
    callconv = "__thiscall "
    if u.x64 or ida_idp.ph.id != ida_idp.PLFM_386:
        callconv = ""
    if kind in ("constructor", "possible_constructor"):
        return "%s * %s%s(%s *self, ...);" % (class_ref, callconv, func_token, class_ref)
    if kind == "destructor":
        return "void %s%s(%s *self);" % (callconv, func_token, class_ref)
    if kind in ("scalar_deleting_destructor", "vector_deleting_destructor"):
        return "void %s%s(%s *self, unsigned int flags);" % (callconv, func_token, class_ref)
    return "void %s%s(%s *self, ...);" % (callconv, func_token, class_ref)


def build_class_ptr_decl(class_type_name):
    return "struct %s *;" % class_type_name


def build_vtable_slot_decl(class_type_name, kind, slot_index):
    class_ref = "struct %s" % class_type_name
    slot_name = "slot_%u" % slot_index
    callconv = "__thiscall "
    if u.x64 or ida_idp.ph.id != ida_idp.PLFM_386:
        callconv = ""

    ptr_decl = "(*%s)" % slot_name
    if callconv:
        ptr_decl = "(%s*%s)" % (callconv, slot_name)

    if kind == "destructor":
        return "void %s(%s *self);" % (ptr_decl, class_ref)
    if kind in ("scalar_deleting_destructor", "vector_deleting_destructor"):
        return "void %s(%s *self, unsigned int flags);" % (ptr_decl, class_ref)
    return "void %s(%s *self, ...);" % (ptr_decl, class_ref)


def apply_generated_signature(func_ea, class_type_name, kind, force=False):
    f = ida_funcs.get_func(func_ea)
    if not f:
        return False

    current_name = ida_funcs.get_func_name(f.start_ea) or ""
    current_type = idc.get_type(f.start_ea)
    existing_tif = get_function_tinfo(f.start_ea)
    if existing_tif is not None and current_type and TYPE_PREFIX not in current_type:
        return False
    if current_type and not force and not is_auto_named(current_name) and TYPE_PREFIX not in current_type:
        return False

    decl = build_method_decl(class_type_name, kind)
    try:
        return bool(idc.SetType(f.start_ea, decl))
    except Exception:
        return False


def apply_vtable_slot_type(slot_ea, class_type_name, kind, slot_index, func_ea):
    ptr_tif = build_function_ptr_tinfo(func_ea, build_vtable_slot_decl(class_type_name, kind, slot_index))
    if ptr_tif is not None:
        try:
            if ida_typeinf.apply_tinfo(slot_ea, ptr_tif, ida_typeinf.TINFO_DEFINITE):
                return True
        except Exception:
            pass

    decl = build_vtable_slot_decl(class_type_name, kind, slot_index)
    try:
        return bool(idc.SetType(slot_ea, decl))
    except Exception:
        return False


def apply_vtable_member_type(sid, member_name, class_type_name, kind, slot_index, func_ea):
    decl = build_vtable_slot_decl(class_type_name, kind, slot_index)
    tif = build_function_ptr_tinfo(func_ea, decl)
    if tif is None:
        return False
    return u.set_member_tinfo(sid, member_name, tif, idx=slot_index)


def apply_vtable_struct_type(entry):
    sid = idc.get_struc_id(entry["vtbl_type_name"])
    if sid == ida_idaapi.BADADDR:
        return False

    size = len(entry["col"].vfeas) * u.PTR_SIZE
    if size <= 0:
        return False

    try:
        ok = bool(ida_bytes.create_struct(entry["vftable_ea"], size, sid, True))
    except Exception:
        ok = False
    if not ok:
        try:
            ok = bool(idc.SetType(entry["vftable_ea"], "struct %s;" % entry["vtbl_type_name"]))
        except Exception:
            ok = False
    if ok:
        append_comment(entry["vftable_ea"], "%s: typed as %s" % (COMMENT_TAG, entry["vtbl_type_name"]), 1)
    return ok


def annotate_ctor_call_sites(func_ea, owner_name, owner_type_name):
    caller_funcs = set()
    for call_ea in idautils.CodeRefsTo(func_ea, 0):
        caller = ida_funcs.get_func(call_ea)
        if caller:
            caller_funcs.add(caller.start_ea)
        append_comment(call_ea, "%s: constructs %s (%s)" % (COMMENT_TAG, owner_name, owner_type_name), 0)
        for prev_ea in get_prev_code_items(call_ea, max_count=6):
            mnem = (idc.print_insn_mnem(prev_ea) or "").lower()
            if mnem not in CALL_MNEMS:
                continue
            targets = get_code_ref_targets(prev_ea)
            if not targets:
                continue
            if any(is_operator_new_like_target(target) for target in targets):
                append_comment(prev_ea, "%s: likely allocates object for %s" % (COMMENT_TAG, owner_name), 0)
                break
    return caller_funcs


def invalidate_cfunc_cache(cfunc_cache, func_ea):
    if cfunc_cache is None:
        return
    cfunc_cache.pop(func_ea, None)


def get_cfunc_cached(func_ea, cfunc_cache=None):
    if not initialize_hexrays():
        return None

    if cfunc_cache is not None and func_ea in cfunc_cache:
        return cfunc_cache[func_ea]

    try:
        cfunc = ida_hexrays.decompile(func_ea)
    except Exception:
        cfunc = None

    if cfunc_cache is not None:
        cfunc_cache[func_ea] = cfunc
    return cfunc


def apply_hexrays_lvar_type(func_ea, var_name, type_decl, cfunc_cache=None):
    if not initialize_hexrays():
        return False

    tif = parse_decl_tinfo(type_decl)
    if tif is None:
        return False

    ll = ida_hexrays.lvar_locator_t()
    try:
        if not ida_hexrays.locate_lvar(ll, func_ea, var_name):
            return False
    except Exception:
        return False

    info = ida_hexrays.lvar_saved_info_t()
    info.ll = ll
    info.type = tif
    try:
        ok = bool(ida_hexrays.modify_user_lvar_info(func_ea, ida_hexrays.MLI_TYPE, info))
    except Exception:
        return False
    if ok:
        invalidate_cfunc_cache(cfunc_cache, func_ea)
    return ok


def get_cfunc_lvars(func_ea, cfunc_cache=None):
    cfunc = get_cfunc_cached(func_ea, cfunc_cache)
    if cfunc is None:
        return None, []

    try:
        lvars = cfunc.get_lvars()
    except Exception:
        lvars = None
    if lvars is None:
        return cfunc, []
    return cfunc, list(lvars)


def apply_hexrays_thisarg_type(func_ea, class_type_name, cfunc_cache=None):
    _, lvars = get_cfunc_lvars(func_ea, cfunc_cache)
    if not lvars:
        return False

    arg_candidates = []
    for lv in lvars:
        try:
            if lv.is_arg_var() and not lv.is_fake_var():
                arg_candidates.append(lv)
        except Exception:
            continue
    if not arg_candidates:
        return False

    preferred = None
    for lv in arg_candidates:
        try:
            if lv.is_thisarg():
                preferred = lv
                break
        except Exception:
            pass
    if preferred is None:
        preferred = arg_candidates[0]

    return apply_hexrays_lvar_type(func_ea, preferred.name, build_class_ptr_decl(class_type_name), cfunc_cache)


def apply_hexrays_ctor_result_type(func_ea, class_type_name, cfunc_cache=None):
    _, lvars = get_cfunc_lvars(func_ea, cfunc_cache)
    if not lvars:
        return False

    candidates = []
    best_candidates = []
    for lv in lvars:
        try:
            if lv.is_arg_var() or lv.is_fake_var() or lv.is_result_var():
                continue
            if lv.has_user_type():
                continue
        except Exception:
            continue

        try:
            if lv.width != u.PTR_SIZE:
                continue
        except Exception:
            continue

        lname = lv.name or ""
        candidates.append(lv)
        if AUTO_LOCAL_PTR_RE.match(lname):
            best_candidates.append(lv)

    if len(best_candidates) == 1:
        target = best_candidates[0]
    elif len(candidates) == 1:
        target = candidates[0]
    else:
        return False

    return apply_hexrays_lvar_type(func_ea, target.name, build_class_ptr_decl(class_type_name), cfunc_cache)


def build_decompilation_context(paths, data):
    class_type_names = {}
    layouts = {}
    vtables = []
    entry_size_estimates = {}
    class_size_estimates = {}

    for vftable_ea in data:
        col = data[vftable_ea]
        if col.name not in class_type_names:
            class_type_names[col.name] = build_generated_type_name("class", col.name)
            class_size_estimates[col.name] = u.PTR_SIZE

    for vftable_ea in paths:
        col = data[vftable_ea]
        path = paths[vftable_ea]
        owner_name = path[-1].name if path else col.name

        if owner_name not in class_type_names:
            class_type_names[owner_name] = build_generated_type_name("class", owner_name)
            class_size_estimates[owner_name] = u.PTR_SIZE

        entry = {
            "vftable_ea": vftable_ea,
            "owner_name": owner_name,
            "owner_type_name": class_type_names[owner_name],
            "subobject_name": col.name,
            "subobject_type_name": class_type_names[col.name],
            "offset": col.offset,
            "col": col,
            "vtbl_type_name": build_generated_type_name("vtbl", owner_name, col.offset),
        }
        vtables.append(entry)
        layouts.setdefault(owner_name, []).append(entry)

    for _ in range(max(1, len(class_size_estimates))):
        changed = False
        for owner_name in layouts:
            owner_entries = sorted(layouts[owner_name], key=lambda x: x["offset"])
            owner_size = class_size_estimates.get(owner_name, u.PTR_SIZE)
            for idx, entry in enumerate(owner_entries):
                next_offset = None
                if idx + 1 < len(owner_entries):
                    next_offset = owner_entries[idx + 1]["offset"]

                sub_size = max(u.PTR_SIZE, class_size_estimates.get(entry["subobject_name"], u.PTR_SIZE))
                if next_offset is not None:
                    sub_size = max(sub_size, next_offset - entry["offset"])

                owner_size = max(owner_size, entry["offset"] + sub_size)

            if owner_size > class_size_estimates.get(owner_name, u.PTR_SIZE):
                class_size_estimates[owner_name] = owner_size
                changed = True
        if not changed:
            break

    for owner_name in layouts:
        owner_entries = sorted(layouts[owner_name], key=lambda x: x["offset"])
        for idx, entry in enumerate(owner_entries):
            size_guess = max(u.PTR_SIZE, class_size_estimates.get(entry["subobject_name"], u.PTR_SIZE))
            if idx + 1 < len(owner_entries):
                size_guess = max(size_guess, owner_entries[idx + 1]["offset"] - entry["offset"])
            entry_size_estimates[(owner_name, entry["offset"])] = size_guess

    return class_type_names, layouts, vtables, entry_size_estimates


def add_generated_tail_member(sid, member_name, offset, size):
    if size <= 0:
        return 0
    return ensure_generated_byte_member(sid, member_name, offset, size)


def collect_virtual_inheritance_hints(paths):
    hints = {}
    for path in paths.values():
        if not path:
            continue
        owner_name = path[-1].name
        owner_hints = hints.setdefault(owner_name, {})
        for bcd in path:
            pdisp = getattr(bcd, "pdisp", -1)
            vdisp = getattr(bcd, "vdisp", -1)
            if pdisp is None or pdisp < 0:
                continue
            comment = "%s: vbptr for %s (pdisp %#x" % (COMMENT_TAG, bcd.name, pdisp)
            if vdisp is not None and vdisp >= 0:
                comment += ", vdisp %#x" % vdisp
            comment += ")"
            owner_hints[pdisp] = comment
    return hints


def collect_constructor_field_writes(layouts, vtables):
    vtable_eas = set(entry["vftable_ea"] for entry in vtables)
    owner_vfptr_offsets = {}
    for owner_name in layouts:
        owner_vfptr_offsets[owner_name] = set(x["offset"] for x in layouts[owner_name])

    fields = {}
    ctor_map = {}
    for entry in vtables:
        owner_name = entry["owner_name"]
        for f in get_vftable_ref_funcs(entry["vftable_ea"]):
            if get_ctor_dtor_kind(f.start_ea) == "possible_constructor":
                ctor_map.setdefault(owner_name, set()).add(f.start_ea)

    for owner_name, funcs in ctor_map.items():
        owner_fields = fields.setdefault(owner_name, {})
        for func_ea in funcs:
            for item in get_function_items(func_ea, max_items=96):
                mem_idx, src_idxs, ops, mnem = get_this_store_info(item)
                if mem_idx is None:
                    continue

                offset = extract_this_offset_from_operand(item, mem_idx)
                if offset is None or offset > 0x2000:
                    continue
                if offset in owner_vfptr_offsets.get(owner_name, set()):
                    continue

                kind = get_field_kind(item, mnem, src_idxs, ops, vtable_eas, get_store_size(item, mnem, mem_idx, src_idxs, ops))
                if kind is None:
                    continue

                size = get_store_size(item, mnem, mem_idx, src_idxs, ops)
                if size <= 0:
                    size = u.PTR_SIZE
                if size > 0x40:
                    size = u.PTR_SIZE

                record = owner_fields.get(offset)
                if record is None:
                    record = {
                        "offset": offset,
                        "size": size,
                        "kind": kind,
                        "writes": 0,
                    }
                    owner_fields[offset] = record
                else:
                    record["size"] = max(record["size"], size)
                    record["kind"] = merge_field_kind(record.get("kind"), kind)
                record["writes"] += 1

    return fields


def build_class_layout_plan(owner_name, layouts, entry_size_estimates, recovered_fields, virtual_hints):
    members = []
    notes = {}
    occupied = []

    def overlaps(offset, size):
        end = offset + size
        for start, stop in occupied:
            if not (end <= start or offset >= stop):
                return True
        return False

    def reserve(offset, size):
        occupied.append((offset, offset + size))

    def append_member(offset, size, name, kind, comment, target_type_name=None):
        if size <= 0 or overlaps(offset, size):
            if comment:
                notes.setdefault(offset, []).append(comment)
            return
        members.append({
            "offset": offset,
            "size": size,
            "name": name,
            "kind": kind,
            "comment": comment,
            "target_type_name": target_type_name,
        })
        reserve(offset, size)

    owner_entries = sorted(layouts.get(owner_name, []), key=lambda x: x["offset"])
    class_size = 0
    for idx, entry in enumerate(owner_entries):
        append_member(
            entry["offset"],
            u.PTR_SIZE,
            get_vfptr_member_name(entry["offset"]),
            "vfptr",
            "%s: vfptr for %s (offset %#x)" % (COMMENT_TAG, entry["subobject_name"], entry["offset"]),
            target_type_name=entry["vtbl_type_name"])

        estimate = entry_size_estimates.get((owner_name, entry["offset"]), u.PTR_SIZE)
        next_offset = None
        if idx + 1 < len(owner_entries):
            next_offset = owner_entries[idx + 1]["offset"]
        if next_offset is not None:
            estimate = min(estimate, max(u.PTR_SIZE, next_offset - entry["offset"]))
        estimate = max(estimate, u.PTR_SIZE)
        class_size = max(class_size, entry["offset"] + estimate)

    for offset, comment in sorted(virtual_hints.get(owner_name, {}).items()):
        append_member(offset, u.PTR_SIZE, "vbptr_%x" % offset, "vbptr", comment)

    for offset, field in sorted(recovered_fields.get(owner_name, {}).items()):
        kind = field.get("kind", "scalar")
        prefix = {
            "ptr": "ptr",
            "float": "float",
            "double": "double",
        }.get(kind, "field")
        size = max(1, int(field.get("size", u.PTR_SIZE)))
        comment = "%s: recovered %s field (%u write%s)" % (
            COMMENT_TAG,
            kind,
            field.get("writes", 1),
            "" if field.get("writes", 1) == 1 else "s")
        append_member(offset, size, "%s_%x" % (prefix, offset), kind, comment)
        class_size = max(class_size, offset + size)

    members.sort(key=lambda x: (x["offset"], 0 if x["kind"] == "vfptr" else 1))

    layout_plan = []
    cursor = 0
    for member in members:
        if member["offset"] < cursor:
            continue
        if member["offset"] > cursor:
            layout_plan.append({
                "offset": cursor,
                "size": member["offset"] - cursor,
                "name": get_gap_member_name(cursor),
                "kind": "gap",
                "comment": "%s: reserved gap up to %#x" % (COMMENT_TAG, member["offset"]),
                "target_type_name": None,
            })
        if notes.get(member["offset"]):
            member = dict(member)
            member["comment"] = " | ".join([member["comment"]] + notes[member["offset"]])
        layout_plan.append(member)
        cursor = member["offset"] + member["size"]

    if class_size > cursor:
        layout_plan.append({
            "offset": cursor,
            "size": class_size - cursor,
            "name": get_gap_member_name(cursor),
            "kind": "gap",
            "comment": "%s: estimated class tail" % COMMENT_TAG,
            "target_type_name": None,
        })

    return layout_plan


def generate_decompilation_types(class_type_names, layouts, vtables, entry_size_estimates, recovered_fields=None, virtual_hints=None):
    if recovered_fields is None:
        recovered_fields = {}
    if virtual_hints is None:
        virtual_hints = {}

    for class_name in class_type_names:
        type_name = class_type_names[class_name]
        sid = ensure_generated_struct(type_name)
        idc.set_struc_cmt(sid, "%s: generated class type for %s" % (COMMENT_TAG, class_name), 1)

    for entry in vtables:
        sid = ensure_generated_struct(entry["vtbl_type_name"])
        idc.set_struc_cmt(sid, "%s: generated vtable type for %s (offset %#x)" % (COMMENT_TAG, entry["owner_name"], entry["offset"]), 1)

        used_names = set()
        for slot_index, func_ea in enumerate(entry["col"].vfeas):
            kind, thunk_target = get_virtual_method_kind(func_ea, slot_index)
            thunk_adjust = get_thunk_adjustment(func_ea) if kind == "thunk" else 0
            member_name = get_vtable_member_name(func_ea, slot_index, kind, thunk_target, used_names, thunk_adjust=thunk_adjust)
            ensure_generated_member(sid, member_name, slot_index * u.PTR_SIZE)
            apply_vtable_member_type(sid, member_name, entry["subobject_type_name"], kind, slot_index, func_ea)
            slot_ea = entry["vftable_ea"] + slot_index * u.PTR_SIZE
            apply_vtable_slot_type(slot_ea, entry["subobject_type_name"], kind, slot_index, func_ea)
            slot_comment = "%s: vtable slot %u for %s (%s)" % (COMMENT_TAG, slot_index, entry["subobject_name"], kind)
            if thunk_adjust:
                slot_comment += ", this %s" % format_signed_offset(thunk_adjust)
            append_comment(slot_ea, slot_comment, 1)
            member_comment = "slot %u -> %#x (%s)" % (slot_index, func_ea, kind)
            if thunk_adjust:
                member_comment += ", this %s" % format_signed_offset(thunk_adjust)
            set_member_comment(sid, member_name, member_comment)

        apply_vtable_struct_type(entry)

    for owner_name in layouts:
        sid = idc.get_struc_id(class_type_names[owner_name])
        clear_generated_layout_members(sid)
        for member in build_class_layout_plan(owner_name, layouts, entry_size_estimates, recovered_fields, virtual_hints):
            r = -1
            if member["kind"] == "vfptr":
                r = add_generated_ptr_member(sid, member["name"], member["offset"], member["target_type_name"])
            elif member["kind"] == "vbptr":
                r = add_generated_ptr_member(sid, member["name"], member["offset"])
            elif member["kind"] == "ptr":
                r = add_generated_ptr_member(sid, member["name"], member["offset"])
            elif member["kind"] == "gap":
                r = ensure_generated_byte_member(sid, member["name"], member["offset"], member["size"])
            else:
                r = ensure_generated_sized_member(sid, member["name"], member["offset"], member["size"])

            if r == 0 and member["comment"]:
                set_member_comment(sid, member["name"], member["comment"])
            if r == 0 and member["kind"] in ("float", "double"):
                scalar_tif = parse_decl_tinfo("%s __pci_tmp;" % member["kind"])
                if scalar_tif is not None:
                    u.set_member_tinfo(sid, member["name"], scalar_tif)


def refresh_decompiler_views(func_eas, cfunc_cache=None):
    if not initialize_hexrays():
        return
    for func_ea in sorted(set(func_eas)):
        invalidate_cfunc_cache(cfunc_cache, func_ea)
        refresh_hexrays_function(func_ea)


def improve_decompilation(paths, data, config):
    class_type_names, layouts, vtables, entry_size_estimates = build_decompilation_context(paths, data)
    generate_decompilation_types(class_type_names, layouts, vtables, entry_size_estimates)

    typed_virtuals = set()
    typed_refs = set()
    thisarg_types = {}
    ctor_callers = {}
    refreshed_funcs = set()
    cfunc_cache = {}
    for entry in vtables:
        col = entry["col"]
        is_lib = (col.libflag == col.LIBLIB)

        for slot_index, func_ea in enumerate(col.vfeas):
            kind, thunk_target = get_virtual_method_kind(func_ea, slot_index)
            thunk_adjust = get_thunk_adjustment(func_ea) if kind == "thunk" else 0
            if config.rnvm:
                stub_name = get_virtual_stub_name(kind, slot_index, thunk_target, thunk_adjust=thunk_adjust)
                rename_func(func_ea, entry["subobject_name"].split("<")[0] + "::", stub_name, is_lib=is_lib)
            if func_ea not in typed_virtuals:
                apply_generated_signature(func_ea, entry["subobject_type_name"], kind)
                append_comment(func_ea, "%s: %s for %s" % (COMMENT_TAG, kind, entry["subobject_name"]), 1)
                if kind == "thunk" and thunk_target != ida_idaapi.BADADDR:
                    append_comment(func_ea, "%s: adjusts self %s then jumps to %#x" % (COMMENT_TAG, format_signed_offset(thunk_adjust), thunk_target), 1)
                typed_virtuals.add(func_ea)
                thisarg_types[func_ea] = entry["subobject_type_name"]
                refreshed_funcs.add(func_ea)

        for f in get_vftable_ref_funcs(entry["vftable_ea"]):
            ref_kind = get_ctor_dtor_kind(f.start_ea)
            if config.rncd:
                rename_func(f.start_ea, entry["owner_name"].split("<")[0] + "::", ref_kind, is_lib=is_lib)
            if f.start_ea not in typed_refs:
                apply_generated_signature(f.start_ea, entry["owner_type_name"], ref_kind)
                append_comment(f.start_ea, "%s: %s for %s" % (COMMENT_TAG, ref_kind, entry["owner_name"]), 1)
                if ref_kind == "possible_constructor":
                    caller_funcs = annotate_ctor_call_sites(f.start_ea, entry["owner_name"], entry["owner_type_name"])
                    refreshed_funcs.update(caller_funcs)
                    for caller_ea in caller_funcs:
                        existing = ctor_callers.get(caller_ea)
                        if existing is None:
                            ctor_callers[caller_ea] = entry["owner_type_name"]
                        elif existing != entry["owner_type_name"]:
                            ctor_callers[caller_ea] = False
                typed_refs.add(f.start_ea)
                thisarg_types[f.start_ea] = entry["owner_type_name"]
                refreshed_funcs.add(f.start_ea)

        vfptr_member_name = get_vfptr_member_name(entry["offset"])
        for refea in idautils.DataRefsTo(entry["vftable_ea"]):
            append_comment(refea, "%s: writes %s::%s -> %s" % (COMMENT_TAG, entry["owner_name"], vfptr_member_name, entry["vtbl_type_name"]), 1)

    for func_ea, class_type_name in thisarg_types.items():
        if apply_hexrays_thisarg_type(func_ea, class_type_name, cfunc_cache):
            refreshed_funcs.add(func_ea)

    for caller_ea, class_type_name in ctor_callers.items():
        if not class_type_name:
            continue
        if apply_hexrays_ctor_result_type(caller_ea, class_type_name, cfunc_cache):
            refreshed_funcs.add(caller_ea)

    refresh_decompiler_views(refreshed_funcs, cfunc_cache)


def is_probable_ctor_dtor_ref(f, refea, byte_window=0x80):
    if f is None or refea < f.start_ea or refea >= f.end_ea:
        return False
    if refea - f.start_ea > byte_window:
        return False
    mnem = idc.print_insn_mnem(refea)
    if not mnem:
        return False
    return mnem.lower() in CTOR_DTOR_REF_MNEMS


def get_vftable_ref_funcs(vftable_ea):
    ref_funcs = {}
    for refea in idautils.DataRefsTo(vftable_ea):
        f = ida_funcs.get_func(refea)
        if not f:
            continue
        likely = is_probable_ctor_dtor_ref(f, refea)
        cached = ref_funcs.get(f.start_ea)
        if cached is None or (likely and not cached[1]):
            ref_funcs[f.start_ea] = (f, likely)

    likely_funcs = [x[0] for x in ref_funcs.values() if x[1]]
    if likely_funcs:
        return likely_funcs
    return [x[0] for x in ref_funcs.values()]

def change_dir_of_ctors_dtors(paths, data, dirtree):
    path_prefix = "/classes/"
    
    # move virtual functions to its class folder
    for vftable_ea in paths:
        path = paths[vftable_ea]
        if not path:
            continue
        
        # get the class name that owns the vftable, which is the last entry of the path.
        class_name = path[-1].name
        
        for f in get_vftable_ref_funcs(vftable_ea):
            func_name = ida_funcs.get_func_name(f.start_ea)
            if not func_name:
                continue
            # make a directory with a class name
            dst_path = path_prefix + class_name + "/possible ctors or dtors/"
            dirtree.mkdir(dst_path)
            
            # if the vfunc is at the top level, move it into the vftables folder.
            func_path = "/" + func_name
        
            # get the func path in the dir tree.
            dirtree_path = pyclassinformer.dirtree_utils.get_abs_path_by_inode(dirtree, f.start_ea)
        
            # check if the function is at the top level or not.
            # and rename it.
            if func_path == dirtree_path:
                #print(func_path)
                dirtree.rename(func_path, dst_path)
        
def change_dir_of_vfuncs(paths, data, dirtree):
    path_prefix = "/classes/"
    
    # move virtual functions to its class folder
    for vftable_ea in paths:
        path = paths[vftable_ea]
        if not path:
            continue
        
        # get the class name that owns the vftable, which is the last entry of the path.
        class_name = path[-1].name
        vfunc_eas = data[vftable_ea].vfeas
        #print(hex(vftable_ea), class_name, len(vfunc_eas), list(reversed([x.name for x in path])))
        
        # make a directory with a class name
        dst_path = path_prefix + class_name + "/virtual methods/"
        dirtree.mkdir(dst_path)
        
        # move virtual functions into the class name folder
        for vfea in vfunc_eas:
            func_name = ida_funcs.get_func_name(vfea)
            
            # sometimes, a function is not form of a function.
            # try to fix it or skip it
            if func_name is None:
                ida_funcs.add_func(vfea)
                f = ida_funcs.get_func(vfea)
                if f is None:
                    print("Warning: a virtual method at {:#x} in {} is not a function and failed to add it as a function. Skipping...".format(vfea, class_name))
                    continue
                
                # get func name again after creating a function
                func_name = ida_funcs.get_func_name(vfea)
                if func_name is None:
                    print("Warning: the func name of the virtual method at {:#x} in {} could not be obtaind. Skipping...".format(vfea, class_name))
                    continue
            #print(hex(vfea), func_name)
                
            # if the vfunc is at the top level, move it into the vftables folder.
            func_path = "/" + func_name
            
            # get the func path in the dir tree.
            dirtree_path = pyclassinformer.dirtree_utils.get_abs_path_by_inode(dirtree, vfea)
            
            # check if the function is at the top level or not.
            # and rename it.
            if func_path == dirtree_path:
                #print(func_path)
                dirtree.rename(func_path, dst_path)
                
        # just create directories for rest of classes
        for bcd in path[1:]:
            dst_path = path_prefix + bcd.name
            dirtree.mkdir(dst_path)


def rename_func(ea, prefix="", fn="", is_lib=False):
    func_name = ida_funcs.get_func_name(ea)
    
    # if a virtuame method is not a valid function, skip it
    if func_name is None:
        return False
    
    # rename the function name if it is a dummy name
    if is_auto_named(func_name):
        leaf_name = func_name.split("::")[-1]
        # change the function name to the specific name
        if fn:
            leaf_name = fn
        ida_name.set_name(ea, prefix + leaf_name, ida_name.SN_NOCHECK|ida_name.SN_FORCE)
        
    # add FUNC_LIB to make ida recognize the function as a part of static linked libraries
    if is_lib:
        f = ida_funcs.get_func(ea)
        if not f.flags & ida_funcs.FUNC_LIB:
            f.flags |= ida_funcs.FUNC_LIB
            ida_funcs.update_func(f)
    return True


def rename_vftable_ref_funcs(paths, data):
    for vftable_ea in paths:
        path = paths[vftable_ea]
        if not path:
            continue
        col = data[vftable_ea]
        
        # get the class name that owns the vftable, which is the last entry of the path.
        class_name = path[-1].name
        
        # check the class is a part of standard library classes such as STL and MFC
        is_lib = False
        if col.libflag == col.LIBLIB:
            is_lib = True
        
        # get the func eas that refer to vftables and rename them
        #print(hex(vftable_ea))
        for f in get_vftable_ref_funcs(vftable_ea):
            rename_func(f.start_ea, class_name.split("<")[0] + "::", get_ctor_dtor_kind(f.start_ea), is_lib=is_lib)


def rename_funcs(func_eas, prefix="", is_lib=False):
    for ea in func_eas:
        rename_func(ea, prefix, is_lib=is_lib)


def rename_vfuncs(paths, data):
    for vftable_ea in paths:
        path = paths[vftable_ea]
        if not path:
            continue
        col = data[vftable_ea]
        
        # get the class name that owns the vftable, which is the last entry of the path.
        #print(hex(vftable_ea), path)
        class_name = path[-1].name
        vfunc_eas = data[vftable_ea].vfeas
        
        # check the class is a part of standard library classes such as STL and MFC
        is_lib = False
        if col.libflag == col.LIBLIB:
            is_lib = True
        
        rename_funcs(vfunc_eas, class_name.split("<")[0] + "::", is_lib=is_lib)


def get_base_classes(data):
    paths = {}
    for vftable_ea in data:
        # get COL
        col = data[vftable_ea]
        
        # get relevant BCDs mainly for multiple inheritance
        base_classes = pyclassinformer.pci_utils.utils.get_col_bases(col, data)
        
        # reverse the path because the path is reverse ordered.
        base_classes.reverse()
        paths[vftable_ea] = base_classes
    
    # sort the results by the class name and base class length
    return {x:paths[x] for x in sorted(sorted(paths, key=lambda key: [x.name for x in paths[key]]), key=lambda key: len(paths[key]))}


def method_classifier(data, config=None, icon=-1):
    if config is None:
        config = pyclassinformer.pci_config.pci_config()
    decomp_enabled = getattr(config, "decomp", True)

    # check config values to execute or not
    if not config.exana and not config.mvvm and not config.mvcd and not config.rnvm and not config.rncd and not decomp_enabled:
        return None
    
    # get base classes
    paths = get_base_classes(data)
    
    # rename virtual methods in vftables
    if config.rnvm:
        rename_vfuncs(paths, data)

    # rename functions that refer to vftables because they are constructors or destructors
    if config.rncd:
       rename_vftable_ref_funcs(paths, data)

    # generate helper types, annotate vfptr writes and apply conservative signatures
    if decomp_enabled:
        improve_decompilation(paths, data, config)
         
    tree = None
    if tree_categorize:
        # get dirtree and move vfuncs to their class directories
        for dirtype in [ida_dirtree.DIRTREE_FUNCS, ida_dirtree.DIRTREE_NAMES]:
            dirtree = ida_dirtree.get_std_dirtree(dirtype)
            if config.mvvm:
                change_dir_of_vfuncs(paths, data, dirtree)
            if config.mvcd:
                change_dir_of_ctors_dtors(paths, data, dirtree)
        
        # display dir tree
        if config.exana:
            tree = pyclassinformer.mc_tree.show_mc_tree_t(data, paths, icon=icon)
    else:
        print("Warning; Your IDA does not have ida_dirtree or find_entry in dirtree_t. Skip creating dirs for classes and moving functions into them.")
    
    return tree
