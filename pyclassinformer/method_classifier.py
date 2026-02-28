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
AUTO_GENERATED_PREFIXES = ("virtual_method_",)
AUTO_GENERATED_NAMES = ("possible_ctor_or_dtor", "possible_constructor", "possible_destructor", "destructor", "scalar_deleting_destructor", "vector_deleting_destructor")
CTOR_DTOR_REF_MNEMS = set(["mov", "lea", "adr", "adrp", "add", "str", "stp"])
THUNK_BRANCH_MNEMS = set(["jmp", "b", "bra"])
CALL_MNEMS = set(["call", "bl", "blx", "blr"])
DELETE_CALLEE_HINTS = ("??3", "operator delete", "__imp_??3", " free", "_free", "j_j_free", " delete")
ALLOC_CALLEE_HINTS = ("??2", "operator new", "malloc", "calloc", "realloc", "HeapAlloc")
ALLOC_CALLEE_RE = re.compile(r"\b(?:operator\s+new|malloc|calloc|realloc|heapalloc)\b", re.IGNORECASE)
DELETE_CALLEE_RE = re.compile(r"\b(?:operator\s+delete|free)\b", re.IGNORECASE)
GENERIC_AUTO_TYPE_RE = re.compile(r"\b(?:void|_BYTE|_WORD|_DWORD|_QWORD|__int64|int|char|short|long|float|double|bool)\b", re.IGNORECASE)
TYPE_PREFIX = "pci__"
COMMENT_TAG = "PyClassInformer"
AUTO_LOCAL_PTR_RE = re.compile(r"^(v\d+|ptr|p|obj|object|result)$", re.IGNORECASE)
THIS_REG_NAMES = ("ecx", "rcx", "r0", "x0")


def is_auto_named(func_name):
    if not func_name:
        return False
    leaf = func_name.split("::")[-1]
    if leaf in AUTO_GENERATED_NAMES:
        return True
    return leaf.startswith(AUTO_RENAME_PREFIXES + AUTO_GENERATED_PREFIXES)


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
    if sid in (ida_idaapi.BADADDR, -1, None):
        sid = idc.add_struc(0xFFFFFFFF, type_name, False)
    return sid


def is_missing_member_offset(offset):
    if offset is None:
        return True
    if offset == ida_idaapi.BADADDR:
        return True
    if isinstance(offset, int) and offset < 0:
        return True
    return False


def add_generated_ptr_member(sid, member_name, offset, target_type_name=None):
    try:
        existing_off = idc.get_member_offset(sid, member_name)
    except Exception:
        existing_off = ida_idaapi.BADADDR

    if not is_missing_member_offset(existing_off):
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
    if not is_missing_member_offset(existing_off):
        return 0
    return idc.add_struc_member(sid, member_name, offset, ida_bytes.FF_DATA | u.PTR_TYPE, -1, u.PTR_SIZE)


def ensure_generated_byte_member(sid, member_name, offset, size):
    if size <= 0:
        return 0

    try:
        existing_off = idc.get_member_offset(sid, member_name)
    except Exception:
        existing_off = ida_idaapi.BADADDR

    if not is_missing_member_offset(existing_off):
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


def get_class_ptr_tinfo(class_type_name):
    return parse_decl_tinfo(build_class_ptr_decl(class_type_name))


def get_struct_member_tinfo(type_name):
    return parse_decl_tinfo("struct %s __pci_tmp;" % type_name)


def get_void_tinfo():
    tif = ida_typeinf.tinfo_t()
    try:
        if tif.create_simple_type(ida_typeinf.BT_VOID):
            return tif
    except Exception:
        pass
    return None


def get_uint_tinfo():
    return parse_decl_tinfo("unsigned int __pci_tmp;")


def build_adjusted_method_tinfo(func_ea, class_type_name, kind):
    base_tif = get_function_tinfo(func_ea)
    if base_tif is None or not base_tif.is_func():
        return None

    class_ptr_tif = get_class_ptr_tinfo(class_type_name)
    if class_ptr_tif is None:
        return None

    ftd = ida_typeinf.func_type_data_t()
    try:
        if not base_tif.get_func_details(ftd):
            return None
    except Exception:
        return None

    if len(ftd) > 0:
        try:
            farg = ida_typeinf.funcarg_t(ftd[0])
            farg.type = class_ptr_tif
            ftd[0] = farg
        except Exception:
            return None
    elif kind in ("constructor", "possible_constructor", "destructor", "possible_destructor", "scalar_deleting_destructor", "vector_deleting_destructor"):
        return None

    deleting_dtor = kind in ("scalar_deleting_destructor", "vector_deleting_destructor")

    if deleting_dtor:
        if len(ftd) < 2:
            return None
        uint_tif = get_uint_tinfo()
        if uint_tif is not None:
            try:
                farg = ida_typeinf.funcarg_t(ftd[1])
                farg.type = uint_tif
                ftd[1] = farg
            except Exception:
                return None

    if kind in ("constructor", "possible_constructor", "scalar_deleting_destructor", "vector_deleting_destructor"):
        ftd.rettype = class_ptr_tif
    elif kind in ("destructor", "possible_destructor"):
        void_tif = get_void_tinfo()
        if void_tif is not None:
            ftd.rettype = void_tif

    tif = ida_typeinf.tinfo_t()
    try:
        if tif.create_func(ftd):
            return tif
    except Exception:
        pass
    return None


def get_decomp_mode(config):
    mode = getattr(config, "decomp_mode", "balanced")
    if mode not in ("safe", "balanced", "aggressive"):
        mode = "balanced"
    return mode


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


def looks_like_memory_operand(op_text):
    op_text = (op_text or "").lower()
    if not op_text:
        return False
    if "[" in op_text or "]" in op_text:
        return True
    if " ptr " in op_text:
        return True
    return False


def extract_this_offset_from_operand(ea, op_idx):
    op_text = (idc.print_operand(ea, op_idx) or "").lower()
    if not op_text or not contains_this_reg(op_text) or not looks_like_memory_operand(op_text):
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

    if ops[0] and contains_this_reg(ops[0]) and looks_like_memory_operand(ops[0]):
        src_idxs = [i for i in range(1, 4) if ops[i]]
        if src_idxs:
            return 0, src_idxs, ops, mnem

    if mnem.startswith("st"):
        for mem_idx in (2, 1, 3):
            if mem_idx < len(ops) and ops[mem_idx] and contains_this_reg(ops[mem_idx]) and looks_like_memory_operand(ops[mem_idx]):
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


def record_recovered_field(owner_fields, offset, size, kind):
    record = owner_fields.get(offset)
    if record is None:
        owner_fields[offset] = {
            "offset": offset,
            "size": size,
            "kind": kind,
            "writes": 1,
        }
        return

    record["size"] = max(record.get("size", 0), size)
    record["kind"] = merge_field_kind(record.get("kind"), kind)
    record["writes"] = record.get("writes", 0) + 1


def merge_recovered_field_record(owner_fields, field, prefer_new=False):
    if not field:
        return

    try:
        offset = int(field.get("offset", -1))
    except Exception:
        offset = -1
    if offset < 0:
        return

    normalized = dict(field)
    normalized["offset"] = offset
    normalized["size"] = max(1, int(normalized.get("size", u.PTR_SIZE)))
    normalized["writes"] = max(1, int(normalized.get("writes", 1)))

    cur = owner_fields.get(offset)
    if cur is None:
        owner_fields[offset] = normalized
        return

    if prefer_new:
        cur["size"] = normalized["size"]
        cur["kind"] = normalized.get("kind") or cur.get("kind")
    else:
        cur["size"] = max(cur.get("size", 0), normalized["size"])
        cur["kind"] = merge_field_kind(cur.get("kind"), normalized.get("kind"))
    cur["writes"] = cur.get("writes", 0) + normalized["writes"]


def should_keep_pre_vfptr_field(field):
    if not field:
        return False
    kind = field.get("kind", "scalar")
    writes = max(0, int(field.get("writes", 0)))
    size = max(1, int(field.get("size", u.PTR_SIZE)))
    if kind in ("ptr", "float", "double"):
        return True
    if writes >= 2:
        return True
    if size != u.PTR_SIZE:
        return True
    return False


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
    if not is_missing_member_offset(existing_off):
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
        "base_",
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


def clear_all_generated_members(sid):
    members = list(idautils.StructMembers(sid))
    for offset, _, _ in reversed(members):
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


def get_resolved_target_eas(target, max_depth=3):
    resolved = []
    queue = [target]
    seen = set()

    while queue and max_depth >= 0:
        cur = queue.pop(0)
        if cur in (None, ida_idaapi.BADADDR) or cur in seen:
            continue
        seen.add(cur)
        resolved.append(cur)

        f = ida_funcs.get_func(cur)
        if not f or not (f.flags & ida_funcs.FUNC_THUNK):
            continue

        next_targets = []
        for item in get_function_items(f.start_ea, max_items=4):
            for ref in idautils.CodeRefsFrom(item, 0):
                if ref not in (ida_idaapi.BADADDR, f.start_ea):
                    next_targets.append(ref)
            if next_targets:
                break
        queue.extend(next_targets[:2])
        max_depth -= 1

    return resolved


def iter_target_name_variants(target):
    for ea in get_resolved_target_eas(target):
        raw_name = ida_name.get_short_name(ea) or ida_name.get_name(ea) or ""
        demangled = ida_name.demangle_name(raw_name, 0) or raw_name
        if raw_name:
            yield ea, raw_name, raw_name.lower()
        if demangled and demangled != raw_name:
            yield ea, demangled, demangled.lower()


def target_has_function_signature(target, require_return_ptr=False, require_first_arg_ptr=False):
    for ea in get_resolved_target_eas(target):
        tif = get_function_tinfo(ea)
        if tif is None or not tif.is_func():
            continue

        ftd = ida_typeinf.func_type_data_t()
        try:
            if not tif.get_func_details(ftd):
                continue
        except Exception:
            continue

        if require_return_ptr:
            try:
                if not ftd.rettype.is_ptr():
                    continue
            except Exception:
                continue

        if require_first_arg_ptr:
            if len(ftd) < 1:
                continue
            try:
                if not ftd[0].type.is_ptr():
                    continue
            except Exception:
                continue

        return True
    return False


def target_lacks_tinfo(target):
    for ea in get_resolved_target_eas(target):
        if get_function_tinfo(ea) is None:
            return True
    return False


def is_operator_new_like_target(target):
    saw_name_match = False
    for _, raw_name, lname in iter_target_name_variants(target):
        raw_lower = raw_name.lower()
        if "??2" in raw_name:
            return True
        if ALLOC_CALLEE_RE.search(lname):
            saw_name_match = True
            continue
        if any(token and token.lower() in lname for token in ALLOC_CALLEE_HINTS):
            saw_name_match = True
            continue
        if "__imp_" in raw_lower or raw_lower.startswith("j_"):
            if any(token and token.lower().strip() in lname for token in ALLOC_CALLEE_HINTS):
                saw_name_match = True
                continue
    if saw_name_match:
        if target_has_function_signature(target, require_return_ptr=True):
            return True
        if target_lacks_tinfo(target):
            saw_name_match = True
            return True
    return False


def is_delete_like_target(target):
    saw_name_match = False
    for _, raw_name, lname in iter_target_name_variants(target):
        raw_lower = raw_name.lower()
        if "??3" in raw_name:
            return True
        if DELETE_CALLEE_RE.search(lname):
            saw_name_match = True
            continue
        if any(token and token.lower() in lname for token in DELETE_CALLEE_HINTS):
            saw_name_match = True
            continue
        if "__imp_" in raw_lower or raw_lower.startswith("j_"):
            if any(token and token.lower().strip() in lname for token in DELETE_CALLEE_HINTS):
                saw_name_match = True
                continue
    if saw_name_match:
        if target_has_function_signature(target, require_first_arg_ptr=True):
            return True
        if target_lacks_tinfo(target):
            saw_name_match = True
            return True
    return False


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
    if is_missing_member_offset(moff):
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


def get_thunk_target(func_ea, cfunc_cache=None):
    f = ida_funcs.get_func(func_ea)
    if not f:
        return ida_idaapi.BADADDR

    if ida_hexrays is not None and initialize_hexrays():
        cfunc = get_cfunc_cached(func_ea, cfunc_cache)
        if cfunc is not None:
            class thunk_target_finder_t(ida_hexrays.ctree_visitor_t):
                def __init__(self):
                    ida_hexrays.ctree_visitor_t.__init__(self, ida_hexrays.CV_FAST)
                    self.target = ida_idaapi.BADADDR

                def visit_expr(self, expr):
                    if self.target != ida_idaapi.BADADDR or expr.op != ida_hexrays.cot_call:
                        return 0
                    target_ea = get_call_target_ea(expr)
                    if target_ea not in (ida_idaapi.BADADDR, func_ea):
                        self.target = target_ea
                    return 0

            visitor = thunk_target_finder_t()
            try:
                visitor.apply_to_exprs(cfunc.body, None)
            except Exception:
                visitor.target = ida_idaapi.BADADDR
            if visitor.target != ida_idaapi.BADADDR:
                return visitor.target

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


def get_thunk_adjustment(func_ea, cfunc_cache=None):
    ctree_adjust = get_thunk_adjustment_from_ctree(func_ea, cfunc_cache)
    if ctree_adjust is not None:
        return ctree_adjust

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


def function_calls_delete_like(func_ea, max_items=32, cfunc_cache=None):
    f = ida_funcs.get_func(func_ea)
    if not f:
        return False

    if function_calls_ctree_predicate(func_ea, is_delete_like_target, cfunc_cache):
        return True

    for item in get_function_items(f.start_ea, max_items=max_items):
        refs = [x for x in idautils.CodeRefsFrom(item, 0) if x != ida_idaapi.BADADDR]
        if not refs:
            continue
        mnem = idc.print_insn_mnem(item).lower()
        if mnem not in CALL_MNEMS and mnem not in THUNK_BRANCH_MNEMS:
            continue
        for target in refs:
            if is_delete_like_target(target):
                return True
    return False


def get_virtual_method_kind(func_ea, slot_index, cfunc_cache=None):
    name = ida_funcs.get_func_name(func_ea) or ida_name.get_name(func_ea) or ""
    demangled = ida_name.demangle_name(name, 0) or name
    lname = demangled.lower()
    leaf_name = name.split("::")[-1]
    thunk_target = get_thunk_target(func_ea, cfunc_cache)
    analysis_ea = thunk_target if thunk_target != ida_idaapi.BADADDR else func_ea

    if name.startswith("??_G") or "scalar deleting destructor" in lname or "scalar_deleting_destructor" in lname:
        return "scalar_deleting_destructor", thunk_target
    if name.startswith("??_E") or "vector deleting destructor" in lname or "vector_deleting_destructor" in lname:
        return "vector_deleting_destructor", thunk_target
    if name.startswith("??1") or leaf_name == "destructor":
        return "destructor", thunk_target
    if ("`destructor'" in lname or " destructor" in lname) and not is_auto_named(name):
        return "destructor", thunk_target

    delete_info = analyze_deleting_destructor_behavior(analysis_ea, cfunc_cache)
    if delete_info.get("delete_call"):
        if delete_info.get("vector_flag"):
            return "vector_deleting_destructor", thunk_target
        if slot_index == 1 and (delete_info.get("has_flags_arg") or delete_info.get("uses_flags")):
            return "vector_deleting_destructor", thunk_target
        if delete_info.get("delete_flag") or delete_info.get("has_flags_arg") or delete_info.get("uses_flags") or delete_info.get("returns_self"):
            return "scalar_deleting_destructor", thunk_target
        if slot_index == 0:
            return "scalar_deleting_destructor", thunk_target
        if slot_index == 1:
            return "vector_deleting_destructor", thunk_target
    if thunk_target != ida_idaapi.BADADDR:
        return "thunk", thunk_target
    return "virtual_method", thunk_target


def get_ctor_dtor_kind(func_ea, cfunc_cache=None):
    thunk_target = get_thunk_target(func_ea, cfunc_cache)
    analysis_ea = thunk_target if thunk_target != ida_idaapi.BADADDR else func_ea
    if function_calls_delete_like(analysis_ea, cfunc_cache=cfunc_cache):
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
        return "%s * %s%s(%s *self, unsigned int flags);" % (class_ref, callconv, func_token, class_ref)
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
        return "%s * %s(%s *self, unsigned int flags);" % (class_ref, ptr_decl, class_ref)
    return "void %s(%s *self, ...);" % (ptr_decl, class_ref)


def is_generic_auto_type(current_name, current_type):
    if not current_type:
        return True
    if TYPE_PREFIX in current_type:
        return True
    if not is_auto_named(current_name):
        return False

    lowered = current_type.lower()
    if "::" in current_type:
        return False
    if "struct " in lowered or "class " in lowered or "enum " in lowered:
        return False
    if "_qword" in lowered or "_dword" in lowered or "_word" in lowered or "_byte" in lowered:
        return True
    if "void *" in lowered or "void **" in lowered:
        return True
    if "..." in current_type and "*" in current_type:
        return True
    return bool(GENERIC_AUTO_TYPE_RE.search(current_type))


def apply_generated_signature(func_ea, class_type_name, kind, force=False):
    f = ida_funcs.get_func(func_ea)
    if not f:
        return False

    current_name = ida_funcs.get_func_name(f.start_ea) or ""
    current_type = idc.get_type(f.start_ea)
    existing_tif = get_function_tinfo(f.start_ea)
    can_override_generic = is_generic_auto_type(current_name, current_type)
    if existing_tif is not None and current_type and TYPE_PREFIX not in current_type and not can_override_generic:
        return False
    if current_type and not force and not is_auto_named(current_name) and TYPE_PREFIX not in current_type and not can_override_generic:
        return False

    exact_tif = build_adjusted_method_tinfo(f.start_ea, class_type_name, kind)
    if exact_tif is not None:
        try:
            if ida_typeinf.apply_tinfo(f.start_ea, exact_tif, ida_typeinf.TINFO_DEFINITE):
                return True
        except Exception:
            pass

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


def get_arg_lvars(func_ea, cfunc_cache=None):
    _, lvars = get_cfunc_lvars(func_ea, cfunc_cache)
    if not lvars:
        return []

    result = []
    for lv in lvars:
        try:
            if lv.is_arg_var() and not lv.is_fake_var():
                result.append(lv)
        except Exception:
            continue
    return result


def get_ctree_local_var(expr, require_ptr=False, allow_args=False):
    expr = strip_ctree_wrappers(expr)
    if expr is None or expr.op != ida_hexrays.cot_var:
        return None

    try:
        lv = expr.v.getv()
    except Exception:
        return None

    try:
        if not allow_args and (lv.is_arg_var() or lv.is_fake_var() or lv.is_result_var()):
            return None
    except Exception:
        return None

    if require_ptr:
        try:
            if lv.width != u.PTR_SIZE:
                return None
        except Exception:
            return None

    return lv


def get_ctree_lvar(expr):
    expr = strip_ctree_wrappers(expr)
    if expr is None or expr.op != ida_hexrays.cot_var:
        return None

    try:
        return expr.v.getv()
    except Exception:
        return None


def ctree_lvar_matches(expr, target_lv):
    if target_lv is None:
        return False

    lv = get_ctree_lvar(expr)
    if lv is None:
        return False

    try:
        if lv == target_lv:
            return True
    except Exception:
        pass

    try:
        lidx = getattr(lv, "idx", None)
        tidx = getattr(target_lv, "idx", None)
        if lidx is not None and tidx is not None and lidx == tidx:
            return True
    except Exception:
        pass

    lname = getattr(lv, "name", "") or ""
    tname = getattr(target_lv, "name", "") or ""
    return bool(lname and lname == tname)


def get_call_target_ea(call_expr):
    call_expr = strip_ctree_wrappers(call_expr)
    if call_expr is None or call_expr.op != ida_hexrays.cot_call:
        return ida_idaapi.BADADDR

    callee = strip_ctree_wrappers(call_expr.x)
    if callee is None or callee.op != ida_hexrays.cot_obj:
        return ida_idaapi.BADADDR
    return callee.obj_ea


def is_ctree_operator_new_call(expr):
    target_ea = get_call_target_ea(expr)
    if target_ea == ida_idaapi.BADADDR:
        return False
    return is_operator_new_like_target(target_ea)


def rank_lvar_candidates(counts):
    if not counts:
        return None

    ranked = sorted(
        counts.items(),
        key=lambda item: (-item[1], 0 if AUTO_LOCAL_PTR_RE.match(item[0]) else 1, item[0]))
    if len(ranked) == 1:
        return ranked[0][0]
    if ranked[0][1] > ranked[1][1]:
        return ranked[0][0]

    best_score = ranked[0][1]
    best_auto = [name for name, score in ranked if score == best_score and AUTO_LOCAL_PTR_RE.match(name)]
    if len(best_auto) == 1:
        return best_auto[0]
    return None


if ida_hexrays is not None:
    class ctor_result_collector_t(ida_hexrays.ctree_visitor_t):
        def __init__(self, ctor_targets):
            ida_hexrays.ctree_visitor_t.__init__(self, ida_hexrays.CV_FAST)
            self.ctor_targets = set(x for x in ctor_targets if x != ida_idaapi.BADADDR)
            self.alloc_lvars = {}
            self.ctor_lvars = {}

        def add_candidate(self, store, lv):
            if lv is None:
                return
            name = lv.name or ""
            if not name:
                return
            store[name] = store.get(name, 0) + 1

        def visit_expr(self, expr):
            expr = strip_ctree_wrappers(expr)
            if expr is None:
                return 0

            if expr.op == ida_hexrays.cot_asg:
                lhs = strip_ctree_wrappers(expr.x)
                rhs = strip_ctree_wrappers(expr.y)
                lhs_lv = get_ctree_local_var(lhs, require_ptr=True)
                if lhs_lv is not None:
                    if is_ctree_operator_new_call(rhs):
                        self.add_candidate(self.alloc_lvars, lhs_lv)
                    if get_call_target_ea(rhs) in self.ctor_targets:
                        self.add_candidate(self.ctor_lvars, lhs_lv)
                return 0

            if expr.op == ida_hexrays.cot_call:
                target_ea = get_call_target_ea(expr)
                if target_ea not in self.ctor_targets:
                    return 0
                try:
                    args = list(expr.a)
                except Exception:
                    args = []
                if not args:
                    return 0
                lv = get_ctree_local_var(args[0], require_ptr=True)
                if lv is not None:
                    self.add_candidate(self.ctor_lvars, lv)
            return 0
else:
    class ctor_result_collector_t(object):
        def __init__(self, ctor_targets):
            self.ctor_targets = set()
            self.alloc_lvars = {}
            self.ctor_lvars = {}


def find_ctor_result_lvar_name(func_ea, ctor_targets, cfunc_cache=None):
    if ida_hexrays is None or not ctor_targets or not initialize_hexrays():
        return None

    cfunc = get_cfunc_cached(func_ea, cfunc_cache)
    if cfunc is None:
        return None

    visitor = ctor_result_collector_t(ctor_targets)
    try:
        visitor.apply_to_exprs(cfunc.body, None)
    except Exception:
        return None

    shared = {}
    for name, ctor_score in visitor.ctor_lvars.items():
        total = ctor_score
        if name in visitor.alloc_lvars:
            total += visitor.alloc_lvars[name] * 2
        shared[name] = total

    candidate = rank_lvar_candidates(shared)
    if candidate:
        return candidate

    candidate = rank_lvar_candidates(visitor.ctor_lvars)
    if candidate:
        return candidate

    return None


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


def apply_hexrays_ctor_result_type(func_ea, class_type_name, ctor_targets=None, cfunc_cache=None):
    if cfunc_cache is None and ctor_targets is not None and not isinstance(ctor_targets, (list, tuple, set)):
        cfunc_cache = ctor_targets
        ctor_targets = None

    target_name = find_ctor_result_lvar_name(func_ea, ctor_targets or [], cfunc_cache)
    if target_name:
        return apply_hexrays_lvar_type(func_ea, target_name, build_class_ptr_decl(class_type_name), cfunc_cache)

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


def strip_ctree_wrappers(expr):
    while expr is not None and expr.op in (ida_hexrays.cot_cast, ida_hexrays.cot_ref):
        expr = expr.x
    return expr


def get_ctree_num_value(expr):
    expr = strip_ctree_wrappers(expr)
    if expr is None or expr.op != ida_hexrays.cot_num:
        return None

    for getter in (
            lambda: expr.numval(),
            lambda: expr.n.value(ida_typeinf.tinfo_t()),
            lambda: expr.n._value):
        try:
            return int(getter())
        except Exception:
            continue
    return None


def get_ctree_obj_ea(expr):
    expr = strip_ctree_wrappers(expr)
    if expr is None:
        return ida_idaapi.BADADDR
    if expr.op == ida_hexrays.cot_obj:
        return expr.obj_ea
    return ida_idaapi.BADADDR


def expr_references_ea(expr, target_ea):
    return get_ctree_obj_ea(expr) == target_ea


def cexpr_is_thisarg(expr):
    expr = strip_ctree_wrappers(expr)
    if expr is None or expr.op != ida_hexrays.cot_var:
        return False
    try:
        lv = expr.v.getv()
    except Exception:
        return False
    try:
        if lv.is_thisarg():
            return True
    except Exception:
        pass
    try:
        if lv.is_arg_var() and (lv.name or "").lower() in ("this", "self", "a1", "arg1", "arg0"):
            return True
    except Exception:
        pass
    return False


def get_ctree_this_adjust(expr):
    expr = strip_ctree_wrappers(expr)
    if expr is None:
        return None
    if cexpr_is_thisarg(expr):
        return 0

    if expr.op == ida_hexrays.cot_add:
        left = get_ctree_this_adjust(expr.x)
        if left is not None:
            imm = get_ctree_num_value(expr.y)
            if imm is not None:
                return left + imm
        right = get_ctree_this_adjust(expr.y)
        if right is not None:
            imm = get_ctree_num_value(expr.x)
            if imm is not None:
                return right + imm
        return None

    if expr.op == ida_hexrays.cot_sub:
        left = get_ctree_this_adjust(expr.x)
        if left is None:
            return None
        imm = get_ctree_num_value(expr.y)
        if imm is None:
            return None
        return left - imm

    return None


def get_ctree_expr_size(expr):
    expr = strip_ctree_wrappers(expr)
    if expr is None:
        return 0
    try:
        if expr.refwidth and expr.refwidth > 0:
            return int(expr.refwidth)
    except Exception:
        pass
    try:
        if expr.op == ida_hexrays.cot_memptr and expr.ptrsize > 0:
            return int(expr.ptrsize)
    except Exception:
        pass
    try:
        size = expr.type.get_size()
        if size and size > 0:
            return int(size)
    except Exception:
        pass
    return 0


def get_ctree_field_kind(expr, size, vtable_eas):
    expr = strip_ctree_wrappers(expr)
    if expr is None:
        return "scalar"

    try:
        if expr.is_vftable():
            return None
    except Exception:
        pass

    if expr.op == ida_hexrays.cot_obj and expr.obj_ea in vtable_eas:
        return None
    if expr.op in (ida_hexrays.cot_obj, ida_hexrays.cot_str):
        return "ptr"

    try:
        tif = expr.type
    except Exception:
        tif = None

    if tif is not None:
        try:
            if tif.is_ptr():
                return "ptr"
        except Exception:
            pass
        try:
            if tif.is_double():
                return "double"
        except Exception:
            pass
        try:
            if tif.is_float() or tif.is_floating():
                return "float" if size <= 4 else "double"
        except Exception:
            pass

    if expr.op == ida_hexrays.cot_call:
        target_ea = get_call_target_ea(expr)
        if target_ea != ida_idaapi.BADADDR and is_operator_new_like_target(target_ea):
            return "ptr"

    return "scalar"


def cexpr_member_uses_union_index(expr):
    expr = strip_ctree_wrappers(expr)
    if expr is None or expr.op not in (ida_hexrays.cot_memptr, ida_hexrays.cot_memref):
        return False

    base = strip_ctree_wrappers(expr.x)
    if base is None:
        return False

    try:
        tif = base.type
    except Exception:
        return False

    try:
        if expr.op == ida_hexrays.cot_memptr and tif.is_ptr():
            tif = tif.get_pointed_object()
    except Exception:
        pass

    try:
        return bool(tif and tif.is_union())
    except Exception:
        return False


def get_candidate_flags_arg_lvar(func_ea, cfunc_cache=None):
    arg_lvars = get_arg_lvars(func_ea, cfunc_cache)
    if len(arg_lvars) < 2:
        return None
    return arg_lvars[1]


def function_returns_self_tail(func_ea, max_items=8):
    items = get_function_items(func_ea)
    if not items:
        return False

    for item in reversed(items[-max_items:]):
        mnem = (idc.print_insn_mnem(item) or "").lower()
        if not mnem or mnem.startswith("ret") or mnem in ("nop",):
            continue

        op0 = (idc.print_operand(item, 0) or "").lower()
        op1 = (idc.print_operand(item, 1) or "").lower()
        if mnem in ("mov", "lea") and op0 in ("eax", "rax", "r0", "x0"):
            if op1 in THIS_REG_NAMES:
                return True
            if contains_this_reg(op1):
                imm = extract_this_offset_from_operand(item, 1)
                if imm in (None, 0):
                    return True
        break
    return False


if ida_hexrays is not None:
    class deleting_dtor_analyzer_t(ida_hexrays.ctree_visitor_t):
        def __init__(self, flags_lvar=None):
            ida_hexrays.ctree_visitor_t.__init__(self, ida_hexrays.CV_FAST)
            self.flags_lvar = flags_lvar
            self.uses_flags = False
            self.delete_flag = False
            self.vector_flag = False
            self.delete_call = False

        def visit_expr(self, expr):
            expr = strip_ctree_wrappers(expr)
            if expr is None:
                return 0

            if ctree_lvar_matches(expr, self.flags_lvar):
                self.uses_flags = True

            if expr.op == ida_hexrays.cot_band:
                left = strip_ctree_wrappers(expr.x)
                right = strip_ctree_wrappers(expr.y)
                mask = None
                if ctree_lvar_matches(left, self.flags_lvar):
                    mask = get_ctree_num_value(right)
                elif ctree_lvar_matches(right, self.flags_lvar):
                    mask = get_ctree_num_value(left)
                if mask is not None:
                    mask = int(mask) & 0xffffffff
                    self.uses_flags = True
                    if mask & 1:
                        self.delete_flag = True
                    if mask & 2:
                        self.vector_flag = True
                return 0

            if expr.op == ida_hexrays.cot_call:
                target_ea = get_call_target_ea(expr)
                if target_ea != ida_idaapi.BADADDR and is_delete_like_target(target_ea):
                    self.delete_call = True
            return 0


    class call_target_matcher_t(ida_hexrays.ctree_visitor_t):
        def __init__(self, predicate):
            ida_hexrays.ctree_visitor_t.__init__(self, ida_hexrays.CV_FAST)
            self.predicate = predicate
            self.matched = False

        def visit_expr(self, expr):
            if self.matched or expr.op != ida_hexrays.cot_call:
                return 0
            target_ea = get_call_target_ea(expr)
            if target_ea != ida_idaapi.BADADDR and self.predicate(target_ea):
                self.matched = True
            return 0


    class vtable_store_finder_t(ida_hexrays.ctree_visitor_t):
        def __init__(self, vtable_ea, expected_offset=None):
            ida_hexrays.ctree_visitor_t.__init__(self, ida_hexrays.CV_FAST)
            self.vtable_ea = vtable_ea
            self.expected_offset = expected_offset
            self.matches = []

        def visit_expr(self, expr):
            if expr.op != ida_hexrays.cot_asg:
                return 0

            lhs = strip_ctree_wrappers(expr.x)
            rhs = strip_ctree_wrappers(expr.y)
            if lhs is None or lhs.op not in (ida_hexrays.cot_memptr, ida_hexrays.cot_memref):
                return 0
            if not cexpr_is_thisarg(lhs.x) or cexpr_member_uses_union_index(lhs):
                return 0

            offset = int(lhs.m)
            if self.expected_offset is not None and offset != self.expected_offset:
                return 0
            if not expr_references_ea(rhs, self.vtable_ea):
                return 0

            self.matches.append({
                "offset": offset,
                "ea": getattr(expr, "ea", ida_idaapi.BADADDR),
            })
            return 0


    class vbtable_store_finder_t(ida_hexrays.ctree_visitor_t):
        def __init__(self, valid_offsets, forbidden_eas):
            ida_hexrays.ctree_visitor_t.__init__(self, ida_hexrays.CV_FAST)
            self.valid_offsets = set(valid_offsets)
            self.forbidden_eas = set(forbidden_eas)
            self.candidates = {}

        def add_candidate(self, offset, target_ea):
            if offset not in self.valid_offsets:
                return
            if target_ea in (None, ida_idaapi.BADADDR):
                return
            if target_ea in self.forbidden_eas:
                return
            if not u.within(target_ea, u.valid_ranges):
                return
            if u.within(target_ea, u.code_ranges):
                return

            counts = self.candidates.setdefault(offset, {})
            counts[target_ea] = counts.get(target_ea, 0) + 1

        def visit_expr(self, expr):
            if expr.op != ida_hexrays.cot_asg:
                return 0

            lhs = strip_ctree_wrappers(expr.x)
            if lhs is None or lhs.op not in (ida_hexrays.cot_memptr, ida_hexrays.cot_memref):
                return 0
            if not cexpr_is_thisarg(lhs.x) or cexpr_member_uses_union_index(lhs):
                return 0

            offset = int(lhs.m)
            if offset not in self.valid_offsets:
                return 0

            self.add_candidate(offset, get_ctree_obj_ea(expr.y))
            return 0


    class ctor_field_collector_t(ida_hexrays.ctree_visitor_t):
        def __init__(self, owner_name, owner_vfptr_offsets, vtable_eas):
            ida_hexrays.ctree_visitor_t.__init__(self, ida_hexrays.CV_FAST)
            self.owner_name = owner_name
            self.owner_vfptr_offsets = owner_vfptr_offsets
            self.vtable_eas = vtable_eas
            self.fields = {}

        def visit_expr(self, expr):
            if expr.op != ida_hexrays.cot_asg:
                return 0

            lhs = strip_ctree_wrappers(expr.x)
            if lhs is None or lhs.op not in (ida_hexrays.cot_memptr, ida_hexrays.cot_memref):
                return 0
            if not cexpr_is_thisarg(lhs.x):
                return 0
            if cexpr_member_uses_union_index(lhs):
                return 0

            offset = int(lhs.m)
            if offset < 0 or offset > 0x2000 or offset in self.owner_vfptr_offsets:
                return 0

            rhs = strip_ctree_wrappers(expr.y)
            size = get_ctree_expr_size(lhs) or get_ctree_expr_size(rhs) or u.PTR_SIZE
            if size <= 0:
                size = u.PTR_SIZE
            if size > 0x40:
                size = u.PTR_SIZE

            kind = get_ctree_field_kind(rhs, size, self.vtable_eas)
            if kind is None:
                return 0

            record = self.fields.get(offset)
            if record is None:
                record = {"offset": offset, "size": size, "kind": kind, "writes": 0}
                self.fields[offset] = record
            else:
                record["size"] = max(record["size"], size)
                record["kind"] = merge_field_kind(record.get("kind"), kind)
            record["writes"] += 1
            return 0
else:
    class deleting_dtor_analyzer_t(object):
        def __init__(self, flags_lvar=None):
            self.flags_lvar = flags_lvar
            self.uses_flags = False
            self.delete_flag = False
            self.vector_flag = False
            self.delete_call = False


    class call_target_matcher_t(object):
        def __init__(self, predicate):
            self.predicate = predicate
            self.matched = False


    class vtable_store_finder_t(object):
        def __init__(self, vtable_ea, expected_offset=None):
            self.vtable_ea = vtable_ea
            self.expected_offset = expected_offset
            self.matches = []


    class vbtable_store_finder_t(object):
        def __init__(self, valid_offsets, forbidden_eas):
            self.valid_offsets = set(valid_offsets)
            self.forbidden_eas = set(forbidden_eas)
            self.candidates = {}


    class ctor_field_collector_t(object):
        def __init__(self, owner_name, owner_vfptr_offsets, vtable_eas):
            self.fields = {}


def analyze_deleting_destructor_behavior(func_ea, cfunc_cache=None):
    info = {
        "has_flags_arg": False,
        "uses_flags": False,
        "delete_flag": False,
        "vector_flag": False,
        "delete_call": False,
        "returns_self": function_returns_self_tail(func_ea),
    }

    flags_lvar = get_candidate_flags_arg_lvar(func_ea, cfunc_cache)
    info["has_flags_arg"] = flags_lvar is not None

    cfunc = get_cfunc_cached(func_ea, cfunc_cache)
    if cfunc is not None and ida_hexrays is not None:
        visitor = deleting_dtor_analyzer_t(flags_lvar)
        try:
            visitor.apply_to_exprs(cfunc.body, None)
        except Exception:
            visitor = None
        if visitor is not None:
            info["uses_flags"] = bool(visitor.uses_flags)
            info["delete_flag"] = bool(visitor.delete_flag)
            info["vector_flag"] = bool(visitor.vector_flag)
            info["delete_call"] = bool(visitor.delete_call)

    if not info["delete_call"]:
        info["delete_call"] = function_calls_delete_like(func_ea, cfunc_cache=cfunc_cache)
    return info


def function_calls_ctree_predicate(func_ea, predicate, cfunc_cache=None):
    if ida_hexrays is None or not initialize_hexrays():
        return False

    cfunc = get_cfunc_cached(func_ea, cfunc_cache)
    if cfunc is None:
        return False

    visitor = call_target_matcher_t(predicate)
    try:
        visitor.apply_to_exprs(cfunc.body, None)
    except Exception:
        return False
    return visitor.matched


def function_writes_vtable_to_this(func_ea, vtable_ea, expected_offset=None, cfunc_cache=None):
    if ida_hexrays is None or not initialize_hexrays():
        return []

    cfunc = get_cfunc_cached(func_ea, cfunc_cache)
    if cfunc is None:
        return []

    visitor = vtable_store_finder_t(vtable_ea, expected_offset=expected_offset)
    try:
        visitor.apply_to_exprs(cfunc.body, None)
    except Exception:
        return []
    return visitor.matches


def collect_vbtable_store_candidates_ctree(func_ea, valid_offsets, forbidden_eas, cfunc_cache=None):
    if ida_hexrays is None or not initialize_hexrays():
        return {}

    cfunc = get_cfunc_cached(func_ea, cfunc_cache)
    if cfunc is None:
        return {}

    visitor = vbtable_store_finder_t(valid_offsets, forbidden_eas)
    try:
        visitor.apply_to_exprs(cfunc.body, None)
    except Exception:
        return {}
    return visitor.candidates


def get_thunk_adjustment_from_ctree(func_ea, cfunc_cache=None):
    thunk_target = get_thunk_target(func_ea, cfunc_cache)
    if thunk_target == ida_idaapi.BADADDR or ida_hexrays is None or not initialize_hexrays():
        return None

    cfunc = get_cfunc_cached(func_ea, cfunc_cache)
    if cfunc is None:
        return None

    class thunk_adjust_finder_t(ida_hexrays.ctree_visitor_t):
        def __init__(self, target_eas):
            ida_hexrays.ctree_visitor_t.__init__(self, ida_hexrays.CV_FAST)
            self.target_eas = set(target_eas)
            self.adjust = None

        def visit_expr(self, expr):
            if self.adjust is not None or expr.op != ida_hexrays.cot_call:
                return 0
            target_ea = get_call_target_ea(expr)
            if target_ea not in self.target_eas:
                return 0
            try:
                args = list(expr.a)
            except Exception:
                return 0
            if not args:
                return 0
            adjust = get_ctree_this_adjust(args[0])
            if adjust is not None:
                self.adjust = adjust
            return 0

    visitor = thunk_adjust_finder_t(get_resolved_target_eas(thunk_target))
    try:
        visitor.apply_to_exprs(cfunc.body, None)
    except Exception:
        return None
    return visitor.adjust


def merge_recovered_field_maps(base_fields, new_fields, prefer_new=False):
    merged = {}
    for owner_name, fields in base_fields.items():
        merged[owner_name] = {}
        for offset, field in fields.items():
            merged[owner_name][offset] = dict(field)

    for owner_name, fields in new_fields.items():
        owner_map = merged.setdefault(owner_name, {})
        for offset, field in fields.items():
            merged_field = dict(field)
            merged_field["offset"] = offset
            merge_recovered_field_record(owner_map, merged_field, prefer_new=prefer_new)
    return merged


def collect_constructor_field_writes_ctree(layouts, vtables, cfunc_cache):
    if ida_hexrays is None or not initialize_hexrays():
        return {}

    vtable_eas = set(entry["vftable_ea"] for entry in vtables)
    owner_vfptr_offsets = {}
    for owner_name in layouts:
        owner_vfptr_offsets[owner_name] = set(x["offset"] for x in layouts[owner_name])

    fields = {}
    ctor_map = {}
    for entry in vtables:
        owner_name = entry["owner_name"]
        for f in get_vftable_ref_funcs(entry["vftable_ea"], expected_offset=entry["offset"], cfunc_cache=cfunc_cache):
            if get_ctor_dtor_kind(f.start_ea, cfunc_cache) == "possible_constructor":
                ctor_map.setdefault(owner_name, set()).add(f.start_ea)

    for owner_name, funcs in ctor_map.items():
        owner_fields = fields.setdefault(owner_name, {})
        for func_ea in funcs:
            cfunc = get_cfunc_cached(func_ea, cfunc_cache)
            if cfunc is None:
                continue
            visitor = ctor_field_collector_t(owner_name, owner_vfptr_offsets.get(owner_name, set()), vtable_eas)
            try:
                visitor.apply_to_exprs(cfunc.body, None)
            except Exception:
                continue
            for offset, field in visitor.fields.items():
                merged_field = dict(field)
                merged_field["offset"] = offset
                merge_recovered_field_record(owner_fields, merged_field)
    return fields


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
            "embed_type_name": build_generated_type_name("subobj", "%s_%s" % (owner_name, col.name), col.offset),
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


def generate_embedded_subobject_type(entry, entry_size_estimates):
    sid = ensure_generated_struct(entry["embed_type_name"])
    idc.set_struc_cmt(sid, "%s: embedded subobject type for %s in %s (offset %#x)" % (
        COMMENT_TAG,
        entry["subobject_name"],
        entry["owner_name"],
        entry["offset"]), 1)
    clear_generated_layout_members(sid)

    add_generated_ptr_member(sid, "vfptr", 0, entry["vtbl_type_name"])
    set_member_comment(sid, "vfptr", "%s: vfptr for %s embedded subobject" % (COMMENT_TAG, entry["subobject_name"]))

    estimate = max(u.PTR_SIZE, entry_size_estimates.get((entry["owner_name"], entry["offset"]), u.PTR_SIZE))
    tail_size = max(0, estimate - u.PTR_SIZE)
    if tail_size > 0:
        ensure_generated_byte_member(sid, "gap_%x" % u.PTR_SIZE, u.PTR_SIZE, tail_size)
        set_member_comment(sid, "gap_%x" % u.PTR_SIZE, "%s: estimated embedded subobject tail" % COMMENT_TAG)


def populate_standalone_subobject_types(class_type_names, layouts, vtables, entry_size_estimates):
    for class_name, type_name in class_type_names.items():
        if class_name in layouts:
            continue

        candidates = [entry for entry in vtables if entry["subobject_name"] == class_name]
        if not candidates:
            continue

        preferred = sorted(
            candidates,
            key=lambda entry: (
                0 if (entry["owner_name"] == class_name and entry["offset"] == 0) else 1,
                entry["offset"],
                entry["owner_name"]))[0]

        sid = idc.get_struc_id(type_name)
        if sid == ida_idaapi.BADADDR:
            sid = ensure_generated_struct(type_name)
        clear_generated_layout_members(sid)

        if add_generated_ptr_member(sid, "vfptr", 0, preferred["vtbl_type_name"]) == 0:
            set_member_comment(
                sid,
                "vfptr",
                "%s: fallback vfptr for %s (from %s @ %#x)" % (
                    COMMENT_TAG,
                    class_name,
                    preferred["owner_name"],
                    preferred["offset"]))

        estimate = u.PTR_SIZE
        for entry in candidates:
            estimate = max(
                estimate,
                max(u.PTR_SIZE, entry_size_estimates.get((entry["owner_name"], entry["offset"]), u.PTR_SIZE)))

        tail_size = max(0, estimate - u.PTR_SIZE)
        if tail_size > 0:
            gap_name = get_gap_member_name(u.PTR_SIZE)
            if ensure_generated_byte_member(sid, gap_name, u.PTR_SIZE, tail_size) == 0:
                set_member_comment(
                    sid,
                    gap_name,
                    "%s: fallback estimated class tail for %s" % (COMMENT_TAG, class_name))


def merge_count_map(dst, src):
    for key, value in src.items():
        dst[key] = dst.get(key, 0) + value


def collect_vbtable_store_candidates_instruction(func_ea, valid_offsets, forbidden_eas):
    candidates = {}
    valid_offsets = set(valid_offsets)
    forbidden_eas = set(forbidden_eas)

    for item in get_function_items(func_ea, max_items=96):
        mem_idx, _, _, _ = get_this_store_info(item)
        if mem_idx is None:
            continue

        offset = extract_this_offset_from_operand(item, mem_idx)
        if offset not in valid_offsets:
            continue

        counts = candidates.setdefault(offset, {})
        for ref in idautils.DataRefsFrom(item):
            if ref in forbidden_eas:
                continue
            if not u.within(ref, u.valid_ranges) or u.within(ref, u.code_ranges):
                continue
            counts[ref] = counts.get(ref, 0) + 1
    return candidates


def pick_best_counted_target(counts):
    if not counts:
        return ida_idaapi.BADADDR
    return sorted(counts.items(), key=lambda item: (-item[1], item[0]))[0][0]


def collect_virtual_inheritance_hints(paths, vtables=None, cfunc_cache=None):
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

            hint = owner_hints.setdefault(pdisp, {
                "type_name": build_generated_type_name("vbtable", owner_name, pdisp),
                "entries": {},
                "bases": set(),
                "table_ea": ida_idaapi.BADADDR,
                "comment": "",
            })
            hint["bases"].add(bcd.name)
            if vdisp is not None and vdisp >= 0:
                hint["entries"][int(vdisp)] = bcd.name

    for owner_name, owner_hints in hints.items():
        for pdisp, hint in owner_hints.items():
            base_names = sorted(hint["bases"])
            suffix = ", ".join(base_names[:3])
            if len(base_names) > 3:
                suffix += ", ..."
            comment = "%s: vbptr" % COMMENT_TAG
            if suffix:
                comment += " for %s" % suffix
            comment += " (pdisp %#x" % pdisp
            if hint["entries"]:
                comment += ", vdisp %s" % ", ".join("%#x" % x for x in sorted(hint["entries"]))
            comment += ")"
            hint["comment"] = comment

    if not hints or not vtables:
        return hints

    forbidden_eas = set(entry["vftable_ea"] for entry in vtables)
    ctor_map = {}
    for entry in vtables:
        owner_name = entry["owner_name"]
        if owner_name not in hints:
            continue
        for f in get_vftable_ref_funcs(entry["vftable_ea"], expected_offset=entry["offset"], cfunc_cache=cfunc_cache):
            if get_ctor_dtor_kind(f.start_ea, cfunc_cache) == "possible_constructor":
                ctor_map.setdefault(owner_name, set()).add(f.start_ea)

    for owner_name, funcs in ctor_map.items():
        owner_hints = hints.get(owner_name, {})
        valid_offsets = set(owner_hints.keys())
        if not valid_offsets:
            continue
        merged = {}
        for func_ea in funcs:
            ctree_candidates = collect_vbtable_store_candidates_ctree(func_ea, valid_offsets, forbidden_eas, cfunc_cache)
            for offset, counts in ctree_candidates.items():
                merge_count_map(merged.setdefault(offset, {}), counts)

            inst_candidates = collect_vbtable_store_candidates_instruction(func_ea, valid_offsets, forbidden_eas)
            for offset, counts in inst_candidates.items():
                merge_count_map(merged.setdefault(offset, {}), counts)

        for offset, hint in owner_hints.items():
            hint["table_ea"] = pick_best_counted_target(merged.get(offset, {}))

    return hints


def collect_constructor_field_writes(layouts, vtables, cfunc_cache=None):
    vtable_eas = set(entry["vftable_ea"] for entry in vtables)
    owner_vfptr_offsets = {}
    for owner_name in layouts:
        owner_vfptr_offsets[owner_name] = set(x["offset"] for x in layouts[owner_name])

    fields = {}
    ctor_map = {}
    for entry in vtables:
        owner_name = entry["owner_name"]
        for f in get_vftable_ref_funcs(entry["vftable_ea"], expected_offset=entry["offset"], cfunc_cache=cfunc_cache):
            if get_ctor_dtor_kind(f.start_ea, cfunc_cache) == "possible_constructor":
                ctor_map.setdefault(owner_name, set()).add(f.start_ea)

    for owner_name, funcs in ctor_map.items():
        owner_fields = fields.setdefault(owner_name, {})
        for func_ea in funcs:
            pending = {}
            saw_owner_vfptr = False
            for item in get_function_items(func_ea, max_items=96):
                mem_idx, src_idxs, ops, mnem = get_this_store_info(item)
                if mem_idx is None:
                    continue

                offset = extract_this_offset_from_operand(item, mem_idx)
                if offset is None or offset > 0x2000:
                    continue
                if offset in owner_vfptr_offsets.get(owner_name, set()):
                    saw_owner_vfptr = True
                    continue

                size = get_store_size(item, mnem, mem_idx, src_idxs, ops)
                if size <= 0:
                    size = u.PTR_SIZE
                if size > 0x40:
                    size = u.PTR_SIZE

                kind = get_field_kind(item, mnem, src_idxs, ops, vtable_eas, size)
                if kind is None:
                    continue

                if not saw_owner_vfptr:
                    record_recovered_field(pending, offset, size, kind)
                    continue

                record_recovered_field(owner_fields, offset, size, kind)

            for field in pending.values():
                if not saw_owner_vfptr or should_keep_pre_vfptr_field(field):
                    merge_recovered_field_record(owner_fields, field)

    return fields


def get_layout_upper_bound(owner_name, layouts, entry_size_estimates):
    limit = u.PTR_SIZE
    for entry in layouts.get(owner_name, []):
        estimate = max(u.PTR_SIZE, entry_size_estimates.get((owner_name, entry["offset"]), u.PTR_SIZE))
        limit = max(limit, entry["offset"] + estimate)
    return limit


def filter_instruction_recovered_fields(instr_fields, ctree_fields, layouts, entry_size_estimates):
    filtered = {}
    for owner_name, fields in instr_fields.items():
        owner_limit = get_layout_upper_bound(owner_name, layouts, entry_size_estimates)
        owner_ctree = ctree_fields.get(owner_name, {})
        owner_filtered = {}

        for offset, field in fields.items():
            size = max(1, int(field.get("size", u.PTR_SIZE)))
            writes = max(0, int(field.get("writes", 0)))
            kind = field.get("kind", "scalar")

            # Ignore clear outliers beyond the best-effort class-size estimate.
            if offset + size > owner_limit + max(u.PTR_SIZE, 0x20):
                continue

            # When Hex-Rays recovered any fields for this class, keep raw instruction
            # results only if they are strong enough to justify the extra noise.
            if owner_ctree and offset not in owner_ctree:
                if kind == "scalar" and writes < 2:
                    continue

            cleaned = dict(field)
            cleaned["size"] = size
            owner_filtered[offset] = cleaned

        if owner_filtered:
            filtered[owner_name] = owner_filtered

    return filtered


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
    owner_field_offsets = sorted(recovered_fields.get(owner_name, {}).keys())
    owner_vbptr_offsets = set(virtual_hints.get(owner_name, {}).keys())
    class_size = 0
    for idx, entry in enumerate(owner_entries):
        estimate = entry_size_estimates.get((owner_name, entry["offset"]), u.PTR_SIZE)
        next_offset = None
        if idx + 1 < len(owner_entries):
            next_offset = owner_entries[idx + 1]["offset"]
        if next_offset is not None:
            estimate = min(estimate, max(u.PTR_SIZE, next_offset - entry["offset"]))
        estimate = max(estimate, u.PTR_SIZE)

        use_embedded = False
        if entry["offset"] > 0 and estimate > u.PTR_SIZE:
            sub_end = entry["offset"] + estimate
            conflict = False
            for foff in owner_field_offsets:
                if entry["offset"] <= foff < sub_end:
                    conflict = True
                    break
            if not conflict:
                for voff in owner_vbptr_offsets:
                    if entry["offset"] <= voff < sub_end:
                        conflict = True
                        break
            if not conflict:
                use_embedded = True

        if use_embedded:
            append_member(
                entry["offset"],
                estimate,
                "base_%x_%s" % (entry["offset"], normalize_identifier(entry["subobject_name"], fallback="base", max_len=24)),
                "embedded",
                "%s: embedded base subobject %s" % (COMMENT_TAG, entry["subobject_name"]),
                target_type_name=entry["embed_type_name"])
        else:
            append_member(
                entry["offset"],
                u.PTR_SIZE,
                get_vfptr_member_name(entry["offset"]),
                "vfptr",
                "%s: vfptr for %s (offset %#x)" % (COMMENT_TAG, entry["subobject_name"], entry["offset"]),
                target_type_name=entry["vtbl_type_name"])

        class_size = max(class_size, entry["offset"] + estimate)

    for offset, hint in sorted(virtual_hints.get(owner_name, {}).items()):
        comment = hint
        target_type_name = None
        if isinstance(hint, dict):
            comment = hint.get("comment", "")
            target_type_name = hint.get("type_name")
        append_member(offset, u.PTR_SIZE, "vbptr_%x" % offset, "vbptr", comment, target_type_name=target_type_name)

    for offset, field in sorted(recovered_fields.get(owner_name, {}).items()):
        kind = field.get("kind", "scalar")
        prefix = {
            "ptr": "ptr",
            "float": "float",
            "double": "double",
        }.get(kind, "field")
        size = max(1, int(field.get("size", u.PTR_SIZE)))
        comment = "%s: recovered %s field (%u hit%s)" % (
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


def can_read_vbtable_dword(ea):
    try:
        for index in range(4):
            if not ida_bytes.is_loaded(ea + index):
                return False
    except Exception:
        return False
    return True


def read_vbtable_values(table_ea, slot_offsets, hint):
    values = {}
    if table_ea in (None, ida_idaapi.BADADDR):
        return values

    max_slot_off = max(slot_offsets) if slot_offsets else 0
    base_count = len(hint.get("bases", []))
    max_slot_off = max(max_slot_off, base_count * 4)
    max_slot_off = min(max_slot_off, 0x100)

    for slot_off in range(0, max_slot_off + 4, 4):
        slot_ea = table_ea + slot_off
        if not can_read_vbtable_dword(slot_ea):
            break
        slot_offsets.add(slot_off)
        try:
            values[slot_off] = u.to_signed32(ida_bytes.get_32bit(slot_ea))
        except Exception:
            break
    return values


def generate_vbtable_type(owner_name, vbptr_offset, hint):
    if not isinstance(hint, dict):
        return

    type_name = hint.get("type_name")
    if not type_name:
        return

    sid = ensure_generated_struct(type_name)
    idc.set_struc_cmt(sid, "%s: generated vbtable type for %s (vbptr %#x)" % (
        COMMENT_TAG,
        owner_name,
        vbptr_offset), 1)
    clear_all_generated_members(sid)

    slot_offsets = set([0])
    for vdisp in hint.get("entries", {}):
        if isinstance(vdisp, int) and 0 <= vdisp <= 0x400:
            slot_offsets.add(vdisp)

    table_ea = hint.get("table_ea", ida_idaapi.BADADDR)
    slot_values = read_vbtable_values(table_ea, slot_offsets, hint)
    int_tif = parse_decl_tinfo("int __pci_tmp;")
    for slot_off in sorted(slot_offsets):
        base_name = hint.get("entries", {}).get(slot_off)
        if slot_off == 0:
            member_name = "self_off"
        elif base_name:
            member_name = "base_off_%x" % slot_off
        else:
            member_name = "slot_%x" % slot_off
        if base_name:
            member_name = "%s_%s" % (
                member_name,
                normalize_identifier(base_name, fallback="base", max_len=24))

        if ensure_generated_sized_member(sid, member_name, slot_off, 4) == 0:
            slot_value = slot_values.get(slot_off)
            value_suffix = ""
            if slot_value is not None:
                value_suffix = " = %s" % format_signed_offset(slot_value)
            if base_name:
                set_member_comment(sid, member_name, "virtual base offset for %s%s" % (base_name, value_suffix))
            elif slot_off == 0:
                set_member_comment(sid, member_name, "vbtable self offset%s" % value_suffix)
            elif slot_value is not None:
                set_member_comment(sid, member_name, "vbtable entry%s" % value_suffix)
            if int_tif is not None:
                u.set_member_tinfo(sid, member_name, int_tif)
            if table_ea not in (None, ida_idaapi.BADADDR) and slot_value is not None:
                append_comment(
                    table_ea + slot_off,
                    "%s: %s = %s" % (COMMENT_TAG, base_name or member_name, format_signed_offset(slot_value)),
                    1)

    if table_ea not in (None, ida_idaapi.BADADDR) and slot_offsets:
        size = max(slot_offsets) + 4
        try:
            ok = bool(ida_bytes.create_struct(table_ea, size, sid, True))
        except Exception:
            ok = False
        if not ok:
            try:
                ok = bool(idc.SetType(table_ea, "struct %s;" % type_name))
            except Exception:
                ok = False
        if ok:
            append_comment(table_ea, "%s: typed as %s" % (COMMENT_TAG, type_name), 1)


def generate_decompilation_types(class_type_names, layouts, vtables, entry_size_estimates, recovered_fields, virtual_hints, cfunc_cache=None):
    for class_name in class_type_names:
        type_name = class_type_names[class_name]
        sid = ensure_generated_struct(type_name)
        idc.set_struc_cmt(sid, "%s: generated class type for %s" % (COMMENT_TAG, class_name), 1)

    for owner_name, owner_hints in virtual_hints.items():
        for offset, hint in owner_hints.items():
            generate_vbtable_type(owner_name, offset, hint)

    for entry in vtables:
        sid = ensure_generated_struct(entry["vtbl_type_name"])
        idc.set_struc_cmt(sid, "%s: generated vtable type for %s (offset %#x)" % (COMMENT_TAG, entry["owner_name"], entry["offset"]), 1)
        clear_all_generated_members(sid)

        used_names = set()
        for slot_index, func_ea in enumerate(entry["col"].vfeas):
            kind, thunk_target = get_virtual_method_kind(func_ea, slot_index, cfunc_cache)
            thunk_adjust = get_thunk_adjustment(func_ea, cfunc_cache) if kind == "thunk" else 0
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
        if entry["offset"] > 0:
            generate_embedded_subobject_type(entry, entry_size_estimates)

    for owner_name in layouts:
        sid = idc.get_struc_id(class_type_names[owner_name])
        clear_generated_layout_members(sid)
        for member in build_class_layout_plan(owner_name, layouts, entry_size_estimates, recovered_fields, virtual_hints):
            r = -1
            if member["kind"] == "vfptr":
                r = add_generated_ptr_member(sid, member["name"], member["offset"], member["target_type_name"])
            elif member["kind"] == "vbptr":
                r = add_generated_ptr_member(sid, member["name"], member["offset"], member["target_type_name"])
            elif member["kind"] == "ptr":
                r = add_generated_ptr_member(sid, member["name"], member["offset"])
            elif member["kind"] == "gap":
                r = ensure_generated_byte_member(sid, member["name"], member["offset"], member["size"])
            elif member["kind"] == "embedded":
                r = ensure_generated_sized_member(sid, member["name"], member["offset"], member["size"])
            else:
                r = ensure_generated_sized_member(sid, member["name"], member["offset"], member["size"])

            if r == 0 and member["comment"]:
                set_member_comment(sid, member["name"], member["comment"])
            if r == 0 and member["kind"] == "embedded":
                embed_tif = get_struct_member_tinfo(member["target_type_name"])
                if embed_tif is not None:
                    u.set_member_tinfo(sid, member["name"], embed_tif)
            if r == 0 and member["kind"] in ("float", "double"):
                scalar_tif = parse_decl_tinfo("%s __pci_tmp;" % member["kind"])
                if scalar_tif is not None:
                    u.set_member_tinfo(sid, member["name"], scalar_tif)

    populate_standalone_subobject_types(class_type_names, layouts, vtables, entry_size_estimates)


def refresh_decompiler_views(func_eas, cfunc_cache=None):
    if not initialize_hexrays():
        return
    for func_ea in sorted(set(func_eas)):
        invalidate_cfunc_cache(cfunc_cache, func_ea)
        refresh_hexrays_function(func_ea)


def improve_decompilation(paths, data, config):
    decomp_mode = get_decomp_mode(config)
    class_type_names, layouts, vtables, entry_size_estimates = build_decompilation_context(paths, data)
    cfunc_cache = {}
    recovered_fields = {}
    virtual_hints = {}
    if decomp_mode in ("balanced", "aggressive"):
        instr_fields = collect_constructor_field_writes(layouts, vtables, cfunc_cache)
        ctree_fields = collect_constructor_field_writes_ctree(layouts, vtables, cfunc_cache)
        instr_fields = filter_instruction_recovered_fields(instr_fields, ctree_fields, layouts, entry_size_estimates)
        recovered_fields = merge_recovered_field_maps(instr_fields, ctree_fields, prefer_new=True)
        virtual_hints = collect_virtual_inheritance_hints(paths, vtables, cfunc_cache)
    generate_decompilation_types(class_type_names, layouts, vtables, entry_size_estimates, recovered_fields, virtual_hints, cfunc_cache)
    cfunc_cache.clear()

    preferred_ref_entries = {}
    for entry in sorted(vtables, key=lambda item: (item["offset"], item["owner_name"], item["subobject_name"])):
        for f in get_vftable_ref_funcs(entry["vftable_ea"], expected_offset=entry["offset"], cfunc_cache=cfunc_cache):
            current = preferred_ref_entries.get(f.start_ea)
            if current is None or entry["offset"] < current["offset"]:
                preferred_ref_entries[f.start_ea] = entry

    typed_virtuals = set()
    typed_refs = set()
    thisarg_types = {}
    ctor_callers = {}
    refreshed_funcs = set()
    for entry in vtables:
        col = entry["col"]
        is_lib = (col.libflag == col.LIBLIB)

        for slot_index, func_ea in enumerate(col.vfeas):
            kind, thunk_target = get_virtual_method_kind(func_ea, slot_index, cfunc_cache)
            thunk_adjust = get_thunk_adjustment(func_ea, cfunc_cache) if kind == "thunk" else 0
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

        for f in get_vftable_ref_funcs(entry["vftable_ea"], expected_offset=entry["offset"], cfunc_cache=cfunc_cache):
            preferred_entry = preferred_ref_entries.get(f.start_ea)
            if preferred_entry is not None and preferred_entry is not entry:
                continue
            ref_kind = get_ctor_dtor_kind(f.start_ea, cfunc_cache)
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
                            ctor_callers[caller_ea] = {
                                "class_type_name": entry["owner_type_name"],
                                "ctor_targets": set([f.start_ea]),
                            }
                        elif not existing:
                            ctor_callers[caller_ea] = False
                        elif existing["class_type_name"] != entry["owner_type_name"]:
                            ctor_callers[caller_ea] = False
                        else:
                            existing["ctor_targets"].add(f.start_ea)
                typed_refs.add(f.start_ea)
                thisarg_types[f.start_ea] = entry["owner_type_name"]
                refreshed_funcs.add(f.start_ea)

        vfptr_member_name = get_vfptr_member_name(entry["offset"])
        vfptr_store_refs = set()
        for f in get_vftable_ref_funcs(entry["vftable_ea"], expected_offset=entry["offset"], cfunc_cache=cfunc_cache):
            for match in function_writes_vtable_to_this(
                    f.start_ea,
                    entry["vftable_ea"],
                    expected_offset=entry["offset"],
                    cfunc_cache=cfunc_cache):
                if match.get("ea", ida_idaapi.BADADDR) != ida_idaapi.BADADDR:
                    vfptr_store_refs.add(match["ea"])
        if not vfptr_store_refs:
            vfptr_store_refs = set(idautils.DataRefsTo(entry["vftable_ea"]))
        for refea in sorted(vfptr_store_refs):
            append_comment(refea, "%s: writes %s::%s -> %s" % (COMMENT_TAG, entry["owner_name"], vfptr_member_name, entry["vtbl_type_name"]), 1)

    for func_ea, class_type_name in thisarg_types.items():
        if decomp_mode != "safe" and apply_hexrays_thisarg_type(func_ea, class_type_name, cfunc_cache):
            refreshed_funcs.add(func_ea)

    for caller_ea, ctor_info in ctor_callers.items():
        if not ctor_info:
            continue
        if decomp_mode == "aggressive" and apply_hexrays_ctor_result_type(
                caller_ea,
                ctor_info["class_type_name"],
                sorted(ctor_info["ctor_targets"]),
                cfunc_cache):
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


def get_vftable_ref_funcs(vftable_ea, expected_offset=None, cfunc_cache=None):
    ref_funcs = {}
    for refea in idautils.DataRefsTo(vftable_ea):
        f = ida_funcs.get_func(refea)
        if not f:
            continue
        likely = is_probable_ctor_dtor_ref(f, refea)
        cached = ref_funcs.get(f.start_ea)
        if cached is None or (likely and not cached[1]):
            ref_funcs[f.start_ea] = (f, likely)

    if ref_funcs and ida_hexrays is not None and initialize_hexrays():
        exact_funcs = []
        for f, _ in ref_funcs.values():
            matches = function_writes_vtable_to_this(
                f.start_ea,
                vftable_ea,
                expected_offset=expected_offset,
                cfunc_cache=cfunc_cache)
            if matches:
                exact_funcs.append(f)
        if exact_funcs:
            exact_set = set(f.start_ea for f in exact_funcs)
            likely_funcs = [x[0] for x in ref_funcs.values() if x[1] and x[0].start_ea not in exact_set]
            return exact_funcs + likely_funcs

    likely_funcs = [x[0] for x in ref_funcs.values() if x[1]]
    if likely_funcs:
        return likely_funcs
    return [x[0] for x in ref_funcs.values()]

def change_dir_of_ctors_dtors(paths, data, dirtree):
    path_prefix = "/classes/"
    cfunc_cache = {}
    
    # move virtual functions to its class folder
    for vftable_ea in paths:
        path = paths[vftable_ea]
        if not path:
            continue
        
        # get the class name that owns the vftable, which is the last entry of the path.
        class_name = path[-1].name
        
        for f in get_vftable_ref_funcs(vftable_ea, expected_offset=data[vftable_ea].offset, cfunc_cache=cfunc_cache):
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
    cfunc_cache = {}
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
        for f in get_vftable_ref_funcs(vftable_ea, expected_offset=data[vftable_ea].offset, cfunc_cache=cfunc_cache):
            rename_func(f.start_ea, class_name.split("<")[0] + "::", get_ctor_dtor_kind(f.start_ea, cfunc_cache), is_lib=is_lib)


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
