import os
import json
import re

class lib_classes_checker_t(object):
    
    def __init__(self, rules=os.path.join(os.path.dirname(__file__),"lib_classes.json")):
        self.lib_class_ptns = {}
        with open(rules) as f:
            self.lib_class_ptns = json.load(f)
        self.exact_matches = set(self.lib_class_ptns.get("=", []))
        self.startswith_ptns = tuple(self.lib_class_ptns.get("startswith", []))
        self.regex_ptns = [re.compile(x) for x in self.lib_class_ptns.get("regex", [])]
             
    def does_class_startwith(self, name, ptns):
        if isinstance(ptns, tuple):
            return bool(ptns) and name.startswith(ptns)
        for ptn in ptns:
            if name.startswith(ptn):
                return True
        return False
    
    def does_class_match_regex_ptns(self, name, ptns):
        for ptn in ptns:
            if hasattr(ptn, "match"):
                if ptn.match(name):
                    return True
            elif re.match(ptn, name):
                return True
        return False
    
    def is_class_lib(self, name):
        r = False
        if name in self.exact_matches:
            r = True
        elif self.does_class_startwith(name, self.startswith_ptns):
            r = True
        elif self.does_class_match_regex_ptns(name, self.regex_ptns):
            r = True
        return r


_default_checker = None


def get_default_checker():
    global _default_checker
    if _default_checker is None:
        _default_checker = lib_classes_checker_t()
    return _default_checker

def set_libflag(data):
    lib_class_ptns = get_default_checker()
    for vftable_ea in data:
        col = data[vftable_ea]
        
        # get the class name that owns the vftable
        class_name = col.name
        
        # check the class is a part of standard library classes such as STL and MFC
        col.libflag = col.LIBNOTLIB
        if lib_class_ptns.is_class_lib(class_name):
            col.libflag = col.LIBLIB

"""
lib_class_ptns = lib_classes_checker_t()
print(lib_class_ptns.is_class_lib("std::aaaa")) # True
print(lib_class_ptns.is_class_lib("CWinApp")) # True
print(lib_class_ptns.is_class_lib("CSimpleTextApp")) # False
"""
