import os
import json
import re

class lib_classes_checker_t(object):
    
    def __init__(self, rules=os.path.join(os.path.dirname(__file__),"lib_classes.json")):
        self.lib_class_ptns = {}
        with open(rules) as f:
            self.lib_class_ptns = json.load(f)
            
    def does_class_startwith(self, name, ptns):
        for ptn in ptns:
            if name.startswith(ptn):
                return True
        return False
    
    def does_class_match_regex_ptns(self, name, ptns):
        for ptn in ptns:
            if re.match(ptn, name):
                return True
        return False
    
    def is_class_lib(self, name):
        r = False
        if name in self.lib_class_ptns["="]:
            r = True
        elif self.does_class_startwith(name, self.lib_class_ptns["startswith"]):
            r = True
        elif self.does_class_match_regex_ptns(name, self.lib_class_ptns["regex"]):
            r = True
        return r

def set_libflag(data):
    for vftable_ea in data:
        col = data[vftable_ea]
        
        # get the class name that owns the vftable
        class_name = col.name
        
        # check the class is a part of standard library classes such as STL and MFC
        lib_class_ptns = lib_classes_checker_t()
        col.libflag = col.LIBNOTLIB
        if lib_class_ptns.is_class_lib(class_name):
            col.libflag = col.LIBLIB

"""
lib_class_ptns = lib_classes_checker_t()
print(lib_class_ptns.is_class_lib("std::aaaa")) # True
print(lib_class_ptns.is_class_lib("CWinApp")) # True
print(lib_class_ptns.is_class_lib("CSimpleTextApp")) # False
"""
