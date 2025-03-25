#import ida_idaapi
import ida_dirtree

def get_full_paths(dirtree, recurse=False, search_path=""):
    iterator = ida_dirtree.dirtree_iterator_t()
    r = dirtree.findfirst(iterator, "{}/*".format(search_path))
    while r:
        de = dirtree.resolve_cursor(iterator.cursor)
        path = dirtree.get_abspath(iterator.cursor)
        if not de.isdir:
            yield path, de, iterator.cursor
        elif de.isdir and recurse:
            # if dir_entry is a directory, execute it recursively 
            for rpath, rde, rcur in get_full_paths(dirtree, recurse, path):
                yield rpath, rde, rcur
        r = dirtree.findnext(iterator)

"""
# get the top level func paths
abs_paths = []
for path, de, cursor in get_full_paths(dirtree):
    abs_paths.append(path)
"""

# An inode can be ea in standard dirtrees such as Functions and Names.
# It can also be structure ids and enum ids and so on.
def get_cursor_by_inode(dirtree, inode):
    de = ida_dirtree.direntry_t(inode)
    cursor = dirtree.find_entry(de)
    return cursor

def get_abs_path_by_inode(dirtree, inode):
    cursor = get_cursor_by_inode(dirtree, inode)
    abs_path = dirtree.get_abspath(cursor)
    return abs_path

def get_parent_dir_by_inode(dirtree, inode):
    cursor = get_cursor_by_inode(dirtree, inode)
    cursor = dirtree.get_parent_cursor(cursor)
    abs_path = dirtree.get_abspath(cursor)
    return abs_path
