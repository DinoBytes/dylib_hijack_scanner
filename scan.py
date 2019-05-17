import os
import sys
from pprint import pprint

from machotools import rewriter_factory
from machotools.errors import MachoError


def main():
    if len(sys.argv) < 2:
        print("Usage: python scan.py <directory>")
        exit()
    
    files = list_files(sys.argv[1])

    load_entries = {}
    for f in files:
        try:
            entries = list_load_entries(f)
        except:
            continue
        if len(entries['rpaths']) > 1 and len(entries['libraries']) > 0:
            load_entries[f] = entries

    possible_hijacks = {}

    # These are technically different things, but this script doesn't distinguish.
    # this may lead to FPs
    path_replacements = ['@executable_path', '@loader_path']
    for file, entry in load_entries.items():
        exec_path = os.path.join(os.sep, *file.split(os.sep)[:-1])
        vuln_libs = []
        for lib in entry['libraries']:
            first = True
            for rpath in entry['rpaths']:
                for replacement in path_replacements:
                    rpath = rpath.replace(replacement, '')
                dylib_check = os.path.normpath(exec_path + rpath + lib)
                if os.path.isfile(dylib_check):
                    if first: break
                    vuln_libs.append(lib)
                first = False
        if len(vuln_libs) > 0:
            possible_hijacks[file] = vuln_libs

    pprint(possible_hijacks)


def list_load_entries(filepath):
    """
    Return load entry dict for the given filepath.

    :param filepath: file to get rpaths from
    """
    try:
        rewriter = rewriter_factory(filepath)
        dynamic_deps = [dep[6:] for dep in rewriter.dependencies if dep.startswith('@rpath')]
        return {'rpaths': rewriter.rpaths, 'libraries': dynamic_deps}
    except MachoError:
        return {'rpaths': [], 'libraries': []}


def list_files(startpath):
    """
    Yield list of all files (including path) for the specified directory recursively.

    :param startpath: path to start in
    """
    for root, _, files in os.walk(startpath):
        for f in files:
            yield os.path.join(root, f)
    

if __name__ == "__main__":
    main()