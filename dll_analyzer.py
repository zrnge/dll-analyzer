import argparse
import ctypes
import pefile
import os
import sys

class DLLAnalyzer:
    def __init__(self, dll_path):
        if not os.path.exists(dll_path):
            raise FileNotFoundError(f"{dll_path} not found.")
        self.dll_path = dll_path
        self.dll = ctypes.WinDLL(dll_path)
        self.exports = self._get_exports()

    def _get_exports(self):
        pe = pefile.PE(self.dll_path)
        exports = []
        if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
            for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                if exp.name:
                    exports.append(exp.name.decode())
        return exports

    def list_exports(self):
        for idx, func in enumerate(self.exports, start=1):
            print(f"{idx}. {func}")
        return self.exports

    def define_function(self, func_name, argtypes, restype):
        try:
            func = getattr(self.dll, func_name)
            func.argtypes = argtypes
            func.restype = restype
            return func
        except AttributeError:
            print(f"[!] Function {func_name} not found.")
            sys.exit(1)

    def call_function(self, func, args):
        try:
            result = func(*args)
            print(f"[+] {func.__name__} returned: {result}")
        except Exception as e:
            print(f"[!] Error calling {func.__name__}: {e}")

def parse_ctype(arg):
    mapping = {
        "int": ctypes.c_int,
        "str": ctypes.c_char_p,
        "void": None
    }
    return mapping.get(arg, ctypes.c_int)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="DLL Dynamic Analysis Tool")
    parser.add_argument("dll", help="Path to DLL")
    parser.add_argument("--list", action="store_true", help="List exported functions")
    parser.add_argument("--call", metavar="FUNC", help="Function name to call")
    parser.add_argument("--args", nargs="*", help="Arguments for function", default=[])
    parser.add_argument("--types", nargs="*", help="Argument types (int, str)", default=[])
    parser.add_argument("--restype", help="Return type (int, str, void)", default="int")

    args = parser.parse_args()

    analyzer = DLLAnalyzer(args.dll)

    if args.list:
        analyzer.list_exports()

    if args.call:
        argtypes = [parse_ctype(t) for t in args.types]
        restype = parse_ctype(args.restype)
        func = analyzer.define_function(args.call, argtypes, restype)

        # Convert args to correct types
        call_args = []
        for t, v in zip(args.types, args.args):
            if t == "int":
                call_args.append(int(v))
            elif t == "str":
                call_args.append(v.encode())
            else:
                call_args.append(int(v))  # default fallback

        analyzer.call_function(func, call_args)
