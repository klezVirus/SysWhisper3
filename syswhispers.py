#!/usr/bin/python3

import argparse
import json
import os
import random
import re
import string
import struct
from enum import Enum
from pathlib import Path


def fetch_all_type_definitions(code) -> list:
    """Fetch all type definitions from a given code

    Args:
        code (str): The code to parse

    Returns:
        list: The list of all type definitions (tuple of 4 elements) found in the code
    """
    return re.findall(r"typedef\s+(\w+)\s+(\w+)\s+([\w|*]*)\s*([\w|*]*)", code, re.DOTALL)


def fetch_inner_enum_definitions(code) -> list:
    """Fetch all type definitions from a given code

    Args:
        code (str): The code to parse

    Returns:
        list: The list of all enum definitions (tuple of 2 elements) found in the code
    """
    enum_list = []
    code = code.replace("\r", "")
    code = re.sub(r"/\*.*?\*/", "", code, re.DOTALL | re.MULTILINE)
    for x, y in re.findall(r"typedef\s+enum\s+(\w+)\s*{([^}]+)\s*}", code, re.DOTALL | re.MULTILINE):
        for line in y.splitlines():
            if line.startswith("//"):
                continue
            line = re.sub("//.*$", "", line)
            if line.strip() == "":
                continue
            line = line.split("=")[0].replace(",", "").strip()
            enum_list.append((x, line))

    return enum_list


def fetch_includes(code) -> list:
    """
    Fetch all includes from a given code

    Args:
        code (str): The code to parse

    Returns:
        list: The list of all includes found in the code
    """

    _includes = []
    code = code.replace("\r", "")
    code = re.sub(r"/\*.*?\*/", "", code, re.DOTALL | re.MULTILINE)
    for x in re.findall(r'#include\s+\"\s*([^"]+)\s*\"', code, re.DOTALL | re.MULTILINE):
        _includes.append(x.strip())
    for x in re.findall(r'#include\s+<\s*([^>]+)\s*>', code, re.DOTALL | re.MULTILINE):
        _includes.append(x.strip())

    return _includes


try:
    from enums.Architectures import Arch
    from enums.Compilers import Compiler
    from enums.SyscallRecoveryType import SyscallRecoveryType
    from utils.utils import get_project_root

    base_directory = os.path.join(get_project_root(), 'syscalls', 'syswhispersv3')
    define_search_and_replace = False

except ModuleNotFoundError:
    def get_project_root() -> Path:
        return Path(__file__).parent


    base_directory = get_project_root()
    define_search_and_replace = True


    class Arch(Enum):
        Any = ""
        x86 = "x86"
        x64 = "x64"

        @staticmethod
        def from_string(label):
            if label.lower() in ["any", "all"]:
                return Arch.Any
            elif label.lower() in ["32", "86", "x86", "i386"]:
                return Arch.x86
            elif label.lower() in ["64", "x64", "amd64", "x86_64"]:
                return Arch.x64


    class Compiler(Enum):
        All = ""
        MSVC = "MSVC"
        MINGW = "MinGW"

        @staticmethod
        def from_string(label):
            if label.lower() in ["all"]:
                return Compiler.All
            elif label.lower() in ["msvc"]:
                return Compiler.MSVC
            elif label.lower() in ["mingw"]:
                return Compiler.MINGW


    # Define SyscallRecoveryType
    class SyscallRecoveryType(Enum):
        EMBEDDED = 0
        EGG_HUNTER = 1
        JUMPER = 2
        JUMPER_RANDOMIZED = 3
        VECTORED = 4

        @classmethod
        def from_name_or_default(cls, name):
            _types = dict(map(lambda c: (c.name.lower(), c.value), cls))
            return SyscallRecoveryType(_types[name]) if name in _types.keys() else SyscallRecoveryType.EMBEDDED

        @classmethod
        def get_name(cls, value):
            if isinstance(value, str):
                value = int(value)
            _types = dict(map(lambda c: (c.value, c.name.lower()), cls))
            return _types[value] if value in _types.keys() else None

        @classmethod
        def from_name(cls, name):
            _types = dict(map(lambda c: (c.name.lower(), c.value), cls))
            return _types[name] if name in _types.keys() else None

        @classmethod
        def value_list(cls):
            return list(map(lambda c: c.value, cls))

        @classmethod
        def key_list(cls):
            return list(map(lambda c: c.name.lower(), cls))


class SysWhispers(object):
    def __init__(
            self,
            arch: Arch = Arch.x64,
            compiler: Compiler = Compiler.MSVC,
            recovery: SyscallRecoveryType = SyscallRecoveryType.EMBEDDED,
            syscall_instruction: str = "syscall",
            wow64: bool = False,
            verbose: bool = False,
            debug: bool = False,
            prefix: str = 'SW3',
            alternative_headers: list = None,
            no_windows_headers: bool = False):
        self.no_windows_headers = no_windows_headers
        self.prefix = prefix
        self.arch = arch
        self.compiler = compiler
        self.recovery = recovery
        self.wow64 = wow64
        self.syscall_instruction = syscall_instruction
        self.egg = [hex(ord(random.choices(string.ascii_lowercase, k=1)[0])), "0x0", "0x0",
                    hex(ord(random.choices(string.ascii_lowercase, k=1)[0]))]
        self.seed = random.randint(2 ** 28, 2 ** 32 - 1)
        self.typedefs: list = json.load(
            open(os.path.join(base_directory, 'data', 'typedefs.json')))
        self.prototypes: dict = json.load(
            open(os.path.join(base_directory, 'data', 'prototypes.json')))
        self.verbose = verbose
        self.debug = debug
        self.structured_types = []
        self.replaced_types = []

        self.alternative_headers = alternative_headers if alternative_headers else []
        self.includes = []
        self.already_defined_types = []
        self.already_defined_enums = []
        self.populate_defined_types()

        self.validate()

    def __find_header_files(self):
        print("[*] Searching for alternative header files...", end="")
        for i in range(len(self.alternative_headers)):
            if self.alternative_headers[i].startswith("+"):
                self.includes.append(self.alternative_headers[i][1:])
                self.alternative_headers[i] = self.alternative_headers[i][1:]
        print("done")
        print("[*] Resolving header files...", end="")
        for _p in self.alternative_headers.copy():
            p = Path(_p).absolute().resolve()
            if not p.exists():
                self.alternative_headers.remove(_p)
            elif p.is_file():
                self.alternative_headers.remove(_p)
                self.alternative_headers.append(p)
                continue
            elif p.is_dir():
                self.alternative_headers.remove(_p)
                for f in p.glob("**/*.h"):
                    self.alternative_headers.append(f)
        print("done")

        print("[*] Recursively resolving header files from #include directives...", end="")
        alternative_headers = []
        found = True
        while found:
            alternative_headers = self.alternative_headers.copy()
            for f in alternative_headers:
                p = Path(f).absolute().resolve().parent
                with open(f, 'r') as fh:
                    code = fh.read()
                    for i in fetch_includes(code):
                        try:
                            _p_i = Path(i).relative_to(p).absolute().resolve()
                            if _p_i not in self.alternative_headers:
                                self.alternative_headers.append(_p_i)
                        except ValueError:
                            pass
            found = len(alternative_headers) != len(self.alternative_headers)

        print("done")

        print("[*] Removing duplicates...", end="")
        self.alternative_headers = list(set(self.alternative_headers))
        print("done")

    def populate_defined_types(self):
        self.__find_header_files()

        typedefs = []

        for f in self.alternative_headers:
            with open(f, 'r') as fh:
                code = fh.read()
                typedefs += fetch_all_type_definitions(code)
                self.already_defined_enums += fetch_inner_enum_definitions(code)

        for x1, x2 in self.already_defined_enums:
            for y in self.typedefs:
                code = y.get("definition")
                _c_t = fetch_all_type_definitions(code)
                if len(_c_t) == 0 or len(_c_t[0]) == 0 or _c_t[0][0] != "enum":
                    continue
                _c_e = fetch_inner_enum_definitions(code)
                if len(_c_e) == 0:
                    continue

                for _z1, _z2 in _c_e:
                    if x2 == _z2:
                        if x1[1:] not in y.get("identifiers"):
                            new_type_alias = x1[1:]
                            y["definition"] = y["definition"].replace(_z1[1:], new_type_alias)
                            # print("corresponding enum found: ", _z1, x1, y.get("identifiers"))
                            for function, details in self.prototypes.items():
                                for param in details["params"]:
                                    if param["type"] in y.get("identifiers"):
                                        param["type"] = param["type"].replace(_z1[1:], new_type_alias)
                                        # print("function using type found: ", function, param["type"], param["name"])
                            break

        for k1, k2, k3, k4 in typedefs:
            if k1 not in ["struct", "enum", "union", "const"]:
                self.already_defined_types.append(k1)
            else:
                self.already_defined_types.append(k2)

        self.already_defined_types = list(set(self.already_defined_types))


    def validate(self):
        if self.recovery == SyscallRecoveryType.VECTORED and self.arch != Arch.x64:
            exit("[-] Vectored compatible only with x64 arch")
        
        if self.recovery == SyscallRecoveryType.EGG_HUNTER:
            if self.compiler in [Compiler.All, Compiler.MINGW]:
                # TODO: try to make the 'db' instruction work in MinGW
                exit("[-] Egg-Hunter not compatible with MinGW")

            print(r"[*] With the egg-hunter, you need to use a search-replace functionality:")
            print(f"  unsigned char egg[] = {{ {', '.join([hex(int(x, 16)) for x in self.egg] * 2)} }}; // egg")
            replace_x86 = '  unsigned char replace[] = { 0x0f, 0x34, 0x90, 0x90, 0xC3, 0x90, 0xCC, 0xCC }; // sysenter; nop; nop; ret; nop; int3; int3'
            replace_x64 = '  unsigned char replace[] = { 0x0f, 0x05, 0x90, 0x90, 0xC3, 0x90, 0xCC, 0xCC }; // syscall; nop; nop; ret; nop; int3; int3'
            if self.arch == Arch.Any:
                print(f"#ifdef _WIN64\n{replace_x64}\n#else\n{replace_x86}\n#endif")
            elif self.arch == Arch.x86:
                print(replace_x86)
            else:
                print(replace_x64)
            print()

    def generate(self, function_names: list = (), basename: str = 'syscalls'):
        if not function_names:
            function_names = list(self.prototypes.keys())
        elif any([f not in self.prototypes.keys() for f in function_names]):
            raise ValueError('Prototypes are not available for one or more of the requested functions.')

        # Write C file.
        with open(os.path.join(base_directory, 'data', 'base.c'), 'rb') as base_source:
            with open(f'{basename}.c', 'wb') as output_source:
                base_source_contents = base_source.read().decode()

                if self.verbose:
                    base_source_contents = base_source_contents.replace('//#define DEBUG', '#define DEBUG')

                base_source_contents = base_source_contents.replace('<BASENAME>', os.path.basename(basename), 1)
                if self.recovery in [SyscallRecoveryType.JUMPER, SyscallRecoveryType.JUMPER_RANDOMIZED]:
                    base_source_contents = base_source_contents.replace("// JUMPER", "#define JUMPER")
                elif self.recovery == SyscallRecoveryType.VECTORED:
                    base_source_contents = base_source_contents.replace("// VECTORED", "#define VECTORED")

                if self.wow64:
                    base_source_contents = base_source_contents.replace('// JUMP_TO_WOW32Reserved',
                                                                        '        // if we are a WoW64 process, jump to WOW32Reserved\n        SyscallAddress = (PVOID)__readfsdword(0xc0);\n        return SyscallAddress;')
                else:
                    base_source_contents = base_source_contents.replace('// JUMP_TO_WOW32Reserved',
                                                                        '        return NULL;')

                msvc_wow64 = '__declspec(naked) BOOL local_is_wow64(void)\n{\n    __asm {\n        mov eax, fs:[0xc0]\n        test eax, eax\n        jne wow64\n        mov eax, 0\n        ret\n        wow64:\n        mov eax, 1\n        ret\n    }\n}\n'
                mingw_wow64 = '__declspec(naked) BOOL local_is_wow64(void)\n{\n    asm(\n        "mov eax, fs:[0xc0] \\n"\n        "test eax, eax \\n"\n        "jne wow64 \\n"\n        "mov eax, 0 \\n"\n        "ret \\n"\n        "wow64: \\n"\n        "mov eax, 1 \\n"\n        "ret \\n"\n    );\n}'
                wow64_function = ''
                if self.compiler == Compiler.All:
                    wow64_function += '#if defined(_MSC_VER)\n\n'
                    wow64_function += msvc_wow64
                    wow64_function += '\n\n#elif defined(__GNUC__)\n\n'
                    wow64_function += mingw_wow64
                    wow64_function += '\n\n#endif'
                elif self.compiler == Compiler.MSVC:
                    wow64_function += msvc_wow64
                elif self.compiler == Compiler.MINGW:
                    wow64_function += mingw_wow64
                base_source_contents = base_source_contents.replace('// LOCAL_IS_WOW64', wow64_function)

                output_source.write(base_source_contents.encode())

                if self.compiler in [Compiler.All, Compiler.MINGW]:
                    output_source.write('#if defined(__GNUC__)\n\n'.encode())
                    for function_name in function_names:
                        output_source.write((self._get_function_asm_code_mingw(function_name) + '\n').encode())
                    output_source.write('#endif\n'.encode())

                if self.recovery == SyscallRecoveryType.VECTORED:
                    for function_name in function_names:
                        output_source.write((self._get_function_vectored_code(function_name) + '\n\n').encode())


        basename_suffix = ''
        basename_suffix = basename_suffix.capitalize() if os.path.basename(basename).istitle() else basename_suffix
        if self.recovery != SyscallRecoveryType.VECTORED and self.compiler in [Compiler.All, Compiler.MSVC]:
            if self.arch in [Arch.Any, Arch.x64]:
                # Write x64 ASM file
                basename_suffix = f'_{basename_suffix}' if '_' in basename else basename_suffix
                with open(f'{basename}{basename_suffix}-asm.x64.asm', 'wb') as output_asm:
                    output_asm.write(b'.code\n\nEXTERN SW3_GetSyscallNumber: PROC\n\n')
                    if self.recovery == SyscallRecoveryType.JUMPER:
                        # We perform a direct jump to the syscall instruction inside ntdll.dll
                        output_asm.write(b'EXTERN SW3_GetSyscallAddress: PROC\n\n')

                    elif self.recovery == SyscallRecoveryType.JUMPER_RANDOMIZED:
                        # We perform a direct jump to a syscall instruction of another API
                        output_asm.write(b'EXTERN SW3_GetRandomSyscallAddress: PROC\n\n')

                    for function_name in function_names:
                        output_asm.write((self._get_function_asm_code_msvc(function_name, Arch.x64) + '\n').encode())

                    output_asm.write(b'end')

            if self.arch in [Arch.Any, Arch.x86]:
                # Write x86 ASM file
                with open(f'{basename}{basename_suffix}-asm.x86.asm', 'wb') as output_asm:

                    output_asm.write(b".686\n.XMM\n.MODEL flat, c\nASSUME fs:_DATA\n.code\n\n")

                    output_asm.write(
                        b'EXTERN SW3_GetSyscallNumber: PROC\nEXTERN local_is_wow64: PROC\nEXTERN internal_cleancall_wow64_gate: PROC')
                    if self.recovery == SyscallRecoveryType.JUMPER:
                        # We perform a direct jump to the syscall instruction inside ntdll.dll
                        output_asm.write(b'\nEXTERN SW3_GetSyscallAddress: PROC')

                    elif self.recovery == SyscallRecoveryType.JUMPER_RANDOMIZED:
                        # We perform a direct jump to a syscall instruction of another API
                        output_asm.write(b'\nEXTERN SW3_GetRandomSyscallAddress: PROC')

                    output_asm.write(b'\n\n')

                    for function_name in function_names:
                        output_asm.write((self._get_function_asm_code_msvc(function_name, Arch.x86) + '\n').encode())

                    output_asm.write(b'end')

        # Write header file.
        with open(os.path.join(base_directory, 'data', 'base.h'), 'rb') as base_header:
            with open(f'{basename}.h', 'wb') as output_header:
                # Replace <SEED_VALUE> with a random seed.
                base_header_contents = base_header.read().decode()
                base_header_contents = base_header_contents.replace('<SEED_VALUE>', f'0x{self.seed:08X}', 1)

                if self.alternative_headers:
                    for f in self.includes:
                        f = Path(f).absolute().resolve()
                        base_header_contents = base_header_contents.replace('#include <windows.h>', f'#include "{f}"\n#include <windows.h>')
                if self.no_windows_headers:
                    base_header_contents = base_header_contents.replace('#include <windows.h>', '')

                # Write the base header.
                output_header.write(base_header_contents.encode())

                # Write the typedefs.
                for typedef in self._get_typedefs(function_names):
                    output_header.write(typedef.encode() + b'\n\n')

                # Write the function prototypes.
                for function_name in function_names:
                    output_header.write((self._get_function_prototype(function_name) + '\n\n').encode())

                # Write the endif line.
                output_header.write('#endif\n'.encode())

        if self.verbose:
            print('[+] Complete! Files written to:')
            print(f'\t{basename}.h')
            print(f'\t{basename}.c')
            if self.arch in [Arch.x64, Arch.Any]:
                print(f'\t{basename}{basename_suffix}-asm.x64.asm')
            if self.arch in [Arch.x86, Arch.Any]:
                print(f'\t{basename}{basename_suffix}-asm.x86.asm')
            input("[/] Press a key to continue...")

    def _get_typedefs(self, function_names: list) -> list:
        def _names_to_ids(names: list) -> list:
            return [next(i for i, t in enumerate(self.typedefs) if n in t['identifiers']) for n in names]

        # Determine typedefs to use.
        used_typedefs = []
        for function_name in function_names:
            for param in self.prototypes[function_name]['params']:
                if list(filter(lambda t: param['type'] in t['identifiers'], self.typedefs)):
                    if param['type'] not in used_typedefs:
                        used_typedefs.append(param['type'])

        # Resolve typedef dependencies.
        i = 0
        typedef_layers = {i: _names_to_ids(used_typedefs)}
        while True:
            # Identify dependencies of current layer.
            more_dependencies = []
            for typedef_id in typedef_layers[i]:
                more_dependencies += self.typedefs[typedef_id].get('dependencies')
            more_dependencies = list(set(more_dependencies))  # Remove duplicates.

            if more_dependencies:
                # Create new layer.
                i += 1
                typedef_layers[i] = _names_to_ids(more_dependencies)
            else:
                # Remove duplicates between layers.
                for k in range(len(typedef_layers) - 1):
                    typedef_layers[k] = set(typedef_layers[k]) - set(typedef_layers[k + 1])
                break

        # Get code for each typedef.
        typedef_code = []
        prefix = self.prefix + "_" if self.prefix else ""
        for i in range(max(typedef_layers.keys()), -1, -1):
            for j in typedef_layers[i]:
                code = self.typedefs[j].get('definition')
                if code.startswith('typedef') and code.split(" ")[1] in ["const", "struct", "enum"]:
                    pname = code.split(" ")[2].split("\n")[0].strip()
                    name = pname[1:]
                    if pname in self.already_defined_types:
                        continue


                #     self.structured_types.append(name)
                #     code = code.replace(name, prefix + name)
                #     # Probably handle deps here
                #     for dep in self.structured_types:
                #         if dep != name and dep in code:
                #             code = code.replace(dep + " ", prefix + dep + " ")
                # elif code.startswith('typedef'):
                #     for dep in self.structured_types:
                #         if dep in code:
                #             code = code.replace(dep + " ", prefix + dep + " ")
                typedef_code.append(code)

        return typedef_code

    def _fix_type(self, _type: str) -> str:
        return _type
        # if self.prefix in [None, ""]:
        #     return _type
        # if _type in self.structured_types:
        #     return self.prefix + "_" + _type
        #
        # elif _type.startswith("P") and _type[1:] in self.structured_types:
        #     return "P" + self.prefix + "_" + _type[1:]
        #
        # return _type
    
    def _get_function_vectored_code(self, function_name: str) -> str:
        # Check if given function is in syscall map.
        if function_name not in self.prototypes:
            raise ValueError('Invalid function name provided.')

        function_hash = self._get_function_hash(function_name)
        num_params = len(self.prototypes[function_name]['params'])
        func_body = f'NTSTATUS {self.prefix.capitalize()}{function_name}('
        if num_params:
            for i in range(num_params):
                param = self.prototypes[function_name]['params'][i]

                _type = self._fix_type(param['type'])

                func_body += '\n\t'
                func_body += f'{_type} {param["name"]}'
                func_body += ',' if i < num_params - 1 else ')'
        else:
            func_body += ')'
        
        func_body += '\n{\n'
        func_body += '\tPVOID funcAddr, syscAddr;\n'
        func_body += '\tCONTEXT threadCtx;\n'
        func_body += '\tthreadCtx.ContextFlags = CONTEXT_ALL;\n'
        func_body += '\tif (!GetThreadContext((HANDLE)-2, &threadCtx))\n'
        func_body += '\t\treturn 1;\n'
        func_body += f'\tfuncAddr = SW3_GetFunctionAddress(0x{function_hash:08X});\n'        
        func_body += f'\tsyscAddr = SW3_GetSyscallAddress(0x{function_hash:08X});\n'            
        func_body += f'\tUpdateAddresses((BYTE*)funcAddr, syscAddr, SW3_GetSyscallNumber(0x{function_hash:08X}));\n'
        func_body += '\tEnableBreakpoint(&threadCtx, EXCP_ADDR);\n'
        func_body += '\tSetThreadContext((HANDLE)-2, &threadCtx);\n'
        
        func_body += f'\treturn ((NTSTATUS (*)('
        if num_params:
            for i in range(num_params):
                param = self.prototypes[function_name]['params'][i]
                func_body += f'{param["type"]}'
                func_body += ',' if i < num_params - 1 else ')'
            func_body += ')(funcAddr))('
            for i in range(num_params):
                param = self.prototypes[function_name]['params'][i]
                func_body += f'{param["name"]}'
                func_body += ',' if i < num_params - 1 else ');'
        func_body += '\n}'
        
        return func_body      

    def _get_function_prototype(self, function_name: str) -> str:
        # Check if given function is in syscall map.
        if function_name not in self.prototypes:
            raise ValueError('Invalid function name provided.')

        num_params = len(self.prototypes[function_name]['params'])
        signature = f'EXTERN_C NTSTATUS {self.prefix.capitalize()}{function_name}('
        if num_params:
            for i in range(num_params):
                param = self.prototypes[function_name]['params'][i]

                _type = self._fix_type(param['type'])

                signature += '\n\t'
                signature += 'IN ' if param['in'] else ''
                signature += 'OUT ' if param['out'] else ''
                signature += f'{_type} {param["name"]}'
                signature += ' OPTIONAL' if param['optional'] else ''
                signature += ',' if i < num_params - 1 else ');'
        else:
            signature += ');'

        return signature

    def _get_function_hash(self, function_name: str):
        hash = self.seed
        name = function_name.replace('Nt', 'Zw', 1) + '\0'
        ror8 = lambda v: ((v >> 8) & (2 ** 32 - 1)) | ((v << 24) & (2 ** 32 - 1))

        for segment in [s for s in [name[i:i + 2] for i in range(len(name))] if len(s) == 2]:
            partial_name_short = struct.unpack('<H', segment.encode())[0]
            hash ^= partial_name_short + ror8(hash)

        return hash

    def _get_function_asm_code_mingw(self, function_name: str) -> str:
        function_hash = self._get_function_hash(function_name)
        num_params = len(self.prototypes[function_name]['params'])
        prototype = self._get_function_prototype(function_name)
        prototype = prototype.replace('EXTERN_C', '__declspec(naked)')
        prototype = prototype.replace(');', ')')

        code = prototype
        code += '\n{'
        code += '\n\tasm('
        if self.arch == Arch.Any:
            code += '\n#if defined(_WIN64)'
        if self.arch in [Arch.Any, Arch.x64]:
            # Generate 64-bit ASM code.
            code += '\n\t\t"mov [rsp +8], rcx \\n"'
            code += '\n\t\t"mov [rsp+16], rdx \\n"'
            code += '\n\t\t"mov [rsp+24], r8 \\n"'
            code += '\n\t\t"mov [rsp+32], r9 \\n"'
            code += '\n\t\t"sub rsp, 0x28 \\n"'
            code += f'\n\t\t"mov ecx, 0x{function_hash:08X} \\n"'
            if self.recovery in [SyscallRecoveryType.JUMPER, SyscallRecoveryType.JUMPER_RANDOMIZED]:
                if self.recovery == SyscallRecoveryType.JUMPER_RANDOMIZED:
                    code += '\n\t\t"call SW3_GetRandomSyscallAddress \\n"'
                else:
                    code += '\n\t\t"call SW3_GetSyscallAddress \\n"'
                code += '\n\t\t"mov r11, rax \\n"'
                code += f'\n\t\t"mov ecx, 0x{function_hash:08X} \\n"'
            code += '\n\t\t"call SW3_GetSyscallNumber \\n"'
            code += '\n\t\t"add rsp, 0x28 \\n"'
            code += '\n\t\t"mov rcx, [rsp+8] \\n"'
            code += '\n\t\t"mov rdx, [rsp+16] \\n"'
            code += '\n\t\t"mov r8, [rsp+24] \\n"'
            code += '\n\t\t"mov r9, [rsp+32] \\n"'
            code += '\n\t\t"mov r10, rcx \\n"'
            if self.debug:
                code += '\n\t\t"int 3 \\n"'

            if self.recovery in [SyscallRecoveryType.JUMPER, SyscallRecoveryType.JUMPER_RANDOMIZED]:
                code += '\n\t\t"jmp r11 \\n"'
            elif self.recovery == SyscallRecoveryType.EGG_HUNTER:
                for x in self.egg + self.egg:
                    code += f'\n\t\t"DB {x} \\n"'
                code += '\n\t\t"ret \\n"'
            elif self.recovery == SyscallRecoveryType.EMBEDDED:
                code += f'\n\t\t"{self.syscall_instruction} \\n"'
                code += '\n\t\t"ret \\n"'

        if self.arch == Arch.Any:
            code += '\n#else'

        if self.arch in [Arch.Any, Arch.x86]:
            code += '\n\t\t"push ebp \\n"'
            code += '\n\t\t"mov ebp, esp \\n"'
            code += f'\n\t\t"push 0x{function_hash:08X} \\n"'

            if self.recovery in [SyscallRecoveryType.JUMPER, SyscallRecoveryType.JUMPER_RANDOMIZED]:
                if self.recovery == SyscallRecoveryType.JUMPER_RANDOMIZED:
                    code += '\n\t\t"call _SW3_GetRandomSyscallAddress \\n"'
                else:
                    code += '\n\t\t"call _SW3_GetSyscallAddress \\n"'
                code += '\n\t\t"mov edi, eax \\n"'
                code += f'\n\t\t"push 0x{function_hash:08X} \\n"'
            code += '\n\t\t"call _SW3_GetSyscallNumber \\n"'
            code += '\n\t\t"lea esp, [esp+4] \\n"'
            code += f'\n\t\t"mov ecx, {hex(num_params)} \\n"'
            code += f'\n\t"push_argument_{function_hash:08X}: \\n"'
            code += '\n\t\t"dec ecx \\n"'
            code += '\n\t\t"push [ebp + 8 + ecx * 4] \\n"'
            code += f'\n\t\t"jnz push_argument_{function_hash:08X} \\n"'
            if self.debug:
                # 2nd SW breakpoint, to study the syscall instruction in detail
                code += '\n\t\t"int 3 \\n"'
            code += '\n\t\t"mov ecx, eax \\n"'

            if self.recovery not in [SyscallRecoveryType.JUMPER,
                                     SyscallRecoveryType.JUMPER_RANDOMIZED] \
                    and self.wow64:
                # check if the process is WoW64 or native
                code += '\n\t\t"call _local_is_wow64 \\n"'
                code += '\n\t\t"test eax, eax \\n"'
                code += '\n\t\t"je is_native \\n"'

                # if is wow64
                code += '\n\t\t"call _internal_cleancall_wow64_gate \\n"'
                code += f'\n\t\t"lea ebx, [ret_address_epilog_{function_hash:08X}] \\n"'
                code += '\n\t\t"push ebx \\n"'
                # Note: Workaround for Wow64 call
                # ntdll!NtWriteFile+0xc:
                # 77ca2a1c c22400          ret     24h
                # In a standard call, we have two addresses before the arguments passed to the Nt function
                # In this case, as we need to return to the program, we can insert the return address twice
                code += '\n\t\t"push ebx \\n"'
                code += '\n\t\t"xchg eax, ecx \\n"'
                code += '\n\t\t"jmp ecx \\n"'
                code += '\n\t\t"jmp finish \\n"'

                # if is native
                code += '\n\t"is_native: \\n"'

            code += '\n\t\t"mov eax, ecx \\n"'
            code += f'\n\t\t"lea ebx, [ret_address_epilog_{function_hash:08X}] \\n"'
            code += '\n\t\t"push ebx \\n"'
            code += f'\n\t\t"call do_sysenter_interrupt_{function_hash:08X} \\n"'

            if self.recovery not in [SyscallRecoveryType.JUMPER,
                                     SyscallRecoveryType.JUMPER_RANDOMIZED] \
                    and self.wow64:
                code += '\n\t"finish: \\n"'
            code += '\n\t\t"lea esp, [esp+4] \\n"'
            code += f'\n\t"ret_address_epilog_{function_hash:08X}: \\n"'
            code += '\n\t\t"mov esp, ebp \\n"'
            code += '\n\t\t"pop ebp \\n"'
            code += '\n\t\t"ret \\n"'

            code += f'\n\t"do_sysenter_interrupt_{function_hash:08X}: \\n"'
            code += '\n\t\t"mov edx, esp \\n"'

            if self.debug:
                code += '\n\t\t"int 3 \\n"'

            if self.recovery == SyscallRecoveryType.EGG_HUNTER:
                for x in self.egg + self.egg:
                    code += f'\n\t\t"DB {x} \\n"'
            elif self.recovery in [SyscallRecoveryType.JUMPER, SyscallRecoveryType.JUMPER_RANDOMIZED]:
                code += '\n\t\t"jmp edi \\n"'
            else:
                code += '\n\t\t"sysenter \\n"'
            code += '\n\t\t"ret \\n"'

        if self.arch == Arch.Any:
            code += '\n#endif'
        code += '\n\t);'
        code += '\n}'
        code += '\n'

        return code

    def _get_function_asm_code_msvc(self, function_name: str, arch: Arch) -> str:
        function_hash = self._get_function_hash(function_name)
        num_params = len(self.prototypes[function_name]['params'])
        code = ''

        code += f'{self.prefix.capitalize()}{function_name} PROC\n'
        if arch == Arch.x64:
            # Generate 64-bit ASM code.
            if self.debug:
                code += '\tint 3\n'
            code += '\tmov [rsp +8], rcx          ; Save registers.\n'
            code += '\tmov [rsp+16], rdx\n'
            code += '\tmov [rsp+24], r8\n'
            code += '\tmov [rsp+32], r9\n'
            code += '\tsub rsp, 28h\n'
            code += f'\tmov ecx, 0{function_hash:08X}h        ; Load function hash into ECX.\n'
            if self.recovery in [SyscallRecoveryType.JUMPER, SyscallRecoveryType.JUMPER_RANDOMIZED]:
                if self.recovery == SyscallRecoveryType.JUMPER_RANDOMIZED:
                    code += '\tcall SW3_GetRandomSyscallAddress        ; Get a syscall offset from a different api.\n'
                else:
                    code += '\tcall SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.\n'
                code += '\tmov r11, rax                           ; Save the address of the syscall\n'
                code += f'\tmov ecx, 0{function_hash:08X}h        ; Re-Load function hash into ECX (optional).\n'
            code += '\tcall SW3_GetSyscallNumber              ; Resolve function hash into syscall number.\n'
            code += '\tadd rsp, 28h\n'
            code += '\tmov rcx, [rsp+8]                      ; Restore registers.\n'
            code += '\tmov rdx, [rsp+16]\n'
            code += '\tmov r8, [rsp+24]\n'
            code += '\tmov r9, [rsp+32]\n'
            code += '\tmov r10, rcx\n'

            if self.debug:
                code += '\tint 3\n'

            if self.recovery in [SyscallRecoveryType.JUMPER, SyscallRecoveryType.JUMPER_RANDOMIZED]:
                code += '\tjmp r11                                ; Jump to -> Invoke system call.\n'
            elif self.recovery == SyscallRecoveryType.EGG_HUNTER:
                for x in self.egg + self.egg:
                    code += f'\tDB {x[2:]}h                     ; "{chr(int(x, 16)) if int(x, 16) != 0 else str(0)}"\n'
                code += '\tret\n'
            elif self.recovery == SyscallRecoveryType.EMBEDDED:
                code += f'\t{self.syscall_instruction}                    ; Invoke system call.\n'
                code += '\tret\n'
        else:
            # x32 Prolog
            code += '\t\tpush ebp\n'
            code += '\t\tmov ebp, esp\n'
            code += f'\t\tpush 0{function_hash:08X}h                  ; Load function hash into ECX.\n'

            if self.recovery in [SyscallRecoveryType.JUMPER, SyscallRecoveryType.JUMPER_RANDOMIZED]:
                if self.recovery == SyscallRecoveryType.JUMPER_RANDOMIZED:
                    code += '\t\tcall SW3_GetRandomSyscallAddress        ; Get a syscall offset from a different api.\n'
                else:
                    code += '\t\tcall SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.\n'
                code += '\t\tmov edi, eax                           ; Save the address of the syscall\n'
                code += f'\t\tpush 0{function_hash:08X}h        ; Re-Load function hash into ECX (optional).\n'
            code += '\t\tcall SW3_GetSyscallNumber\n'
            code += '\t\tlea esp, [esp+4]\n'
            code += f'\t\tmov ecx, 0{hex(num_params)[2:]}h\n'
            code += f'\tpush_argument_{function_hash:08X}:\n'
            code += '\t\tdec ecx\n'
            code += '\t\tpush [ebp + 8 + ecx * 4]\n'
            code += f'\t\tjnz push_argument_{function_hash:08X}\n'
            if self.debug:
                # 2nd SW breakpoint, to study the syscall instruction in detail
                code += '\t\tint 3\n'
            code += '\t\tmov ecx, eax\n'

            if self.recovery not in [SyscallRecoveryType.JUMPER,
                                     SyscallRecoveryType.JUMPER_RANDOMIZED] \
                    and self.wow64:
                # check if the process is WoW64 or native
                code += '\t\tcall local_is_wow64\n'
                code += '\t\ttest eax, eax\n'
                code += '\t\tje is_native\n'

                # if is wow64
                code += '\t\tcall internal_cleancall_wow64_gate\n'
                # Note: Workaround for Wow64 call
                # ntdll!NtWriteFile+0xc:
                # 77ca2a1c c22400          ret     24h
                # In a standard call, we have two addresses before the arguments passed to the Nt function
                # In this case, as we need to return to the program, we can insert the return address twice
                code += f'\t\tpush ret_address_epilog_{function_hash:08X}\n'
                code += f'\t\tpush ret_address_epilog_{function_hash:08X}\n'
                code += '\t\txchg eax, ecx\n'
                code += '\t\tjmp ecx\n'
                code += '\t\tjmp finish\n'

                # if is native
                code += '\tis_native:\n'

            code += '\t\tmov eax, ecx\n'
            code += f'\t\tpush ret_address_epilog_{function_hash:08X}\n'
            code += f'\t\tcall do_sysenter_interrupt_{function_hash:08X}\n'

            if self.recovery not in [SyscallRecoveryType.JUMPER,
                                     SyscallRecoveryType.JUMPER_RANDOMIZED] \
                    and self.wow64:
                code += '\tfinish:\n'
            code += '\t\tlea esp, [esp+4]\n'
            code += f'\tret_address_epilog_{function_hash:08X}:\n'
            code += '\t\tmov esp, ebp\n'
            code += '\t\tpop ebp\n'
            code += '\t\tret\n'

            code += f'\tdo_sysenter_interrupt_{function_hash:08X}:\n'
            code += '\t\tmov edx, esp\n'
            if self.recovery == SyscallRecoveryType.EGG_HUNTER:
                for x in self.egg + self.egg:
                    code += f'\t\tDB {x[2:]}h                     ; "{chr(int(x, 16)) if int(x, 16) != 0 else str(0)}"\n'
            elif self.recovery in [SyscallRecoveryType.JUMPER, SyscallRecoveryType.JUMPER_RANDOMIZED]:
                code += '\t\tjmp edi\n'
            else:
                code += '\t\tsysenter\n'
            code += '\t\tret\n'
        code += f'{self.prefix.capitalize()}{function_name} ENDP\n'
        return code


if __name__ == '__main__':
    print(
        "                                                       \n"
        "                  .                         ,--.       \n"
        ",-. . . ,-. . , , |-. o ,-. ,-. ,-. ,-. ,-.  __/       \n"
        "`-. | | `-. |/|/  | | | `-. | | |-' |   `-. .  \\      \n"
        "`-' `-| `-' ' '   ' ' ' `-' |-' `-' '   `-'  '''       \n"
        "     /|                     |  @Jackson_T              \n"
        "    `-'                     '  @modexpblog, 2021       \n\n"
        "                      Edits by @klezVirus,  2022       \n"
        "SysWhispers3: Why call the kernel when you can whisper?\n\n"
    )

    parser = argparse.ArgumentParser(description="SysWhispers3 - SysWhispers on steroids")
    parser.add_argument('-p', '--preset', help='Preset ("all", "common")', required=False)
    parser.add_argument('-a', '--arch', default="x64", choices=["x86", "x64", "all"], help='Architecture',
                        required=False)
    parser.add_argument('-c', '--compiler', default="msvc", choices=["msvc", "mingw", "all"], help='Compiler',
                        required=False)
    parser.add_argument('-m', '--method', default="embedded",
                        choices=["embedded", "egg_hunter", "jumper", "jumper_randomized", "vectored"],
                        help='Syscall recovery method', required=False)
    parser.add_argument('-f', '--functions', help='Comma-separated functions', required=False)
    parser.add_argument('-o', '--out-file', help='Output basename (w/o extension)', required=True)
    parser.add_argument('--int2eh', default=False, action='store_true',
                        help='Use the old `int 2eh` instruction in place of `syscall`', required=False)
    parser.add_argument('--wow64', default=False, action='store_true',
                        help='Add support for WoW64, to run x86 on x64', required=False)
    parser.add_argument('-v', '--verbose', default=False, action='store_true',
                        help='Enable debug output', required=False)
    parser.add_argument('-d', '--debug', default=False, action='store_true',
                        help='Enable syscall debug (insert software breakpoint)', required=False)
    parser.add_argument('-P', '--prefix', default="SW3", type=str,
                        help='Add prefix to function names to avoid pollution', required=False)
    parser.add_argument('-H', '--alternative-headers', default=[], action="append",
                        help='Alternative headers files (e.g., phnt.h)', required=False)
    parser.add_argument('-nWH', '--no-win-headers', default=False, action="store_true",
                        help='Do not add <windows.h> in syscalls.h', required=False)
    args = parser.parse_args()

    recovery = SyscallRecoveryType.from_name_or_default(args.method)
    arch = Arch.from_string(args.arch)
    compiler = Compiler.from_string(args.compiler)

    sw = SysWhispers(
        arch=arch,
        compiler=compiler,
        syscall_instruction="syscall" if not args.int2eh else "int 2eh",
        recovery=recovery,
        wow64=args.wow64,
        verbose=args.verbose,
        debug=args.debug,
        prefix=args.prefix,
        alternative_headers=args.alternative_headers,
        no_windows_headers=args.no_win_headers
    )
    print()

    if args.preset == 'all':
        print('[I] All functions selected.\n')
        sw.generate(basename=args.out_file)

    elif args.preset == 'common':
        print('[I] Common functions selected.\n')
        sw.generate(
            ['NtCreateProcess',
             'NtCreateThreadEx',
             'NtOpenProcess',
             'NtOpenProcessToken',
             'NtTestAlert',
             'NtOpenThread',
             'NtSuspendProcess',
             'NtSuspendThread',
             'NtResumeProcess',
             'NtResumeThread',
             'NtGetContextThread',
             'NtSetContextThread',
             'NtClose',
             'NtReadVirtualMemory',
             'NtWriteVirtualMemory',
             'NtAllocateVirtualMemory',
             'NtProtectVirtualMemory',
             'NtFreeVirtualMemory',
             'NtQuerySystemInformation',
             'NtQueryDirectoryFile',
             'NtQueryInformationFile',
             'NtQueryInformationProcess',
             'NtQueryInformationThread',
             'NtCreateSection',
             'NtOpenSection',
             'NtMapViewOfSection',
             'NtUnmapViewOfSection',
             'NtAdjustPrivilegesToken',
             'NtDeviceIoControlFile',
             'NtQueueApcThread',
             'NtWaitForMultipleObjects'],
            basename=args.out_file)

    elif args.preset:
        print('[-] Invalid preset provided. Must be "all" or "common".')

    elif not args.functions:
        print('[-] --preset XOR --functions switch must be specified.\n')
        print('[H] ./syswhispers.py --preset common --out-file syscalls_common')
        print('[H] ./syswhispers.py --functions NtTestAlert,NtGetCurrentProcessorNumber --out-file syscalls_test')

    else:
        functions = args.functions.split(',') if args.functions else []
        sw.generate(functions, args.out_file)
