__author__ = "Current Resident"
__copyright__ = "No"
__license__ = "GPL"
__version__ = "0.1"
__email__ = ["root@127.0.0.1"]

from idautils import *
from idc import *
import idaapi
import ida_segment
import ida_nalt
import ida_enum
from ida_funcs import get_func
from ida_name import get_name_ea, get_name
from ida_ua import get_dtype_size
from ida_bytes import get_byte
from idaapi import offflag, enum_flag
import sys
import string

# this makes the assumption you've ran
# golang_loader_assist beforehand

# other assumptions being made currently:
# - x86_64 arch
# - go1.11

# opinfo for offsets of the current segment
OFF_CURRENT_SEGMENT = idaapi.opinfo_t()
OFF_CURRENT_SEGMENT.ri.base = BADADDR
OFF_CURRENT_SEGMENT.ri.target = BADADDR
OFF_CURRENT_SEGMENT.ri.flags = ida_nalt.REF_OFF64

GO_BUILTIN_STRUCTS = [
    ('go_string', [
        # (name, size(int) or struct name(str), typeflags, opinfo, enum)
        ('str', 8, FF_QWORD|FF_DATA|offflag(), OFF_CURRENT_SEGMENT, None),
        ('len', 8, FF_QWORD|FF_DATA, None, None)
        ]),
    ('go_array', [
        ('data', 8, FF_QWORD|FF_DATA|offflag(), OFF_CURRENT_SEGMENT,
            None),
        ('len', 8, FF_QWORD|FF_DATA, None, None),
        ('cap', 8, FF_QWORD|FF_DATA, None, None)
        ]),
    ('go_hmap', [
        ('count', 8, FF_QWORD|FF_DATA, None, None),
        ('flags', 1, FF_BYTE|FF_DATA, None, 'go_maptype_flags'),
        ('B', 1, FF_BYTE|FF_DATA, None, None),
        ('noverflow', 2, FF_WORD|FF_DATA, None, None),
        ('hash0', 4, FF_DWORD|FF_DATA, None, None),
        ('buckets', 8, FF_QWORD|FF_DATA, OFF_CURRENT_SEGMENT, None),
        ('oldbuckets', 8, FF_QWORD|FF_DATA, OFF_CURRENT_SEGMENT, None),
        ('nevacuate', 8, FF_QWORD|FF_DATA, None, None),
        # TODO: mapextra struct
        ('extra', 8, FF_QWORD|FF_DATA|offflag(), OFF_CURRENT_SEGMENT,
            None)
        ]),
    ('go_runtime_bitvector', [
        ('n', 4, FF_DWORD|FF_DATA, None, None),
        ('bytedata', 8, FF_QWORD|FF_DATA|offflag(), OFF_CURRENT_SEGMENT,
            None)
        ]),
    ('go_runtime_moduledata', [
        ('pclntable', 'go_array', None, None, None),
        ('ftab', 'go_array', None, None, None),
        ('filetab', 'go_array', None, None, None),
        ('findfunctab', 8, FF_QWORD|FF_DATA|offflag(),
            OFF_CURRENT_SEGMENT, None),
        ('minpc', 8, FF_QWORD|FF_DATA|offflag(), OFF_CURRENT_SEGMENT,
            None),
        ('maxpc', 8, FF_QWORD|FF_DATA|offflag(), OFF_CURRENT_SEGMENT,
            None),
        ('text', 8, FF_QWORD|FF_DATA|offflag(), OFF_CURRENT_SEGMENT,
            None),
        ('etext', 8, FF_QWORD|FF_DATA|offflag(), OFF_CURRENT_SEGMENT,
            None),
        ('noptrdata', 8, FF_QWORD|FF_DATA|offflag(),
            OFF_CURRENT_SEGMENT, None),
        ('enoptrdata', 8, FF_QWORD|FF_DATA|offflag(),
            OFF_CURRENT_SEGMENT, None),
        ('data', 8, FF_QWORD|FF_DATA|offflag(), OFF_CURRENT_SEGMENT,
            None),
        ('edata', 8, FF_QWORD|FF_DATA|offflag(), OFF_CURRENT_SEGMENT,
            None),
        ('bss', 8, FF_QWORD|FF_DATA|offflag(), OFF_CURRENT_SEGMENT, None),
        ('ebss', 8, FF_QWORD|FF_DATA|offflag(), OFF_CURRENT_SEGMENT,
            None),
        ('noptrbss', 8, FF_QWORD|FF_DATA|offflag(), OFF_CURRENT_SEGMENT,
            None),
        ('enoptrbss', 8, FF_QWORD|FF_DATA|offflag(),
            OFF_CURRENT_SEGMENT, None),
        ('end', 8, FF_QWORD|FF_DATA|offflag(), OFF_CURRENT_SEGMENT, None),
        ('gcdata', 8, FF_QWORD|FF_DATA|offflag(), OFF_CURRENT_SEGMENT,
            None),
        ('gcbss', 8, FF_QWORD|FF_DATA|offflag(), OFF_CURRENT_SEGMENT,
            None),
        ('types', 8, FF_QWORD|FF_DATA|offflag(), OFF_CURRENT_SEGMENT,
            None),
        ('etypes', 8, FF_QWORD|FF_DATA|offflag(), OFF_CURRENT_SEGMENT,
            None),
        ('textsecmap', 'go_array', None, None, None),
        ('typelinks', 'go_array', None, None, None),
        ('itablinks', 'go_array', None, None, None),
        ('ptab', 'go_array', None, None, None),
        ('pluginpath', 'go_string', None, None, None),
        ('pkgHashes', 'go_array', None, None, None),
        ('modulename', 'go_string', None, None, None),
        ('modulehashes', 'go_array', None, None, None),
        ('hasmain', 1, FF_BYTE|FF_DATA, None, None),
        ('gcdatamask', 'go_runtime_bitvector', None, None, None),
        ('gcbssmask', 'go_runtime_bitvector', None, None, None),
        ('typemap', 'go_hmap', None, None, None),
        ('bad', 1, FF_BYTE|FF_DATA, None, None),
        ('next', 8, FF_QWORD|FF_DATA|offflag(), OFF_CURRENT_SEGMENT, None)
        ])
    ]


# list of typedata offset ranges (as a tuple) from
# each moduledata entry in the order that they're found
GO_TYPES_RANGES = list()


def create_and_populate_struct(struct_name, struct_fields):
    existing_struct = ida_struct.get_struc_id(struct_name)
    if existing_struct != BADADDR:
        print 'struct %s already exists, skipping..' % struct_name
        return

    new_struct = ida_struct.add_struc(BADADDR, struct_name)
    new_sptr = ida_struct.get_struc(new_struct)
    for name, struct_name_or_size, typeflags, opinfo, enum_ptr in \
            struct_fields:
        print 'adding struct field %s:%s' % (struct_name, name)
        if type(struct_name_or_size) in (str,unicode):
            # plaster in an existing struct
            existing_struct_field = ida_struct.get_struc_id(
                                        struct_name_or_size)
            if existing_struct_field == BADADDR:
                print 'ERROR: trying to add struct type %s ' \
                        'as field before it is declared, ' \
                        'cannot continue' % struct_name_or_size
                break
            existing_sptr = ida_struct.get_struc(existing_struct_field)
            existing_size = ida_struct.get_struc_size(existing_sptr)
            opinfo = idaapi.opinfo_t()
            opinfo.tid = existing_struct_field
            ida_struct.add_struc_member(new_sptr,
                                        name,
                                        BADADDR,
                                        FF_STRUCT|FF_DATA,
                                        opinfo,
                                        existing_size)
        else:
            if enum_ptr:
                existing_enum = ida_enum.get_enum(enum_ptr)
                print 'existing_enum: %x' % existing_enum
                if existing_enum == BADADDR:
                    print 'ERROR: enum %s does not exist, ' \
                            'cannot continue' % enum_ptr
                    break
                opinfo = idaapi.opinfo_t()
                opinfo.ec.tid = existing_enum
                opinfo.ec.serial = ida_enum.get_enum_idx(
                                        existing_enum)
                #opinfo.tid = existing_enum
                typeflags |= FF_0ENUM
            ida_struct.add_struc_member(
                    new_sptr, name, BADADDR,
                    typeflags, opinfo,
                    struct_name_or_size)


GO_BUILTIN_BITFIELDS = {
    # bitfield_name: (width, values)
    'go_tflag': (1, { # type flags
        # value_name: (value, mask)
        'tflagUncommon': (1, 0x01),
        'tflagExtraStar': (2, 0x02),
        'tflagNamed': (4, 0x04)
        }),
    'go_NameFlags': (1, { # name flags
        'nameExported': (1, 0x1),
        'nameTagFollowsName': (2, 0x2),
        'namePkgPathFollowsTag': (4, 0x4),
        }),
    'go_typekind': (1, { # kind value + flags
        'kindBool': (1, 0x1f),
        'kindInt': (2, 0x1f),
        'kindInt8': (3, 0x1f),
        'kindInt16': (4, 0x1f),
        'kindInt32': (5, 0x1f),
        'kindInt64': (6, 0x1f),
        'kindUint': (7, 0x1f),
        'kindUint8': (8, 0x1f),
        'kindUint16': (9, 0x1f),
        'kindUint32': (10, 0x1f),
        'kindUint64': (11, 0x1f),
        'kindUintptr': (12, 0x1f),
        'kindFloat32': (13, 0x1f),
        'kindFloat64': (14, 0x1f),
        'kindComplex64': (15, 0x1f),
        'kindComplex128': (16, 0x1f),
        'kindArray': (17, 0x1f),
        'kindChan': (18, 0x1f),
        'kindFunc': (19, 0x1f),
        'kindInterface': (20, 0x1f),
        'kindMap': (21, 0x1f),
        'kindPtr': (22, 0x1f),
        'kindSlice': (23, 0x1f),
        'kindString': (24, 0x1f),
        'kindStruct': (25, 0x1f),
        'kindUnsafePointer': (26, 0x1f),
        'kindDirectIface': (0x20, 0x20),
        'kindGCProg': (0x40, 0x40),
        'kindNoPointers': (0x80, 0x80)
        }),
    'go_maptype_flags': (1, {
        'IndirectKey': (1, 0x1),
        'IndirectElem': (2, 0x2),
        'ReflexiveKey': (4, 0x4),
        'NeedKeyUpdate': (8, 0x8),
        'HashMightPanic': (16, 0x10)
        })
    }


def populate_builtin_bitfields():
    for bf_name, (bf_size, bf_values) in GO_BUILTIN_BITFIELDS.items():
        existing_enum = ida_enum.get_enum(bf_name)
        if existing_enum != BADADDR:
            print 'bitfield %s already exists, skipping..' % bf_name
            continue
        new_bf_id = ida_enum.add_enum(BADADDR, bf_name, 0)
        ida_enum.set_enum_bf(new_bf_id, True)
        ida_enum.set_enum_width(new_bf_id, bf_size)
        for name, (enum_val, bf_mask) in bf_values.items():
            ret = ida_enum.add_enum_member(new_bf_id, name,
                                           enum_val, bf_mask)
            if ret != 0:
                print 'Could not add %s bitfield value to %s ' \
                        '(error code %d)' % (name, bf_name, ret)
                break


def find_runtime_newobject_fn():
    return get_name_ea(BADADDR, 'runtime_newobject')


def rename_type_structs():
    runtime_newobject_fn = find_runtime_newobject_fn()
    if runtime_newobject_fn == BADADDR:
        print 'Could not find runtime_newobject, not moving on ' \
                '(did you run golang_loader_assist.py beforehand?)'
        return 1

    for newobject_xref in XrefsTo(runtime_newobject_fn, 0):
        # find the most recent mov to [rsp] prior to the call
        # instruction, continue backtracking til you find
        # the register being assigned an EA to an immediate value
        #
        # lea rbx, unk_XXXXXX
        # ...
        # mov [rsp], rbx
        # ...
        # call runtime_newobject
        register_n = -1
        xref_func = get_func(newobject_xref.frm)
        go_type_addr = BADADDR
        if not xref_func or xref_func.start_ea == BADADDR:
            continue

        inst = DecodePreviousInstruction(newobject_xref.frm)
        while inst and inst.ea != BADADDR:
            if inst.ea < xref_func.start_ea:
                # we went past the actual function
                print 'inst went past the function EA, wat..'
                break

            if register_n == -1:
                # is it the mov [rsp], xxx instruction?
                if inst.Op1.specflag1: # SIB byte in effect
                    regsize = get_dtype_size(inst.Op1.dtype)
                    base_reg_n = inst.Op1.specflag2 & 7
                    if idaapi.get_reg_name(base_reg_n, regsize) == 'rsp' \
                            and inst.Op1.addr == 0:
                        register_n = inst.Op2.reg

            else:
                # is it the lea xxx, unk_XXXXXX instruction?
                if inst.Op1.reg == register_n and \
                        get_byte(inst.ea+1) == 0x8D:

                    # assure second operand is an immediate value
                    if inst.Op2.type == 2:
                        go_type_addr = inst.Op2.addr
                    else:
                        # it's grabbing it from a struct field
                        # or something. ignore it.  we're most
                        # likely in the "runtime" module anyway.
                        pass

                    break
            inst = DecodePreviousInstruction(inst.ea)

        if go_type_addr != BADADDR:
            data_name = get_name(go_type_addr)
            print 'found go data type at %s' % data_name


def populate_builtin_structs():
    for struct_name, struct_data in GO_BUILTIN_STRUCTS:
        print 'Adding struct %s...' % struct_name
        create_and_populate_struct(struct_name, struct_data)


def find_runtime_firstmoduledata():
    return ida_name.get_name_ea(BADADDR, 'runtime.firstmoduledata')


def get_next_moduledata(ea):
    md_next_member = ida_struct.get_member_by_fullname(
                        'go_runtime_moduledata.next')[0]
    return ida_bytes.get_qword(ea + md_next_member.soff) \
            or BADADDR


def create_go_type_struct(idx, types_ea):
    go_type_name = 'go_type%d' % idx
    types_opinfo = idaapi.opinfo_t()
    types_opinfo.ri.base = types_ea
    types_opinfo.ri.target = BADADDR
    types_opinfo.ri.tdelta = 0
    types_opinfo.ri.flags = ida_nalt.REF_OFF64
    go_type_spec = [
        ('size', 8, FF_QWORD|FF_DATA, None, None),
        ('ptrdata', 8, FF_QWORD|FF_DATA, None, None),
        ('hash', 4, FF_DWORD|FF_DATA, None, None),
        ('tflag', 1, FF_BYTE|FF_DATA, None, 'go_tflag'),
        ('align', 1, FF_BYTE|FF_DATA, None, None),
        ('fieldalign', 1, FF_BYTE|FF_DATA, None, None),
        ('kind', 1, FF_BYTE|FF_DATA, None, 'go_typekind'),
        ('alg', 8, FF_QWORD|FF_DATA, None, None),
        ('gcdata', 8, FF_QWORD|FF_DATA, None, None),
        ('str', 4, FF_DWORD|FF_DATA|offflag(), types_opinfo, None),
        ('ptrToThis', 4, FF_DWORD|FF_DATA|offflag(), types_opinfo, None)
        ]
    return create_and_populate_struct(go_type_name, go_type_spec)


def main():
    print 'populating built-in bitfields...'
    populate_builtin_bitfields()

    print 'populating built-in runtime structs...'
    populate_builtin_structs()

    print 'finding and declaring moduledata structs...'
    moduledata_ea = find_runtime_firstmoduledata()
    if moduledata_ea == BADADDR:
        print 'ERROR: could not find runtime.firstmoduledata...'
        return

    moduledata_struct_id = ida_struct.get_struc_id('go_runtime_moduledata')
    if moduledata_struct_id != BADADDR:
        moduledata_size = ida_struct.get_struc_size(
                            ida_struct.get_struc(moduledata_struct_id))
        types_struct_offset = ida_struct.get_member_by_fullname(
                                    'go_runtime_moduledata.types')[0].soff
        etypes_struct_offset = ida_struct.get_member_by_fullname(
                                    'go_runtime_moduledata.etypes')[0].soff

        while moduledata_ea != BADADDR:
            print 'found moduledata at %x' % moduledata_ea
            if not ida_bytes.del_items(moduledata_ea, 0,
                                       moduledata_size):
                print 'ERROR: could not undefine byte range for ' \
                        'moduledata at %x' % moduledata_ea
                return
            if not ida_bytes.create_struct(moduledata_ea, moduledata_size,
                                           moduledata_struct_id):
                print 'ERROR: could not create moduledata struct at ' \
                        '%x' % moduledata_ea
                return

            types_offset = ida_bytes.get_qword(
                    moduledata_ea + types_struct_offset)
            etypes_offset = ida_bytes.get_qword(
                    moduledata_ea + etypes_struct_offset)
            GO_TYPES_RANGES.append( (types_offset,etypes_offset) )
            moduledata_ea = get_next_moduledata(moduledata_ea)

    # create a different type struct for each moduledata types
    # list, as the name and type offsets in the go_type struct
    # rely on that particular offset
    for idx, (types_start_ea, _) in enumerate(GO_TYPES_RANGES):
        print 'Creating type struct (types offset: %x)' % types_start_ea
        create_go_type_struct(idx, types_start_ea)

    #print 'renaming type structs...'
    #rename_type_structs()



if __name__ == '__main__':
    main()
