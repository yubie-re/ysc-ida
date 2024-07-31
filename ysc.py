# ----------------------------------------------------------------------
# (c) Hex-Rays
import sys
import idaapi
from idaapi import *
import ida_pro
import ida_bytes
import idc
import idautils
import ctypes

if sys.version_info.major < 3:
  print("Needs python3!")


# Opcodes
OP_NOP = 0
OP_IADD = 1
OP_ISUB = 2
OP_IMUL = 3
OP_IDIV = 4
OP_IMOD = 5
OP_INOT = 6
OP_INEG = 7
OP_IEQ = 8
OP_INE = 9
OP_IGT = 10
OP_IGE = 11
OP_ILT = 12
OP_ILE = 13
OP_FADD = 14
OP_FSUB = 15
OP_FMUL = 16
OP_FDIV = 17
OP_FMOD = 18
OP_FNEG = 19
OP_FEQ = 20
OP_FNE = 21
OP_FGT = 22
OP_FGE = 23
OP_FLT = 24
OP_FLE = 25
OP_VADD = 26
OP_VSUB = 27
OP_VMUL = 28
OP_VDIV = 29
OP_VNEG = 30
OP_IAND = 31
OP_IOR = 32
OP_IXOR = 33
OP_I2F = 34
OP_F2I = 35
OP_F2V = 36
OP_PUSH_CONST_U8 = 37
OP_PUSH_CONST_U8_U8 = 38
OP_PUSH_CONST_U8_U8_U8 = 39
OP_PUSH_CONST_U32 = 40
OP_PUSH_CONST_F = 41
OP_DUP = 42
OP_DROP = 43
OP_NATIVE = 44
OP_ENTER = 45
OP_LEAVE = 46
OP_LOAD = 47
OP_STORE = 48
OP_STORE_REV = 49
OP_LOAD_N = 50
OP_STORE_N = 51
OP_ARRAY_U8 = 52
OP_ARRAY_U8_LOAD = 53
OP_ARRAY_U8_STORE = 54
OP_LOCAL_U8 = 55
OP_LOCAL_U8_LOAD = 56
OP_LOCAL_U8_STORE = 57
OP_STATIC_U8 = 58
OP_STATIC_U8_LOAD = 59
OP_STATIC_U8_STORE = 60
OP_IADD_U8 = 61
OP_IMUL_U8 = 62
OP_IOFFSET = 63
OP_IOFFSET_U8 = 64
OP_IOFFSET_U8_LOAD = 65
OP_IOFFSET_U8_STORE = 66
OP_PUSH_CONST_S16 = 67
OP_IADD_S16 = 68
OP_IMUL_S16 = 69
OP_IOFFSET_S16 = 70
OP_IOFFSET_S16_LOAD = 71
OP_IOFFSET_S16_STORE = 72
OP_ARRAY_U16 = 73
OP_ARRAY_U16_LOAD = 74
OP_ARRAY_U16_STORE = 75
OP_LOCAL_U16 = 76
OP_LOCAL_U16_LOAD = 77
OP_LOCAL_U16_STORE = 78
OP_STATIC_U16 = 79
OP_STATIC_U16_LOAD = 80
OP_STATIC_U16_STORE = 81
OP_GLOBAL_U16 = 82
OP_GLOBAL_U16_LOAD = 83
OP_GLOBAL_U16_STORE = 84
OP_J = 85
OP_JZ = 86
OP_IEQ_JZ = 87
OP_INE_JZ = 88
OP_IGT_JZ = 89
OP_IGE_JZ = 90
OP_ILT_JZ = 91
OP_ILE_JZ = 92
OP_CALL = 93
OP_STATIC_U24 = 94
OP_STATIC_U24_LOAD = 95
OP_STATIC_U24_STORE = 96
OP_GLOBAL_U24 = 97
OP_GLOBAL_U24_LOAD = 98
OP_GLOBAL_U24_STORE = 99
OP_PUSH_CONST_U24 = 100
OP_SWITCH = 101
OP_STRING = 102
OP_STRINGHASH = 103
OP_TEXT_LABEL_ASSIGN_STRING = 104
OP_TEXT_LABEL_ASSIGN_INT = 105
OP_TEXT_LABEL_APPEND_STRING = 106
OP_TEXT_LABEL_APPEND_INT = 107
OP_TEXT_LABEL_COPY = 108
OP_CATCH = 109
OP_THROW = 110
OP_CALLINDIRECT = 111
OP_PUSH_CONST_M1 = 112
OP_PUSH_CONST_0 = 113
OP_PUSH_CONST_1 = 114
OP_PUSH_CONST_2 = 115
OP_PUSH_CONST_3 = 116
OP_PUSH_CONST_4 = 117
OP_PUSH_CONST_5 = 118
OP_PUSH_CONST_6 = 119
OP_PUSH_CONST_7 = 120
OP_PUSH_CONST_FM1 = 121
OP_PUSH_CONST_F0 = 122
OP_PUSH_CONST_F1 = 123
OP_PUSH_CONST_F2 = 124
OP_PUSH_CONST_F3 = 125
OP_PUSH_CONST_F4 = 126
OP_PUSH_CONST_F5 = 127
OP_PUSH_CONST_F6 = 128
OP_PUSH_CONST_F7 = 129
OP_IS_BIT_SET = 130


# ----------------------------------------------------------------------
class ysc_t(idaapi.processor_t):
    """
    Processor module classes must derive from idaapi.processor_t

    A processor_t instance is, conceptually, both an IDP_Hooks and
    an IDB_Hooks. This means any callback from those two classes
    can be implemented. Below, you'll find a handful of those
    as an example (e.g., ev_out_header(), ev_newfile(), ...)
    Also note that some IDP_Hooks callbacks must be implemented
    """

    # IDP id ( Numbers above 0x8000 are reserved for the third-party modules)
    id = 0x8000 + 2704

    # Processor features
    flag = PR_ASSEMBLE | PR_SEGS | PR_DEFSEG32 | PR_USE32 | PRN_HEX | PR_RNAMESOK

    # Number of bits in a byte for code segments (usually 8)
    # IDA supports values up to 32 bits (64 for IDA64)
    cnbits = 8

    # Number of bits in a byte for non-code segments (usually 8)
    # IDA supports values up to 32 bits (64 for IDA64)
    dnbits = 8

    # short processor names
    # Each name should be shorter than 9 characters
    psnames = ['ysc']

    # long processor names
    # No restriction on name lengthes.
    plnames = ['RAGE Script Compiler']

    # register names
    reg_names = [
        # General purpose registers
        "SP", # aka R0
        # Fake segment registers
        "CS",
        "DS"
    ]

    # number of registers (optional: deduced from the len(reg_names))
    regs_num = len(reg_names)

    # Segment register information (use virtual CS and DS registers if your
    # processor doesn't have segment registers):
    reg_first_sreg = 1 # index of CS
    reg_last_sreg  = 2 # index of DS

    # size of a segment register in bytes
    segreg_size = 0

    # You should define 2 virtual segment registers for CS and DS.

    # number of CS/DS registers
    reg_code_sreg = 1
    reg_data_sreg = 2

    # Array of typical code start sequences (optional)
    codestart = [bytearray([OP_ENTER])]

    # Array of 'return' instruction opcodes (optional)
    retcodes = [bytearray([OP_LEAVE])]

    instruc = [
        {'name': 'NOP', 'feature': 0},
        {'name': 'IADD', 'feature': 0},
        {'name': 'ISUB', 'feature': 0},
        {'name': 'IMUL', 'feature': 0},
        {'name': 'IDIV', 'feature': 0},
        {'name': 'IMOD', 'feature': 0},
        {'name': 'INOT', 'feature': 0},
        {'name': 'INEG', 'feature': 0},
        {'name': 'IEQ', 'feature': 0},
        {'name': 'INE', 'feature': 0},
        {'name': 'IGT', 'feature': 0},
        {'name': 'IGE', 'feature': 0},
        {'name': 'ILT', 'feature': 0},
        {'name': 'ILE', 'feature': 0},
        {'name': 'FADD', 'feature': 0},
        {'name': 'FSUB', 'feature': 0},
        {'name': 'FMUL', 'feature': 0},
        {'name': 'FDIV', 'feature': 0},
        {'name': 'FMOD', 'feature': 0},
        {'name': 'FNEG', 'feature': 0},
        {'name': 'FEQ', 'feature': 0},
        {'name': 'FNE', 'feature': 0},
        {'name': 'FGT', 'feature': 0},
        {'name': 'FGE', 'feature': 0},
        {'name': 'FLT', 'feature': 0},
        {'name': 'FLE', 'feature': 0},
        {'name': 'VADD', 'feature': 0},
        {'name': 'VSUB', 'feature': 0},
        {'name': 'VMUL', 'feature': 0},
        {'name': 'VDIV', 'feature': 0},
        {'name': 'VNEG', 'feature': 0},
        {'name': 'IAND', 'feature': 0},
        {'name': 'IOR', 'feature': 0},
        {'name': 'IXOR', 'feature': 0},
        {'name': 'I2F', 'feature': 0},
        {'name': 'F2I', 'feature': 0},
        {'name': 'F2V', 'feature': 0},
        {'name': 'PUSH_CONST_U8', 'feature': 0},
        {'name': 'PUSH_CONST_U8_U8', 'feature': 0},
        {'name': 'PUSH_CONST_U8_U8_U8', 'feature': 0},
        {'name': 'PUSH_CONST_U32', 'feature': 0},
        {'name': 'PUSH_CONST_F', 'feature': 0},
        {'name': 'DUP', 'feature': 0},
        {'name': 'DROP', 'feature': 0},
        {'name': 'NATIVE', 'feature': 0},
        {'name': 'ENTER', 'feature': 0},
        {'name': 'LEAVE', 'feature': CF_STOP},
        {'name': 'LOAD', 'feature': 0},
        {'name': 'STORE', 'feature': 0},
        {'name': 'STORE_REV', 'feature': 0},
        {'name': 'LOAD_N', 'feature': 0},
        {'name': 'STORE_N', 'feature': 0},
        {'name': 'ARRAY_U8', 'feature': 0},
        {'name': 'ARRAY_U8_LOAD', 'feature': 0},
        {'name': 'ARRAY_U8_STORE', 'feature': 0},
        {'name': 'LOCAL_U8', 'feature': 0},
        {'name': 'LOCAL_U8_LOAD', 'feature': 0},
        {'name': 'LOCAL_U8_STORE', 'feature': 0},
        {'name': 'STATIC_U8', 'feature': 0},
        {'name': 'STATIC_U8_LOAD', 'feature': 0},
        {'name': 'STATIC_U8_STORE', 'feature': 0},
        {'name': 'IADD_U8', 'feature': 0},
        {'name': 'IMUL_U8', 'feature': 0},
        {'name': 'IOFFSET', 'feature': 0},
        {'name': 'IOFFSET_U8', 'feature': 0},
        {'name': 'IOFFSET_U8_LOAD', 'feature': 0},
        {'name': 'IOFFSET_U8_STORE', 'feature': 0},
        {'name': 'PUSH_CONST_S16', 'feature': 0},
        {'name': 'IADD_S16', 'feature': 0},
        {'name': 'IMUL_S16', 'feature': 0},
        {'name': 'IOFFSET_S16', 'feature': 0},
        {'name': 'IOFFSET_S16_LOAD', 'feature': 0},
        {'name': 'IOFFSET_S16_STORE', 'feature': 0},
        {'name': 'ARRAY_U16', 'feature': 0},
        {'name': 'ARRAY_U16_LOAD', 'feature': 0},
        {'name': 'ARRAY_U16_STORE', 'feature': 0},
        {'name': 'LOCAL_U16', 'feature': 0},
        {'name': 'LOCAL_U16_LOAD', 'feature': 0},
        {'name': 'LOCAL_U16_STORE', 'feature': 0},
        {'name': 'STATIC_U16', 'feature': 0},
        {'name': 'STATIC_U16_LOAD', 'feature': 0},
        {'name': 'STATIC_U16_STORE', 'feature': 0},
        {'name': 'GLOBAL_U16', 'feature': 0},
        {'name': 'GLOBAL_U16_LOAD', 'feature': 0},
        {'name': 'GLOBAL_U16_STORE', 'feature': 0},
        {'name': 'J', 'feature': CF_USE1},
        {'name': 'JZ', 'feature': CF_USE1},
        {'name': 'IEQ_JZ', 'feature': CF_USE1},
        {'name': 'INE_JZ', 'feature': CF_USE1},
        {'name': 'IGT_JZ', 'feature': CF_USE1},
        {'name': 'IGE_JZ', 'feature': CF_USE1},
        {'name': 'ILT_JZ', 'feature': CF_USE1},
        {'name': 'ILE_JZ', 'feature': CF_USE1},
        {'name': 'CALL', 'feature': CF_CALL | CF_USE1},
        {'name': 'STATIC_U24', 'feature': 0},
        {'name': 'STATIC_U24_LOAD', 'feature': 0},
        {'name': 'STATIC_U24_STORE', 'feature': 0},
        {'name': 'GLOBAL_U24', 'feature': 0},
        {'name': 'GLOBAL_U24_LOAD', 'feature': 0},
        {'name': 'GLOBAL_U24_STORE', 'feature': 0},
        {'name': 'PUSH_CONST_U24', 'feature': 0},
        {'name': 'SWITCH', 'feature': CF_JUMP},
        {'name': 'STRING', 'feature': 0},
        {'name': 'STRINGHASH', 'feature': 0},
        {'name': 'TEXT_LABEL_ASSIGN_STRING', 'feature': 0},
        {'name': 'TEXT_LABEL_ASSIGN_INT', 'feature': 0},
        {'name': 'TEXT_LABEL_APPEND_STRING', 'feature': 0},
        {'name': 'TEXT_LABEL_APPEND_INT', 'feature': 0},
        {'name': 'TEXT_LABEL_COPY', 'feature': 0},
        {'name': 'CATCH', 'feature': 0},
        {'name': 'THROW', 'feature': 0},
        {'name': 'CALLINDIRECT', 'feature': CF_CALL},
        {'name': 'PUSH_CONST_M1', 'feature': 0},
        {'name': 'PUSH_CONST_0', 'feature': 0},
        {'name': 'PUSH_CONST_1', 'feature': 0},
        {'name': 'PUSH_CONST_2', 'feature': 0},
        {'name': 'PUSH_CONST_3', 'feature': 0},
        {'name': 'PUSH_CONST_4', 'feature': 0},
        {'name': 'PUSH_CONST_5', 'feature': 0},
        {'name': 'PUSH_CONST_6', 'feature': 0},
        {'name': 'PUSH_CONST_7', 'feature': 0},
        {'name': 'PUSH_CONST_FM1', 'feature': 0},
        {'name': 'PUSH_CONST_F0', 'feature': 0},
        {'name': 'PUSH_CONST_F1', 'feature': 0},
        {'name': 'PUSH_CONST_F2', 'feature': 0},
        {'name': 'PUSH_CONST_F3', 'feature': 0},
        {'name': 'PUSH_CONST_F4', 'feature': 0},
        {'name': 'PUSH_CONST_F5', 'feature': 0},
        {'name': 'PUSH_CONST_F6', 'feature': 0},
        {'name': 'PUSH_CONST_F7', 'feature': 0},
        {'name': 'IS_BIT_SET', 'feature': 0},
    ]

    # icode of the first instruction
    instruc_start = 0

    # icode of the last instruction + 1
    instruc_end = len(instruc)

    # Size of long double (tbyte) for this processor (meaningful only if ash.a_tbyte != NULL) (optional)
    tbyte_size = 0

    #
    # Number of digits in floating numbers after the decimal point.
    # If an element of this array equals 0, then the corresponding
    # floating point data is not used for the processor.
    # This array is used to align numbers in the output.
    #      real_width[0] - number of digits for short floats (only PDP-11 has them)
    #      real_width[1] - number of digits for "float"
    #      real_width[2] - number of digits for "double"
    #      real_width[3] - number of digits for "long double"
    # Example: IBM PC module has { 0,7,15,19 }
    #
    # (optional)
    real_width = (0, 7, 0, 0)

    # icode (or instruction number) of return instruction. It is ok to give any of possible return
    # instructions
    icode_return = OP_LEAVE

    # only one assembler is supported
    assembler = {
        # flag
        'flag' : ASH_HEXF3 | AS_UNEQU | AS_COLON | ASB_BINF4 | AS_N2CHR,

        # user defined flags (local only for IDP) (optional)
        'uflag' : 0,

        # Assembler name (displayed in menus)
        'name': "YSC",

        # array of automatically generated header lines they appear at the start of disassembled text (optional)
        'header': ["Line1", "Line2"],

        # org directive
        'origin': "org",

        # end directive
        'end': "end",

        # comment string (see also cmnt2)
        'cmnt': ";",

        # ASCII string delimiter
        'ascsep': "\"",

        # ASCII char constant delimiter
        'accsep': "'",

        # ASCII special chars (they can't appear in character and ascii constants)
        'esccodes': "\"'",

        #
        #      Data representation (db,dw,...):
        #
        # ASCII string directive
        'a_ascii': "db",

        # byte directive
        'a_byte': "db",

        # word directive
        'a_word': "dw",

        # remove if not allowed
        'a_dword': "dd",

        # remove if not allowed
        'a_qword': "dq",

        # remove if not allowed
        'a_oword': "xmmword",

        # remove if not allowed
        'a_yword': "ymmword",

        # float;  4bytes; remove if not allowed
        'a_float': "dd",

        # double; 8bytes; NULL if not allowed
        'a_double': "dq",

        # long double;    NULL if not allowed
        'a_tbyte': "dt",

        # packed decimal real; remove if not allowed (optional)
        'a_packreal': "",

        # array keyword. the following
        # sequences may appear:
        #      #h - header
        #      #d - size
        #      #v - value
        #      #s(b,w,l,q,f,d,o) - size specifiers
        #                        for byte,word,
        #                            dword,qword,
        #                            float,double,oword
        'a_dups': "#d dup(#v)",

        # uninitialized data directive (should include '%s' for the size of data)
        'a_bss': "%s dup ?",

        # 'equ' Used if AS_UNEQU is set (optional)
        'a_equ': ".equ",

        # 'seg ' prefix (example: push seg seg001)
        'a_seg': "seg",

        # current IP (instruction pointer) symbol in assembler
        'a_curip': "$",

        # "public" name keyword. NULL-gen default, ""-do not generate
        'a_public': "public",

        # "weak"   name keyword. NULL-gen default, ""-do not generate
        'a_weak': "weak",

        # "extrn"  name keyword
        'a_extrn': "extrn",

        # "comm" (communal variable)
        'a_comdef': "",

        # "align" keyword
        'a_align': "align",

        # Left and right braces used in complex expressions
        'lbrace': "(",
        'rbrace': ")",

        # %  mod     assembler time operation
        'a_mod': "%",

        # &  bit and assembler time operation
        'a_band': "&",

        # |  bit or  assembler time operation
        'a_bor': "|",

        # ^  bit xor assembler time operation
        'a_xor': "^",

        # ~  bit not assembler time operation
        'a_bnot': "~",

        # << shift left assembler time operation
        'a_shl': "<<",

        # >> shift right assembler time operation
        'a_shr': ">>",

        # size of type (format string) (optional)
        'a_sizeof_fmt': "size %s",

        'flag2': 0,

        # comment close string (optional)
        # this is used to denote a string which closes comments, for example, if the comments are represented with (* ... *)
        # then cmnt = "(*" and cmnt2 = "*)"
        'cmnt2': "",

        # low8 operation, should contain %s for the operand (optional fields)
        'low8': "",
        'high8': "",
        'low16': "",
        'high16': "",

        # the include directive (format string) (optional)
        'a_include_fmt': "include %s",

        # if a named item is a structure and displayed  in the verbose (multiline) form then display the name
        # as printf(a_strucname_fmt, typename)
        # (for asms with type checking, e.g. tasm ideal)
        # (optional)
        'a_vstruc_fmt': "",

        # 'rva' keyword for image based offsets (optional)
        # (see nalt.hpp, REFINFO_RVA)
        'a_rva': "rva"
    } # Assembler


    OPTION_KEY_OPERAND_SEPARATOR = "PROCTEMPLATE_OPERAND_SEPARATOR"
    OPTION_KEY_OPERAND_SPACES = "PROCTEMPLATE_OPERAND_SPACES"


    # ----------------------------------------------------------------------
    def __init__(self):
      idaapi.processor_t.__init__(self)
      self.operand_separator = ','
      self.operand_spaces = 1

    #
    # IDP_Hooks callbacks (the first 4 are mandatory)
    #

    def ev_out_operand(self, ctx, op):
        """
        Generate text representation of an instructon operand.
        This function shouldn't change the database, flags or anything else.
        All these actions should be performed only by u_emu() function.
        The output text is placed in the output buffer initialized with init_output_buffer()
        This function uses out_...() functions from ua.hpp to generate the operand text
        Returns: 1-ok, 0-operand is hidden.
        """
        optype = op.type
        fl     = op.specval

        if optype == o_reg:
            ctx.out_register(self.reg_names[op.reg])

        elif optype == o_imm:
            ctx.out_value(op, OOFW_IMM)

        elif optype in [o_near, o_mem]:
            r = ctx.out_name_expr(op, op.addr, BADADDR)
            if not r:
                ctx.out_tagon(COLOR_ERROR)
                ctx.out_btoa(op.addr, 16)
                ctx.out_tagoff(COLOR_ERROR)
                #remember_problem(PR_NONAME, ctx.insn.ea)
        elif optype == o_displ:
            r = ctx.out_name_expr(op, ctypes.c_short(op.value).value + ctx.insn.ea + ctx.insn.size, BADADDR)
            if not r:
                ctx.out_tagon(COLOR_ERROR)
                ctx.out_btoa(ctypes.c_short(op.value).value + ctx.insn.ea + ctx.insn.size, 16)
                ctx.out_tagoff(COLOR_ERROR)
        else:
            return False

        return True

    def ev_out_insn(self, ctx):
        """
        Generate text representation of an instruction in 'ctx.insn' structure.
        This function shouldn't change the database, flags or anything else.
        All these actions should be performed only by u_emu() function.
        Returns: nothing
        """
        ctx.out_mnemonic()

        for i in range(0, 2):
            op = ctx.insn[i]
            if op.type == o_void:
                break;
            if i > 0:
                ctx.out_symbol(self.operand_separator)
                for _ in range(self.operand_spaces):
                  ctx.out_char(' ')
            ctx.out_one_operand(i)

        ctx.set_gen_cmt()
        ctx.flush_outbuf()
        return True

    def ev_ana_insn(self, insn):
        """
        Decodes an instruction into insn
        Returns: insn.size (=the size of the decoded instruction) or zero
        """
        insn.itype = insn.get_next_byte()
        if insn.itype == OP_PUSH_CONST_U8:
            insn.Op1.type = o_imm
            insn.Op1.dtype = dt_byte
            insn.Op1.value = insn.get_next_byte()
        elif insn.itype == OP_PUSH_CONST_U8_U8:
            insn.Op1.type = o_imm
            insn.Op1.dtype = dt_byte
            insn.Op1.value = insn.get_next_byte()
            insn.Op2.type = o_imm
            insn.Op2.dtype = dt_byte
            insn.Op2.value = insn.get_next_byte()
        elif insn.itype == OP_PUSH_CONST_U8_U8_U8:
            insn.Op1.type = o_imm
            insn.Op1.dtype = dt_byte
            insn.Op1.value = insn.get_next_byte()
            insn.Op2.type = o_imm
            insn.Op2.dtype = dt_byte
            insn.Op2.value = insn.get_next_byte()
            insn.Op3.type = o_imm
            insn.Op3.dtype = dt_byte
            insn.Op3.value = insn.get_next_byte()
        elif insn.itype == OP_PUSH_CONST_U32:
            insn.Op1.type = o_imm
            insn.Op1.dtype = dt_dword
            insn.Op1.value = insn.get_next_dword()
        elif insn.itype == OP_PUSH_CONST_F:
            insn.Op1.type = o_imm
            insn.Op1.dtype = dt_float
            insn.Op1.value = insn.get_next_dword()
        elif insn.itype == OP_NATIVE:
            insn.Op1.type = o_imm
            insn.Op1.dtype = dt_byte
            insn.Op1.value = insn.get_next_byte()
            insn.Op2.type = o_mem
            insn.Op2.dtype = dt_qword
            for s in idautils.Segments():
                if idc.get_segm_name(s) == "NATIVES":
                    native_segment = idc.get_segm_start(s)
            insn.Op2.addr = native_segment + ((insn.get_next_byte() << 8) | insn.get_next_byte()) * 8
        elif insn.itype == OP_ENTER:
            insn.Op1.type = o_imm
            insn.Op1.dtype = dt_byte
            insn.Op1.value = insn.get_next_byte()
            insn.Op2.type = o_imm
            insn.Op2.dtype = dt_word
            insn.Op2.value = insn.get_next_word()
            insn.Op3.type = o_imm
            insn.Op3.dtype = dt_byte
            insn.Op3.value = insn.get_next_byte()
        elif insn.itype == OP_LEAVE:
            insn.Op1.type = o_imm
            insn.Op1.dtype = dt_byte
            insn.Op1.value = insn.get_next_byte()
            insn.Op2.type = o_imm
            insn.Op2.dtype = dt_byte
            insn.Op2.value = insn.get_next_byte()
        elif insn.itype == OP_ARRAY_U8:
            insn.Op1.type = o_imm
            insn.Op1.dtype = dt_byte
            insn.Op1.value = insn.get_next_byte()
        elif insn.itype == OP_ARRAY_U8_LOAD:
            insn.Op1.type = o_imm
            insn.Op1.dtype = dt_byte
            insn.Op1.value = insn.get_next_byte()
        elif insn.itype == OP_ARRAY_U8_STORE:
            insn.Op1.type = o_imm
            insn.Op1.dtype = dt_byte
            insn.Op1.value = insn.get_next_byte()
        elif insn.itype == OP_LOCAL_U8:
            insn.Op1.type = o_imm
            insn.Op1.dtype = dt_byte
            insn.Op1.value = insn.get_next_byte()
        elif insn.itype == OP_LOCAL_U8_LOAD:
            insn.Op1.type = o_imm
            insn.Op1.dtype = dt_byte
            insn.Op1.value = insn.get_next_byte()
        elif insn.itype == OP_LOCAL_U8_STORE:
            insn.Op1.type = o_imm
            insn.Op1.dtype = dt_byte
            insn.Op1.value = insn.get_next_byte()
        elif insn.itype == OP_STATIC_U8:
            insn.Op1.type = o_imm
            insn.Op1.dtype = dt_byte
            insn.Op1.value = insn.get_next_byte()
        elif insn.itype == OP_STATIC_U8_LOAD:
            insn.Op1.type = o_imm
            insn.Op1.dtype = dt_byte
            insn.Op1.value = insn.get_next_byte()
        elif insn.itype == OP_STATIC_U8_STORE:
            insn.Op1.type = o_imm
            insn.Op1.dtype = dt_byte
            insn.Op1.value = insn.get_next_byte()
        elif insn.itype == OP_IADD_U8:
            insn.Op1.type = o_imm
            insn.Op1.dtype = dt_byte
            insn.Op1.value = insn.get_next_byte()
        elif insn.itype == OP_IMUL_U8:
            insn.Op1.type = o_imm
            insn.Op1.dtype = dt_byte
            insn.Op1.value = insn.get_next_byte()
        elif insn.itype == OP_IOFFSET_U8:
            insn.Op1.type = o_imm
            insn.Op1.dtype = dt_byte
            insn.Op1.value = insn.get_next_byte()
        elif insn.itype == OP_IOFFSET_U8_LOAD:
            insn.Op1.type = o_imm
            insn.Op1.dtype = dt_byte
            insn.Op1.value = insn.get_next_byte()
        elif insn.itype == OP_IOFFSET_U8_STORE:
            insn.Op1.type = o_imm
            insn.Op1.dtype = dt_byte
            insn.Op1.value = insn.get_next_byte()
        elif insn.itype == OP_PUSH_CONST_S16:
            insn.Op1.type = o_imm
            insn.Op1.dtype = dt_word
            insn.Op1.value = insn.get_next_word()
        elif insn.itype == OP_IADD_S16:
            insn.Op1.type = o_imm
            insn.Op1.dtype = dt_word
            insn.Op1.value = insn.get_next_word()
        elif insn.itype == OP_IMUL_S16:
            insn.Op1.type = o_imm
            insn.Op1.dtype = dt_word
            insn.Op1.value = insn.get_next_word()
        elif insn.itype == OP_IOFFSET_S16:
            insn.Op1.type = o_imm
            insn.Op1.dtype = dt_word
            insn.Op1.value = insn.get_next_word()
        elif insn.itype == OP_IOFFSET_S16_LOAD:
            insn.Op1.type = o_imm
            insn.Op1.dtype = dt_word
            insn.Op1.value = insn.get_next_word()
        elif insn.itype == OP_IOFFSET_S16_STORE:
            insn.Op1.type = o_imm
            insn.Op1.dtype = dt_word
            insn.Op1.value = insn.get_next_word()
        elif insn.itype == OP_ARRAY_U16:
            insn.Op1.type = o_imm
            insn.Op1.dtype = dt_word
            insn.Op1.value = insn.get_next_word()
        elif insn.itype == OP_ARRAY_U16_LOAD:
            insn.Op1.type = o_imm
            insn.Op1.dtype = dt_word
            insn.Op1.value = insn.get_next_word()
        elif insn.itype == OP_ARRAY_U16_STORE:
            insn.Op1.type = o_imm
            insn.Op1.dtype = dt_word
            insn.Op1.value = insn.get_next_word()
        elif insn.itype == OP_LOCAL_U16:
            insn.Op1.type = o_imm
            insn.Op1.dtype = dt_word
            insn.Op1.value = insn.get_next_word()
        elif insn.itype == OP_LOCAL_U16_LOAD:
            insn.Op1.type = o_imm
            insn.Op1.dtype = dt_word
            insn.Op1.value = insn.get_next_word()
        elif insn.itype == OP_LOCAL_U16_STORE:
            insn.Op1.type = o_imm
            insn.Op1.dtype = dt_word
            insn.Op1.value = insn.get_next_word()
        elif insn.itype == OP_STATIC_U16:
            insn.Op1.type = o_imm
            insn.Op1.dtype = dt_word
            insn.Op1.value = insn.get_next_word()
        elif insn.itype == OP_STATIC_U16_LOAD:
            insn.Op1.type = o_imm
            insn.Op1.dtype = dt_word
            insn.Op1.value = insn.get_next_word()
        elif insn.itype == OP_STATIC_U16_STORE:
            insn.Op1.type = o_imm
            insn.Op1.dtype = dt_word
            insn.Op1.value = insn.get_next_word()
        elif insn.itype == OP_GLOBAL_U16:
            insn.Op1.type = o_imm
            insn.Op1.dtype = dt_word
            insn.Op1.value = insn.get_next_word()
        elif insn.itype == OP_GLOBAL_U16_LOAD:
            insn.Op1.type = o_imm
            insn.Op1.dtype = dt_word
            insn.Op1.value = insn.get_next_word()
        elif insn.itype == OP_GLOBAL_U16_STORE:
            insn.Op1.type = o_imm
            insn.Op1.dtype = dt_word
            insn.Op1.value = insn.get_next_word()
        elif insn.itype == OP_J:
            insn.Op1.type = o_displ
            insn.Op1.dtype = dt_word
            insn.Op1.value = insn.get_next_word()
        elif insn.itype == OP_JZ:
            insn.Op1.type = o_displ
            insn.Op1.dtype = dt_word
            insn.Op1.value = insn.get_next_word()
        elif insn.itype == OP_IEQ_JZ:
            insn.Op1.type = o_displ
            insn.Op1.dtype = dt_word
            insn.Op1.value = insn.get_next_word()
        elif insn.itype == OP_INE_JZ:
            insn.Op1.type = o_displ
            insn.Op1.dtype = dt_word
            insn.Op1.value = insn.get_next_word()
        elif insn.itype == OP_IGT_JZ:
            insn.Op1.type = o_displ
            insn.Op1.dtype = dt_word
            insn.Op1.value = insn.get_next_word()
        elif insn.itype == OP_IGE_JZ:
            insn.Op1.type = o_displ
            insn.Op1.dtype = dt_word
            insn.Op1.value = insn.get_next_word()
        elif insn.itype == OP_ILT_JZ:
            insn.Op1.type = o_displ
            insn.Op1.dtype = dt_word
            insn.Op1.value = insn.get_next_word()
        elif insn.itype == OP_ILE_JZ:
            insn.Op1.type = o_displ
            insn.Op1.dtype = dt_word
            insn.Op1.value = insn.get_next_word()
        elif insn.itype == OP_CALL:
            insn.Op1.type = o_mem
            insn.Op1.dtype = dt_dword
            insn.Op1.addr = (insn.get_next_dword()) & 0xFFFFFF
            insn.Op1.offb = 1
            insn.size = 4
        elif insn.itype == OP_STATIC_U24:
            insn.Op1.type = o_imm
            insn.Op1.dtype = dt_dword
            insn.Op1.value = (insn.get_next_dword()) & 0xFFFFFF
            insn.size = 4
        elif insn.itype == OP_STATIC_U24_LOAD:
            # 
            insn.Op1.type = o_imm
            insn.Op1.dtype = dt_dword
            insn.Op1.value = (insn.get_next_dword()) & 0xFFFFFF
            insn.size = 4
        elif insn.itype == OP_STATIC_U24_STORE:
            insn.Op1.type = o_imm
            insn.Op1.dtype = dt_dword
            insn.Op1.value = (insn.get_next_dword()) & 0xFFFFFF
            insn.size = 4
        elif insn.itype == OP_GLOBAL_U24:
            insn.Op1.type = o_imm
            insn.Op1.dtype = dt_dword
            insn.Op1.value = (insn.get_next_dword()) & 0xFFFFFF
            insn.Op1.offb = 1
            insn.size = 4
        elif insn.itype == OP_GLOBAL_U24_LOAD:
            insn.Op1.type = o_imm
            insn.Op1.dtype = dt_dword
            insn.Op1.value = (insn.get_next_dword()) & 0xFFFFFF
            insn.Op1.offb = 1
            insn.size = 4
        elif insn.itype == OP_GLOBAL_U24_STORE:
            insn.Op1.type = o_imm
            insn.Op1.dtype = dt_dword
            insn.Op1.value = (insn.get_next_dword()) & 0xFFFFFF
            insn.Op1.offb = 1
            insn.size = 4
        elif insn.itype == OP_PUSH_CONST_U24:
            insn.Op1.type = o_imm
            insn.Op1.dtype = dt_dword
            insn.Op1.value = (insn.get_next_dword()) & 0xFFFFFF
            insn.size = 4
        elif insn.itype == OP_SWITCH:
            insn.Op1.type = o_imm
            insn.Op1.dtype = dt_byte
            insn.Op1.value = insn.get_next_byte()
            insn.size = 2 + insn.Op1.value * 6
        elif insn.itype == OP_TEXT_LABEL_ASSIGN_STRING:
            insn.Op1.type = o_imm
            insn.Op1.dtype = dt_byte
            insn.Op1.value = insn.get_next_byte()
        elif insn.itype == OP_TEXT_LABEL_ASSIGN_INT:
            insn.Op1.type = o_imm
            insn.Op1.dtype = dt_byte
            insn.Op1.value = insn.get_next_byte()
        elif insn.itype == OP_TEXT_LABEL_APPEND_STRING:
            insn.Op1.type = o_imm
            insn.Op1.dtype = dt_byte
            insn.Op1.value = insn.get_next_byte()
        elif insn.itype == OP_TEXT_LABEL_APPEND_INT:
            insn.Op1.type = o_imm
            insn.Op1.dtype = dt_byte
            insn.Op1.value = insn.get_next_byte()
        elif insn.itype == OP_STRING:
            prev = insn_t()
            decode_prev_insn(prev, insn.ea)
            if prev.Op1.type == o_imm:
                insn.Op1.type = o_mem
                insn.Op1.dtype = dt_qword
                for s in idautils.Segments():
                    if idc.get_segm_name(s) == "STRINGS":
                        string_segment = idc.get_segm_start(s)
                
                insn.Op1.addr = string_segment + prev.Op1.value
                idc.SetType(insn.Op1.addr, "char[]") # so all strings are recognized
        elif insn.itype == OP_PUSH_CONST_M1:
            insn.Op1.type = o_imm
            insn.Op1.dtype = dt_dword
            insn.Op1.value = -1
        elif insn.itype == OP_PUSH_CONST_0:
            insn.Op1.type = o_imm
            insn.Op1.dtype = dt_dword
            insn.Op1.value = 0
        elif insn.itype == OP_PUSH_CONST_1:
            insn.Op1.type = o_imm
            insn.Op1.dtype = dt_dword
            insn.Op1.value = 1
        elif insn.itype == OP_PUSH_CONST_2:
            insn.Op1.type = o_imm
            insn.Op1.dtype = dt_dword
            insn.Op1.value = 2
        elif insn.itype == OP_PUSH_CONST_3:
            insn.Op1.type = o_imm
            insn.Op1.dtype = dt_dword
            insn.Op1.value = 3
        elif insn.itype == OP_PUSH_CONST_4:
            insn.Op1.type = o_imm
            insn.Op1.dtype = dt_dword
            insn.Op1.value = 4
        elif insn.itype == OP_PUSH_CONST_5:
            insn.Op1.type = o_imm
            insn.Op1.dtype = dt_dword
            insn.Op1.value = 5
        elif insn.itype == OP_PUSH_CONST_6:
            insn.Op1.type = o_imm
            insn.Op1.dtype = dt_dword
            insn.Op1.value = 6
        elif insn.itype == OP_PUSH_CONST_7:
            insn.Op1.type = o_imm
            insn.Op1.dtype = dt_dword
            insn.Op1.value = 7
        elif insn.itype == OP_PUSH_CONST_FM1:
            insn.Op1.type = o_imm
            insn.Op1.dtype = dt_float
            insn.Op1.value = 0xbf800000
        elif insn.itype == OP_PUSH_CONST_F0:
            insn.Op1.type = o_imm
            insn.Op1.dtype = dt_float
            insn.Op1.value = 0x00000000
        elif insn.itype == OP_PUSH_CONST_F1:
            insn.Op1.type = o_imm
            insn.Op1.dtype = dt_float
            insn.Op1.value = 0x3f800000
        elif insn.itype == OP_PUSH_CONST_F2:
            insn.Op1.type = o_imm
            insn.Op1.dtype = dt_float
            insn.Op1.value = 0x40000000
        elif insn.itype == OP_PUSH_CONST_F3:
            insn.Op1.type = o_imm
            insn.Op1.dtype = dt_float
            insn.Op1.value = 0x40400000
        elif insn.itype == OP_PUSH_CONST_F4:
            insn.Op1.type = o_imm
            insn.Op1.dtype = dt_float
            insn.Op1.value = 0x40800000
        elif insn.itype == OP_PUSH_CONST_F5:
            insn.Op1.type = o_imm
            insn.Op1.dtype = dt_float
            insn.Op1.value = 0x40a00000
        elif insn.itype == OP_PUSH_CONST_F6:
            insn.Op1.type = o_imm
            insn.Op1.dtype = dt_float
            insn.Op1.value = 0x40c00000
        elif insn.itype == OP_PUSH_CONST_F7:
            insn.Op1.type = o_imm
            insn.Op1.dtype = dt_float
            insn.Op1.value = 0x40e00000
        return insn.size

    def ev_emu_insn(self, insn):
        flow = insn.itype != OP_LEAVE and insn.itype != OP_J
        if insn.itype >= OP_J and insn.itype <= OP_ILE_JZ: # all jmp opcodes
            add_cref(insn.ea, insn.ea + insn.size + ctypes.c_short(insn.Op1.value).value, dr_O)
        elif insn.itype == OP_CALL: # call
            add_cref(insn.ea, insn.Op1.addr, fl_CF)
        elif insn.itype == OP_NATIVE:
            add_dref(insn.ea, insn.Op2.addr, dr_R)
        elif insn.itype == OP_STRING:
            add_dref(insn.ea, insn.Op1.addr, dr_R)
        if flow: # ret
            add_cref(insn.ea, insn.ea + insn.size, fl_F)

        return True

    # The following callbacks are optional.
    # *** Please remove the callbacks that you don't plan to implement ***

    def ev_is_switch(self, swi, insn):
        """
        Find 'switch' idiom at instruction 'insn'.
        Fills 'swi' structure with information
        """
        if insn.itype != OP_SWITCH:
            return 0
        swi.flags = SWI_CUSTOM
        swi.startea = insn.ea
        return 1

    def ev_create_switch_xrefs(self, jumpea, swi):
        """Create xrefs for a custom jump table
           @param jumpea: address of the jump insn
           @param swi: switch information
        """
        switch_instr = jumpea
        jumpea += 1
        branches = ida_bytes.get_byte(jumpea)
        jumpea += 1
        for _ in range(0, branches):
            match = ida_bytes.get_dword(jumpea)
            jumpea += 4
            target = ida_bytes.get_word(jumpea)
            jumpea += 2
            add_cref(switch_instr, jumpea + target, fl_JF)
            idc.set_cmt(jumpea + target, "jumptable 0x{:x} case {}".format(switch_instr, match), 1)
        return 1
# ----------------------------------------------------------------------
# Every processor module script must provide this function.
# It should return a new instance of a class derived from idaapi.processor_t
def PROCESSOR_ENTRY():
    return ysc_t()
