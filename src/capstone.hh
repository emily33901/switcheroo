#pragma once
#include <cassert>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <memory>

#include <capstone.h>
#include <pe_bliss.h>

#include "types.hh"

using namespace pe_bliss;

class PeAccessor {
    pe_base *     image;
    std::fstream *image_data;

public:
    PeAccessor(const char *file_name) {
        image_data = new std::fstream(file_name, std::ios::in | std::ios::binary);
        assert(!!*image_data);

        image = new pe_base(*image_data, pe_properties_32(), false);
        assert(image);
    }

    ~PeAccessor() {
        delete image;
        delete image_data;
    }

    pe_base *base() {
        return image;
    }

    section *find_section(const char *name) {
        for (auto &sec : image->get_image_sections())
            if (sec.get_name() == name)
                return &sec;

        return nullptr;
    }
};

// TODO: if we add multithreading then implement that here
class CapstoneInstruction {
    cs_insn *inst;

public:
    // Refer to cs_insn for more info
    u32        id;
    u64        address;
    u16        size;
    u8         bytes[16];
    char       mnemonic[32];
    char       op_str[160];
    cs_detail *detail;

    CapstoneInstruction(csh handle, u8 *inst_base, u32 code_size, u64 address) {
        cs_disasm(handle, inst_base, code_size, address, 1, &inst);

        id            = inst->id;
        this->address = inst->address;
        size          = inst->size;

        memcpy(bytes, inst->bytes, sizeof(bytes));
        memcpy(mnemonic, inst->mnemonic, sizeof(mnemonic));
        memcpy(op_str, inst->op_str, sizeof(op_str));

        detail = inst->detail;
    }

    ~CapstoneInstruction() {
        cs_free(inst, 1);
    }
};

class CapstoneHelper {
    csh      handle;
    pe_base *image;

public:
    CapstoneHelper(cs_arch arch, cs_mode mode, pe_base *image) {
        auto err = cs_open(arch, mode, &handle);
        assert(err == CS_ERR_OK);

        cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);

        this->image = image;
    }

    CapstoneInstruction disas(u8 *inst_base, u32 code_size, u32 inst_file_address) {
        return CapstoneInstruction(handle, inst_base, code_size, image->file_offset_to_rva(inst_file_address));
    }
};
