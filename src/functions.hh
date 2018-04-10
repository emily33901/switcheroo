#pragma once
#include <algorithm>
#include <vector>

#include "capstone.hh"

#include "xref.hh"

void recurse_functions(std::shared_ptr<pe_base> image,
                       std::string &            data,
                       CapstoneHelper &         h,
                       u32                      address,
                       u32                      text_section_rva,
                       XrefCodeDestination *    current_block) {
    auto offset = 0;

    while (true) {
        auto data_index = address - text_section_rva;

        auto inst = h.disas((u8 *)&data[data_index + offset], 32, address + offset);

#if 0
        for (int i = 0; i < inst.size; i++) {
            u8  b8  = data[data_index + offset + i];
            u32 b32 = (u32)b8;
            printf("%2X \n", b32);
        }

        printf("%s %s\n", inst.mnemonic, inst.op_str);
#endif
        auto instruction_address = address + offset;
        offset += inst.size;

        for (u8 i = 0; i < inst.detail->groups_count; i++) {
            auto g = inst.detail->groups[i];

            if (g == CS_GRP_JUMP or g == CS_GRP_CALL) {
                auto op_count = inst.detail->x86.op_count;

                u32 jump_to = 0;

                for (auto i = 0; i < op_count; i++) {
                    auto operand = inst.detail->x86.operands[i];

                    switch (operand.type) {
                    case X86_OP_REG:
                        break;
                    case X86_OP_IMM: {
                        jump_to = image->rva_to_file_offset(operand.imm);
                        break;
                    }

                    case X86_OP_MEM:
                        if (g == CS_GRP_JUMP) {
                            return;
                        }
                        break;

                    case X86_OP_FP:
                    case X86_OP_INVALID:
                    default:
                        break;
                    }
                }

                if (jump_to != 0) {

                    if (auto found_dest = XrefDestination::find(jump_to)) {
                        auto new_location = new XrefCodeLocation(instruction_address, found_dest);
                        current_block->children.push_back(new_location);
                    } else {
                        // First make the new block
                        auto new_dest = new XrefCodeDestination(jump_to);

                        auto new_location = new XrefCodeLocation(instruction_address, new_dest);
                        current_block->children.push_back(new_location);

                        printf("+");

                        recurse_functions(image, data, h, jump_to, text_section_rva, new_dest);

                        continue;
                    }
                }
            } else if (g == CS_GRP_IRET or g == CS_GRP_RET) {
                return;
            }
        }

        // Check operands for immediate mode or memory arguments
        for (u8 i = 0; i < inst.detail->x86.op_count; i++) {
            auto operand = inst.detail->x86.operands[i];

            if (operand.type == X86_OP_MEM) {
                // We only want to look at absolute addressses
                // TODO: some sort of extra analysis here to see if we can get
                // the value of the register would be nice...
                if (operand.mem.base != X86_REG_INVALID) continue;

                auto dest_address = operand.mem.disp;

                //for (int i = 0; i < inst.size; i++) {
                //    u8  b8  = data[data_index + offset + i];
                //    u32 b32 = (u32)b8;
                //    printf("%2X ", b32);
                //}

                //printf("%s %s\n", inst.mnemonic, inst.op_str);

                if (auto found_dest = XrefDestination::find(dest_address)) {
                    auto new_location = new XrefCodeLocation(instruction_address, found_dest);
                    current_block->children.push_back(new_location);
                } else {
                    auto new_dest = new XrefDataDestination(dest_address);

                    auto new_location = new XrefCodeLocation(instruction_address, new_dest);
                    current_block->children.push_back(new_location);
                }

                printf("-");

                continue;
            }
        }
    }
}
