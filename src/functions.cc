#include <precompiled.hh>

#include "functions.hh"

#include <algorithm>
#include <stack>

namespace analysis {

auto find_opcode_size(u8 opcode[4]) {
    if (opcode[1] == 0) return 1;
    if (opcode[2] == 0) return 2;
    if (opcode[3] == 0) return 3;

    return 4;
}

struct Block {
    XrefCodeDestination *dest;
    u32                  address;
    u32                  offset;
};

using BlockStack = std::stack<Block, std::vector<Block>>;

// Pass this around to internal analysis functions
struct State {
    pe_base *       image;
    std::string *   data;
    CapstoneHelper *h;
    BlockStack *    bs;
};

namespace code {
bool try_analyse_function_call(State *s, CapstoneInstruction &inst, u32 address) {
    auto &current_block = s->bs->top();
    auto &current_dest  = current_block.dest;

    auto instruction_address = inst.address;
    auto opcode_size         = find_opcode_size(inst.detail->x86.opcode);

    u32 instruction_offset = opcode_size;

    for (u8 i = 0; i < inst.detail->groups_count; i++) {
        auto g = inst.detail->groups[i];

        if (g == CS_GRP_JUMP || g == CS_GRP_CALL) {
            auto op_count = inst.detail->x86.op_count;

            if (op_count > 1) printf("Opcount is greater than 1 for jump/call??\n");

            u32 jump_to = 0;

            for (auto i = 0; i < op_count; i++) {
                auto operand = inst.detail->x86.operands[i];

                switch (operand.type) {
                case X86_OP_REG:
                    break;
                case X86_OP_IMM: {
                    jump_to = s->image->rva_to_file_offset(operand.imm);
                    //jump_to = operand.imm;
                    break;
                }

                    // TODO: this could do with some more analysis
                case X86_OP_MEM:
                    if (g == CS_GRP_JUMP) {
                        s->bs->pop();
                        return true;
                    }
                    break;

                case X86_OP_FP:
                case X86_OP_INVALID:
                default:
                    continue;
                }
            }

            if (jump_to != 0) {

                if (auto found_dest = XrefDestination::find(jump_to)) {
                    auto new_location = new XrefCodeLocation(instruction_address + opcode_size, found_dest);
                    current_dest->children.push_back(new_location);
                } else {
                    // First make the new block
                    auto new_dest = new XrefCodeDestination(jump_to);

                    auto new_location = new XrefCodeLocation(instruction_address + opcode_size, new_dest);
                    current_dest->children.push_back(new_location);

                    //recurse_functions(image, data, h, jump_to, text_section_rva, new_dest);
                    s->bs->push(Block{new_dest, jump_to, 0});
                }

                return true;
            }
        } else if (g == CS_GRP_IRET || g == CS_GRP_RET) {
            s->bs->pop();
            return true;
        }
    }

    return false;
}
} // namespace code

void code::analyse(pe_base *            image,
                   std::string &        data,
                   CapstoneHelper *     h,
                   u32                  ep,
                   u32                  text_section_rva,
                   XrefCodeDestination *root_code_dest) {
    // TODO: this should be stack allocated up to a point
    std::stack<Block, std::vector<Block>> block_stack;

    block_stack.push(Block{root_code_dest, ep, 0});

    State s;
    s.bs    = &block_stack;
    s.data  = &data;
    s.image = image;
    s.h     = h;

    while (block_stack.size() > 0) {
        auto &current_block = block_stack.top();

        auto &current_dest = current_block.dest;
        auto &address      = current_block.address;
        auto &offset       = current_block.offset;

        auto data_index = address - text_section_rva;

        auto data_ptr = &data[data_index + offset];

        auto inst = h->disas((u8 *)data_ptr, 32, address + offset);

#if 0
        printf("%08X ", address + offset);

        for (int i = 0; i < inst.size; i++) {
            u8  b8  = data[data_index + offset + i];
            u32 b32 = (u32)b8;
            printf("%2X ", b32);
        }

        printf("%s %s\n", inst.mnemonic, inst.op_str);
#endif

        auto instruction_address = address + offset;
        offset += inst.size;

        if (try_analyse_function_call(&s, inst, instruction_address)) {
            printf("+");
            continue;
        }

        auto opcode_size        = find_opcode_size(inst.detail->x86.opcode);
        auto instruction_offset = opcode_size;

        // Check operands for immediate mode or memory arguments
        for (u8 i = 0; i < inst.detail->x86.op_count; i++) {
            auto operand = inst.detail->x86.operands[i];

            if (operand.type == X86_OP_MEM) {
                // We only want to look at absolute addressses
                // TODO: some sort of extra analysis here to see if we can get
                // the value of the register would be nice...
                // (This would allow us to analyse things like global initialisers properly
                //  which start at an address and increment a register according to what function
                //  they are currently on
                if (operand.mem.base != X86_REG_INVALID) continue;

                auto dest_address = operand.mem.disp;

#if 0
                for (int i = 0; i < inst.size; i++) {
                    u8  b8  = data[data_index + offset + i];
                    u32 b32 = (u32)b8;
                    printf("%2X ", b32);
                }

                printf("%s %s\n", inst.mnemonic, inst.op_str);
#endif

                if (auto found_dest = XrefDestination::find(dest_address)) {
                    auto new_location = new XrefCodeLocation(instruction_address + opcode_size, found_dest);
                    current_dest->children.push_back(new_location);
                } else {
                    auto new_dest = new XrefDataDestination(dest_address);

                    auto new_location = new XrefCodeLocation(instruction_address + opcode_size, new_dest);
                    current_dest->children.push_back(new_location);
                }

                printf("-");

                continue;
            }
        }
    }
}
} // namespace analysis
