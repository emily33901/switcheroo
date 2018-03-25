#pragma once
#include <algorithm>
#include <vector>

#include "capstone.hh"

class CallSite;

class JumpBlock {
public:
	u32 location_address;

	std::vector<std::shared_ptr<CallSite>> children;
	std::vector<std::shared_ptr<CallSite>> parents;

	JumpBlock(u32 location) {
		this->location_address = location;
	}
};

std::shared_ptr<JumpBlock> root_block;
std::vector<std::shared_ptr<JumpBlock>> blocks;

class CallSite {
public:
	u32 address;

	std::shared_ptr<JumpBlock> jump_block;
	std::shared_ptr<JumpBlock> parent;

	CallSite(u32 addr, std::shared_ptr<JumpBlock> &block, std::shared_ptr<JumpBlock> &par) {
		address = addr;
		jump_block = block;
		parent = par;
	}
};

std::weak_ptr<JumpBlock> has_visited_address_recursive(std::shared_ptr<JumpBlock> this_block, u32 address, std::vector<std::shared_ptr<JumpBlock>> &visited) {
	auto block_it = std::find_if(blocks.begin(), blocks.end(), [address](std::shared_ptr<JumpBlock> &x) {return x->location_address == address; });
	if (block_it != blocks.end()) {
		return *block_it;
	}

	return {};
}

std::weak_ptr<JumpBlock> has_visited_address(u32 address) {
	std::vector<std::shared_ptr<JumpBlock>> visited;
	return has_visited_address_recursive(root_block, address, visited);
}

void recurse_functions(std::shared_ptr<pe_base> image,
	std::string &data,
	CapstoneHelper &h,
	u32 address,
	u32 text_section_rva,
	std::shared_ptr<JumpBlock> current_block) {
	auto offset = 0;

	while (true) {
		auto data_index = address - text_section_rva;

		auto inst = h.disas((u8 *)&data[data_index + offset], 32, address + offset);

		/*
		std::cout << print_offset;
		for (int i = 0; i < inst.size; i++) {
			u8 b8 = data[data_index + offset + i];
			u32 b32 = (u32)b8;
			printf("%2X \n", b32);
		}

		printf("%s %s\n", inst.mnemonic, inst.op_str);
		*/

		for (int i = 0; i < inst.detail->groups_count; i++) {
			auto g = inst.detail->groups[i];

			if (g == CS_GRP_JUMP or g == CS_GRP_CALL) {
				auto op_count = inst.detail->x86.op_count;

				u32 jump_to = 0;

				for (auto i = 0; i < op_count; i++) {
					auto operand = inst.detail->x86.operands[i];


					switch (operand.type)
					{
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


					if (auto found_block = has_visited_address(jump_to).lock()) {
						auto new_callsite = current_block->children.emplace_back(std::make_shared<CallSite>(CallSite(address + offset, found_block, current_block)));

						found_block->parents.push_back(new_callsite);

					}
					else {
						// First make the new block
						auto new_block = std::make_shared<JumpBlock>(JumpBlock(jump_to));

						blocks.push_back(new_block);

						// Now make the callsite
						auto new_callsite = current_block->children.emplace_back(std::make_shared<CallSite>(CallSite(address + offset, new_block, current_block)));

						// Update relevent data for children and parents (this must be done here
						//  as we cant get the shared ptr to ourselves inside of these constructors...)
						new_block->parents.push_back(new_callsite);

						printf(".");

						recurse_functions(image, data, h, jump_to, text_section_rva, new_block);

					}
				}
			}
			else if (g == CS_GRP_IRET or g == CS_GRP_RET) {
				return;
			}
		}

		offset += inst.size;
	}
}
