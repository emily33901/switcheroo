#include <precompiled.hh>

#include "data.hh"

#include "xref.hh"

void analysis::data::analyse(pe_base *image, CapstoneHelper *h) {
    std::vector<u32> reloc_addresses;

    auto relocations = get_relocations(*image);

    for (const auto &block : relocations) {
        auto block_rva = block.get_rva();

        for (const auto &reloc : block.get_relocations()) {
            reloc_addresses.push_back(block_rva + reloc.get_rva());
        }
    }

    printf("\n%d total relocs\n", reloc_addresses.size());

    for (auto loc : XrefLocation::get_locations()) {
        if (loc->destination->type != XrefDestinationType::data) continue;

        auto data_loc = (XrefCodeLocation *)loc;

        for (auto addr : reloc_addresses) {
            if (data_loc->address == addr) {
                data_loc->needs_relocation = true;
            }
        }
    }
}
