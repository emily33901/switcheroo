#include <precompiled.hh>

#include "data.hh"

#include "xref.hh"

void analysis::data::analyse(pe_base *image, CapstoneHelper *h) {

    auto relocations = get_relocations(*image);

    std::vector<u32> reloc_addresses;
    for (const auto &block : relocations) {
        auto block_rva = block.get_rva();

        for (const auto &reloc : block.get_relocations()) {
            auto addr = block_rva + reloc.get_rva();

            reloc_addresses.push_back(addr);
        }
    }

    printf("%d relocations\nFinding...\n", reloc_addresses.size());

    std::vector<u32> not_found;
    not_found.reserve(reloc_addresses.size());

    for (auto addr : reloc_addresses) {
        auto found = false;
        for (auto l : XrefLocation::get_locations()) {
            if (addr == l->address) {
                auto code_loc              = (XrefCodeLocation *)l;
                code_loc->needs_relocation = true;

                found = true;
                break;
            }
        }

        if (!found) not_found.push_back(addr);
    }

    printf("%d relocs not found - adding new locations !\n", not_found.size());

    for (auto addr : not_found) {
        auto  section = image->section_and_offset_from_rva(addr);
        auto &data    = section.second->get_raw_data();

        auto dest_addr = *(u32 *)&data[section.first];

        auto d = XrefDestination::find(dest_addr);

        if (d == nullptr) {
            d = new XrefDestination(dest_addr);
        }

        auto new_location              = new XrefLocation(addr, d);
        new_location->needs_relocation = true;
    }
}
