#include "precompiled.hh"

#include <thread>

#include "analysis.hh"

#include "xref.hh"

using namespace pe_bliss;

int main(const int arg_count, const char **arg_strings) {
    if (arg_count > 1) {
        const char *file_name = arg_strings[1];
        assert(file_name);

        PeAccessor p{file_name};
        auto       image = p.base();

        auto base = image->get_image_base_32();

        // Help us out when we are trying to analyse
        auto relocations = get_relocations(*image);
        if (base != 0) {
            rebase_image(*image, relocations, 0x0);
        }

        CapstoneHelper h{cs_arch::CS_ARCH_X86, cs_mode::CS_MODE_32, image};

        analysis::analyse(&p, &h);

        printf("\n%d Locations, %d Destinations\n", XrefLocation::get_locations().size(), XrefDestination::get_destinations().size());

        u32 total_locations_relocations = 0;
        for (auto loc : XrefLocation::get_locations()) {
            if (loc->needs_relocation) total_locations_relocations += 1;
        }

        printf("%d need relocations\n", total_locations_relocations);

        printf("Dumping...\n");

        FILE *f;

        if (f = fopen("dump.txt", "w")) {
            fprintf(f, "Locations:\n");

            for (auto &l : XrefLocation::get_locations()) {
                auto relocation = l->needs_relocation;

                fprintf(f, "0x%08X (%d %s) -> 0x%08X (%d)\n", l->address, l->type, relocation ? "true" : "false", l->destination->address, l->destination->type);
            }

            fprintf(f, "\nDestinations:\n");

            for (auto &d : XrefDestination::get_destinations()) {
                fprintf(f, "0x%08X (%d) <- {\n", d->address, d->type);

                for (auto &l : d->location) {
                    fprintf(f, "\t0x%08X (%d %s)\n", l->address, l->type, l->needs_relocation ? "true" : "false");
                }

                fprintf(f, "}\n");
            }

            fprintf(f, "\nRelocs:\n");

            std::vector<u32> reloc_addresses;

            auto relocations = get_relocations(*image);

            for (const auto &block : relocations) {
                auto block_rva = block.get_rva();

                for (const auto &reloc : block.get_relocations()) {
                    reloc_addresses.push_back(block_rva + reloc.get_rva());
                }
            }

            for (auto a : reloc_addresses) {
                fprintf(f, "0x%X\n", a);
            }

            fclose(f);
        }

        printf("Done.\n");

        std::this_thread::sleep_for(std::chrono::seconds(2));
    }
    return 0;
}
