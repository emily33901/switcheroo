#include "precompiled.hh"

#include <ciso646>

#include "functions.hh"

using namespace pe_bliss;

int main(const int arg_count, const char **arg_strings) {
    if (arg_count > 1) {
        const char *file_name = arg_strings[1];
        assert(file_name);

        PeAccessor p{file_name};
        auto       image = p.base();

        auto base = image->get_image_base_32();

        // Help us out when we are trying to analyse
        if (base != 0) {
            rebase_image(*image, get_relocations(*image), 0x0);
        }

        CapstoneHelper h{cs_arch::CS_ARCH_X86, cs_mode::CS_MODE_32, image};

        auto s = p.find_section(".text");

        auto ep_address = image->get_ep();

        auto code_root = new XrefCodeDestination(ep_address);

        analysis::code::analyse(image, s->get_raw_data(), h, image->get_ep(), s->get_virtual_address(), code_root);

        printf("\n%d Locations, %d Destinations\n", XrefLocation::get_locations().size(), XrefDestination::get_destinations().size());

        printf("Dumping...\n");

        FILE *f;

        if (f = fopen("dump.txt", "w")) {
            fprintf(f, "Locations:\n");

            for (auto &l : XrefLocation::get_locations()) {
                fprintf(f, "0x%08X (%d) -> 0x%08X (%d)\n", l->address, l->type, l->destination->address, l->destination->type);
            }

            fprintf(f, "\nDestinations:\n");

            for (auto &d : XrefDestination::get_destinations()) {
                fprintf(f, "0x%08X (%d) <- {\n", d->address, d->type);

                for (auto &l : d->location) {
                    fprintf(f, "\t0x%08X (%d)\n", l->address, l->type);
                }

                fprintf(f, "}\n");
            }

            fclose(f);
        }

        system("pause");
    }
    return 0;
}
