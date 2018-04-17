#include <precompiled.hh>

#include "analysis.hh"

#include "data.hh"
#include "functions.hh"

void analysis::analyse(PeAccessor *pe, CapstoneHelper *h) {
    // Setup some state

    auto image = pe->base();

    // Code analysis, follows code path, enumerates possible data references
    {
        auto text_section = pe->find_section(".text");

        auto ep_address = image->get_ep();

        auto code_root = new XrefCodeDestination(ep_address);

        analysis::code::analyse(image, text_section->get_raw_data(), h, image->get_ep(), text_section->get_virtual_address(), code_root);
    }

    // Data analysis, finds relocations and assigns them to their data references
    {
        analysis::data::analyse(image, h);
    }
}
