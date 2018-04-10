#pragma once

#include "capstone.hh"

#include "xref.hh"

namespace analysis::code {
void analyse(pe_base *            image,
             std::string &        data,
             CapstoneHelper &     h,
             u32                  ep,
             u32                  text_section_rva,
             XrefCodeDestination *root_block);
} // namespace analysis::code
