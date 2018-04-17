#pragma once

#include "capstone.hh"

namespace analysis::data {
void analyse(pe_base *image, CapstoneHelper *h);
}
