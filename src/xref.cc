#include "precompiled.hh"

#include "xref.hh"

#include <typeinfo>

std::vector<XrefLocation *> XrefLocation::locations;

XrefLocation::XrefLocation(u32 address, XrefDestination *dest) : address(address), destination(dest) {
    locations.push_back(this);
    dest->location.push_back(this);
}

XrefCodeLocation::XrefCodeLocation(u32 address, XrefDestination *dest) : XrefLocation(address, dest) {
    type = XrefLocationType::code;

    needs_relocation = false;
}

XrefDataLocation::XrefDataLocation(u32 address, XrefDestination *dest) : XrefLocation(address, dest) {
    type = XrefLocationType::data;
}

std::vector<XrefDestination *> XrefDestination::destinations;

XrefDestination::XrefDestination(u32 address) : address(address) {
    destinations.push_back(this);
}

XrefDestination *XrefDestination::find(u32 address) {

    auto it = std::find_if(destinations.begin(), destinations.end(), [address](const XrefDestination *x) { return x->address == address; });

    if (it != destinations.end()) return *it;

    return nullptr;
}

XrefCodeDestination::XrefCodeDestination(u32 address) : XrefDestination(address) {
    type = XrefDestinationType::code;
}

XrefDataDestination::XrefDataDestination(u32 address) : XrefDestination(address) {
    type = XrefDestinationType::data;
}
