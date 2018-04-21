#pragma once
#include <memory>
#include <vector>

#include "types.hh"

// All structures related to data xrefs (code / data)

enum class XrefLocationType {
    data,
    code,
    unknown,
};

enum class XrefDestinationType {
    data,
    code,
    unknown,
};

class XrefDestination;

// Represents the location where the xref exists
// These are NOT from the start of the instruction that contains them
// But at the point where they are referenced as an operand
// TODO: does the want a backwards link aswell?
class XrefLocation {
    static std::vector<XrefLocation *> locations;

public:
    static std::vector<XrefLocation *> &get_locations() { return locations; }

    XrefLocation(u32 address, XrefDestination *dest);

    XrefLocationType type;
    u32              address;
    XrefDestination *destination;

    bool needs_relocation;

    static XrefLocation *find(u32 address);
};

class XrefCodeLocation : public XrefLocation {

public:
    XrefCodeLocation(u32 address, XrefDestination *dest);
};

class XrefDataLocation : public XrefLocation {

public:
    XrefDataLocation(u32 address, XrefDestination *dest);
};

// Represents where the xref points to
class XrefDestination {
    static std::vector<XrefDestination *> destinations;

public:
    static std::vector<XrefDestination *> &get_destinations() { return destinations; }
    XrefDestination(u32 address);

    XrefDestinationType type;
    u32                 address;

    // Destinations can have multiple locations referencing
    std::vector<XrefLocation *> location;

    // find the destination at this address
    static XrefDestination *find(u32 address);

    auto operator==(const XrefDestination &other) { return this->address == other.address; }
};

class XrefCodeDestination : public XrefDestination {

public:
    XrefCodeDestination(u32 address);

    std::vector<XrefLocation *> children;
};

class XrefDataDestination : public XrefDestination {

public:
    XrefDataDestination(u32 address);
};
