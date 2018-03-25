#include "precompiled.hh"

#include <ciso646>

#include "functions.hh"

using namespace pe_bliss;

class CallSite;

int main(const int arg_count, const char **arg_strings) {
	if (arg_count > 1) {
		const char *file_name = arg_strings[1];
		assert(file_name);

		PeAccessor p{ file_name };
		auto image = p.base().lock();

		auto s = p.find_section(".text");
		auto data = s->get_raw_data();

		CapstoneHelper h{ cs_arch::CS_ARCH_X86, cs_mode::CS_MODE_32, image };

		root_block = std::make_shared<JumpBlock>(JumpBlock(0));

		recurse_functions(image, data, h, image->get_ep(), s->get_virtual_address(), root_block);

		printf("%d Blocks\n", blocks.size());

		std::cout << blocks.size() << " Blocks" << std::endl;

		system("pause");
	}
	return 0;
}



