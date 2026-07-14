#include "nids/version.hpp"

#include <string_view>

static_assert(__cplusplus >= 202002L, "nids-core requires C++20");

int main() {
    return nids::version() == std::string_view{"0.1.0"} ? 0 : 1;
}
