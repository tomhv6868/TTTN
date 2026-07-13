#include <onnxruntime_cxx_api.h>
#include <rte_version.h>

#include <iostream>
#include <string_view>

#ifndef NIDS_EXPECTED_DPDK_VERSION
#error "NIDS_EXPECTED_DPDK_VERSION is required"
#endif

#ifndef NIDS_EXPECTED_ORT_VERSION
#error "NIDS_EXPECTED_ORT_VERSION is required"
#endif

int main() {
    const std::string_view dpdk_version{rte_version()};
    const char* const ort_version = OrtGetApiBase()->GetVersionString();
    if (ort_version == nullptr) {
        std::cerr << "ONNX Runtime returned a null version string\n";
        return 1;
    }

    const std::string_view ort_version_view{ort_version};
    if (dpdk_version.find(NIDS_EXPECTED_DPDK_VERSION) == std::string_view::npos) {
        std::cerr << "Unexpected DPDK version: " << dpdk_version << '\n';
        return 2;
    }
    if (ort_version_view != NIDS_EXPECTED_ORT_VERSION) {
        std::cerr << "Unexpected ONNX Runtime version: " << ort_version_view << '\n';
        return 3;
    }

    Ort::Env environment{ORT_LOGGING_LEVEL_WARNING, "nids-t0.2-smoke"};
    std::cout << "DPDK " << NIDS_EXPECTED_DPDK_VERSION << '\n';
    std::cout << "ONNX Runtime " << ort_version_view << '\n';
    std::cout << "C++ standard " << __cplusplus << '\n';
    return 0;
}
