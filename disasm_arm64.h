
#pragma once

#include <cstdint>
#include <cstddef>
#include <string>
#include <vector>

struct DisasmInsn {
    uint64_t address = 0;
    std::string mnemonic;
    std::string op_str;
    bool is_jump = false;
    bool is_call = false;
    bool is_ret = false;
};

struct A64StatsEx {
    uint64_t total_insn = 0;
    uint64_t jump = 0;
    uint64_t cond_jump = 0;
    uint64_t indirect_jump = 0;
    uint64_t call = 0;
    uint64_t ret = 0;
    uint64_t load = 0;
    uint64_t store = 0;
    uint64_t arithmetic = 0;
    uint64_t logical = 0;
    uint64_t compare = 0;

    double branch_ratio() const {
        if (!total_insn) return 0.0;
        return double(jump + call + ret) / double(total_insn);
    }

    double indirect_branch_ratio() const {
        if (!total_insn) return 0.0;
        return double(indirect_jump) / double(total_insn);
    }

    double obf_arith_ratio() const {
        if (!total_insn) return 0.0;
        return double(arithmetic + logical + compare) / double(total_insn);
    }
};

struct DisasmLine {
    uint64_t address = 0;
    std::string mnemonic;
    std::string op_str;
};

class Arm64DisasmEngine {
public:
    Arm64DisasmEngine();
    ~Arm64DisasmEngine();

    bool init();
    void close();

    A64StatsEx analyze_text(const uint8_t* data, size_t size, uint64_t base_addr = 0);

    std::vector<DisasmLine> disasm_preview(const uint8_t* data,
                                           size_t size,
                                           uint64_t base_addr = 0,
                                           size_t max_insn = 32);
    std::vector<DisasmInsn> disasm_all(const uint8_t* data,
                                       size_t size,
                                       uint64_t base_addr = 0,
                                       size_t max_insn = 0);
private:
    struct Impl;
    Impl* impl_;
};