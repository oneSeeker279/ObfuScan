
#include "disasm_arm64.h"

#include <capstone/capstone.h>

#include <string>

struct Arm64DisasmEngine::Impl {
    csh handle = 0;
    bool inited = false;
};

Arm64DisasmEngine::Arm64DisasmEngine() : impl_(new Impl()) {}

Arm64DisasmEngine::~Arm64DisasmEngine() {
    close();
    delete impl_;
    impl_ = nullptr;
}

bool Arm64DisasmEngine::init() {
    if (impl_->inited) return true;

    cs_err err = cs_open(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN, &impl_->handle);
    if (err != CS_ERR_OK) {
        return false;
    }

    cs_option(impl_->handle, CS_OPT_DETAIL, CS_OPT_ON);
    impl_->inited = true;
    return true;
}

void Arm64DisasmEngine::close() {
    if (impl_ && impl_->inited) {
        cs_close(&impl_->handle);
        impl_->inited = false;
        impl_->handle = 0;
    }
}

static bool starts_with(const std::string& s, const char* prefix) {
    return s.rfind(prefix, 0) == 0;
}

A64StatsEx Arm64DisasmEngine::analyze_text(const uint8_t* data, size_t size, uint64_t base_addr) {
    A64StatsEx s{};
    if (!impl_ || !impl_->inited || !data || size == 0) return s;

    cs_insn* insn = nullptr;
    size_t count = cs_disasm(impl_->handle, data, size, base_addr, 0, &insn);
    if (count == 0) return s;

    s.total_insn = count;

    for (size_t i = 0; i < count; ++i) {
        const cs_insn& ci = insn[i];
        std::string m = ci.mnemonic ? ci.mnemonic : "";

        bool is_jump = cs_insn_group(impl_->handle, &ci, CS_GRP_JUMP);
        bool is_call = cs_insn_group(impl_->handle, &ci, CS_GRP_CALL);
        bool is_ret  = cs_insn_group(impl_->handle, &ci, CS_GRP_RET);

        if (is_jump) s.jump++;
        if (is_call) s.call++;
        if (is_ret)  s.ret++;

        if (m == "b.eq" || m == "b.ne" || m == "b.lt" || m == "b.le" ||
            m == "b.gt" || m == "b.ge" || m == "b.cs" || m == "b.cc" ||
            m == "b.mi" || m == "b.pl" || m == "b.vs" || m == "b.vc" ||
            m == "cbz" || m == "cbnz" || m == "tbz" || m == "tbnz") {
            s.cond_jump++;
        }

        if (m == "br" || m == "blr") {
            s.indirect_jump++;
        }

        if (starts_with(m, "ldr") || m == "ldp" || m == "ldur" || m == "ldxr" || m == "ldaxr") {
            s.load++;
        }

        if (starts_with(m, "str") || m == "stp" || m == "stur" || m == "stxr" || m == "stlxr") {
            s.store++;
        }

        if (m == "add" || m == "sub" || m == "subs" || m == "adc" || m == "sbc" ||
            m == "mul" || m == "madd" || m == "msub" || m == "udiv" || m == "sdiv" ||
            m == "neg" || m == "cmp" || m == "cmn") {
            s.arithmetic++;
        }

        if (m == "and" || m == "ands" || m == "orr" || m == "eor" ||
            m == "bic" || m == "orn" || m == "eon" || m == "tst") {
            s.logical++;
        }

        if (m == "cmp" || m == "cmn" || m == "tst") {
            s.compare++;
        }
    }

    cs_free(insn, count);
    return s;
}

std::vector<DisasmLine> Arm64DisasmEngine::disasm_preview(const uint8_t* data,
                                                          size_t size,
                                                          uint64_t base_addr,
                                                          size_t max_insn) {
    std::vector<DisasmLine> out;
    if (!impl_ || !impl_->inited || !data || size == 0) return out;

    cs_insn* insn = nullptr;
    size_t count = cs_disasm(impl_->handle, data, size, base_addr, 0, &insn);
    if (count == 0) return out;

    size_t n = (count < max_insn) ? count : max_insn;
    out.reserve(n);

    for (size_t i = 0; i < n; ++i) {
        DisasmLine line;
        line.address = insn[i].address;
        line.mnemonic = insn[i].mnemonic ? insn[i].mnemonic : "";
        line.op_str = insn[i].op_str ? insn[i].op_str : "";
        out.push_back(std::move(line));
    }

    cs_free(insn, count);
    return out;
}

std::vector<DisasmInsn> Arm64DisasmEngine::disasm_all(const uint8_t* data,
                                                      size_t size,
                                                      uint64_t base_addr,
                                                      size_t max_insn) {
    std::vector<DisasmInsn> out;
    if (!impl_ || !impl_->inited || !data || size == 0) return out;

    cs_insn* insn = nullptr;
    size_t count = cs_disasm(impl_->handle, data, size, base_addr, 0, &insn);
    if (count == 0) return out;

    size_t n = count;
    if (max_insn > 0) n = std::min(count, max_insn);

    out.reserve(n);
    for (size_t i = 0; i < n; ++i) {
        DisasmInsn di;
        di.address = insn[i].address;
        di.mnemonic = insn[i].mnemonic ? insn[i].mnemonic : "";
        di.op_str = insn[i].op_str ? insn[i].op_str : "";
        di.is_jump = cs_insn_group(impl_->handle, &insn[i], CS_GRP_JUMP);
        di.is_call = cs_insn_group(impl_->handle, &insn[i], CS_GRP_CALL);
        di.is_ret  = cs_insn_group(impl_->handle, &insn[i], CS_GRP_RET);
        out.push_back(std::move(di));
    }

    cs_free(insn, count);
    return out;
}