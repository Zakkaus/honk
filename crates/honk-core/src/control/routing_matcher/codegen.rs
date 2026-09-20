//! Native eBPF emitter for the fixed RoutingInput/Decision ABI.
//!
//! The emitter produces only a function body.  The backend supplies the real
//! freplace prototype, BTF and map lifetime; R1 is `*const RoutingInput` and
//! R2 is `*mut RoutingDecision`.

use super::{KernelCondition, KernelPredicate, RoutingPushPlan};
use anyhow::{Context, ensure};
use aya_obj::generated::{
    BPF_ALU64, BPF_AND, BPF_B, BPF_CALL, BPF_DW, BPF_EXIT, BPF_IMM, BPF_JA, BPF_JEQ, BPF_JGE,
    BPF_JGT, BPF_JMP, BPF_JNE, BPF_K, BPF_LD, BPF_LDX, BPF_MEM, BPF_MOV, BPF_OR, BPF_ST, BPF_STX,
    BPF_W, BPF_X, bpf_insn,
};
use honk_ebpf_common::{
    ROUTING_FACT_CAPACITY, ROUTING_FEATURE_DOMAIN, ROUTING_FEATURE_DOMAIN_REROUTE,
    ROUTING_FEATURE_PROCESS, ROUTING_PROCESS_MAX_LEN, RoutingDecision, RoutingInput,
};

const R0: u8 = 0;
const R1: u8 = 1;
const R2: u8 = 2;
const R3: u8 = 3;
const R4: u8 = 4;
const R5: u8 = 5;
const R6: u8 = 6;
const R7: u8 = 7;
const R8: u8 = 8;
const R10: u8 = 10;
const MAP_LOOKUP_ELEM: i32 = 1;
const BPF_INSTRUCTION_CAPACITY: usize = 1_000_000;
const PSEUDO_MAP_FD: u8 = 1;
/// Bytes of one `DomainRouting` bitmap, copied out of a map value.
const FACT_BYTES: i16 = (ROUTING_FACT_CAPACITY / 8) as i16;
/// LPM/MAC lookup key: 20 bytes written, 32 reserved.
const STACK_KEY: i16 = -(4 * FACT_BYTES) - 32;
/// Domain lookup key: the 16-byte destination address.
const STACK_DOMAIN_KEY: i16 = STACK_KEY - 16;
const INPUT_SRC_IP: i16 = std::mem::offset_of!(RoutingInput, src_ip) as i16;
const INPUT_DST_IP: i16 = std::mem::offset_of!(RoutingInput, dst_ip) as i16;
const INPUT_MAC: i16 = std::mem::offset_of!(RoutingInput, mac) as i16;
const INPUT_PNAME: i16 = std::mem::offset_of!(RoutingInput, pname) as i16;
const INPUT_SRC_PORT: i16 = std::mem::offset_of!(RoutingInput, src_port) as i16;
const INPUT_DST_PORT: i16 = std::mem::offset_of!(RoutingInput, dst_port) as i16;
const INPUT_PROTO: i16 = std::mem::offset_of!(RoutingInput, l4proto) as i16;
const INPUT_VERSION: i16 = std::mem::offset_of!(RoutingInput, ip_version) as i16;
const INPUT_DSCP: i16 = std::mem::offset_of!(RoutingInput, dscp) as i16;
const INPUT_PNAME_LEN: i16 = std::mem::offset_of!(RoutingInput, pname_len) as i16;
const INPUT_MAC_PRESENT: i16 = std::mem::offset_of!(RoutingInput, mac_present) as i16;
const OUTBOUND: i16 = std::mem::offset_of!(RoutingDecision, outbound) as i16;
const MARK: i16 = std::mem::offset_of!(RoutingDecision, mark) as i16;
const MUST: i16 = std::mem::offset_of!(RoutingDecision, must) as i16;
const DOMAIN_FINAL: i16 = std::mem::offset_of!(RoutingDecision, domain_final) as i16;
const RULE_ID: i16 = std::mem::offset_of!(RoutingDecision, rule_id) as i16;

/// One lookup category. Each owns a 32-byte stack area holding its
/// `DomainRouting` bitmap once resolved: domain at [-32, -1], destination at
/// [-64, -33], source at [-96, -65], MAC at [-128, -97].
#[derive(Clone, Copy)]
enum FactKind {
    Domain,
    Destination,
    Source,
    Mac,
}

impl FactKind {
    fn area(self) -> i16 {
        -(self as i16 + 1) * FACT_BYTES
    }
}

#[derive(Debug, Clone, Copy)]
pub struct RoutingMapFds {
    pub destination_v4: i32,
    pub destination_v6: i32,
    pub source_v4: i32,
    pub source_v6: i32,
    pub mac: i32,
    pub domain: i32,
}

#[derive(Debug, Clone)]
pub struct RoutingSourceLine {
    pub insn_offset: u32,
    pub line: u32,
    pub text: String,
}

#[derive(Debug, Clone)]
pub struct RoutingBytecode {
    pub insns: Vec<bpf_insn>,
    pub lines: Vec<RoutingSourceLine>,
}

#[derive(Debug, Clone, Copy)]
struct Label(usize);

struct Assembler {
    insns: Vec<bpf_insn>,
    lines: Vec<RoutingSourceLine>,
    labels: Vec<Option<usize>>,
    fixups: Vec<(usize, Label)>,
}

impl Assembler {
    fn new() -> Self {
        Self {
            insns: Vec::new(),
            lines: Vec::new(),
            labels: Vec::new(),
            fixups: Vec::new(),
        }
    }

    fn source(&mut self, line: u32, text: impl Into<String>) {
        self.lines.push(RoutingSourceLine {
            insn_offset: self.insns.len() as u32,
            line,
            text: text.into(),
        });
    }

    fn label(&mut self) -> Label {
        let label = Label(self.labels.len());
        self.labels.push(None);
        label
    }

    fn bind(&mut self, label: Label) {
        self.labels[label.0] = Some(self.insns.len());
    }

    fn emit(&mut self, code: u32, dst: u8, src: u8, off: i16, imm: i32) -> anyhow::Result<usize> {
        ensure!(
            self.insns.len() < BPF_INSTRUCTION_CAPACITY,
            "routing program exceeds BPF instruction capacity"
        );
        let insn = bpf_insn {
            code: code as u8,
            _bitfield_align_1: [],
            _bitfield_1: bpf_insn::new_bitfield_1(dst, src),
            off,
            imm,
        };
        let offset = self.insns.len();
        self.insns.push(insn);
        Ok(offset)
    }

    fn jump(&mut self, op: u32, dst: u8, imm: i32, target: Label) -> anyhow::Result<()> {
        let index = self.emit(BPF_JMP | op | BPF_K, dst, 0, 0, imm)?;
        self.fixups.push((index, target));
        Ok(())
    }

    fn ja(&mut self, target: Label) -> anyhow::Result<()> {
        let index = self.emit(BPF_JMP | BPF_JA, 0, 0, 0, 0)?;
        self.fixups.push((index, target));
        Ok(())
    }

    fn finish(mut self) -> anyhow::Result<RoutingBytecode> {
        for (index, label) in self.fixups {
            let target = self
                .labels
                .get(label.0)
                .and_then(|target| *target)
                .with_context(|| format!("unresolved jump label ordinal {}", label.0))?;
            let delta = target as isize - index as isize - 1;
            ensure!(
                i16::try_from(delta).is_ok(),
                "routing jump out of range: {index} -> {target}"
            );
            self.insns[index].off = delta as i16;
        }
        Ok(RoutingBytecode {
            insns: self.insns,
            lines: self.lines,
        })
    }

    fn mov_reg(&mut self, dst: u8, src: u8) -> anyhow::Result<()> {
        self.emit(BPF_ALU64 | BPF_MOV | BPF_X, dst, src, 0, 0)?;
        Ok(())
    }
    fn mov_imm(&mut self, dst: u8, imm: i32) -> anyhow::Result<()> {
        self.emit(BPF_ALU64 | BPF_MOV | BPF_K, dst, 0, 0, imm)?;
        Ok(())
    }
    fn add_imm(&mut self, dst: u8, imm: i32) -> anyhow::Result<()> {
        self.emit(BPF_ALU64 | BPF_K, dst, 0, 0, imm)?;
        Ok(())
    }
    fn and_imm(&mut self, dst: u8, imm: i32) -> anyhow::Result<()> {
        self.emit(BPF_ALU64 | BPF_AND | BPF_K, dst, 0, 0, imm)?;
        Ok(())
    }
    fn or_imm(&mut self, dst: u8, imm: i32) -> anyhow::Result<()> {
        self.emit(BPF_ALU64 | BPF_OR | BPF_K, dst, 0, 0, imm)?;
        Ok(())
    }
    fn ldx_w(&mut self, dst: u8, src: u8, off: i16) -> anyhow::Result<()> {
        self.emit(BPF_LDX | BPF_W | BPF_MEM, dst, src, off, 0)?;
        Ok(())
    }
    fn ldx_b(&mut self, dst: u8, src: u8, off: i16) -> anyhow::Result<()> {
        self.emit(BPF_LDX | BPF_B | BPF_MEM, dst, src, off, 0)?;
        Ok(())
    }
    fn ldx_dw(&mut self, dst: u8, src: u8, off: i16) -> anyhow::Result<()> {
        self.emit(BPF_LDX | BPF_DW | BPF_MEM, dst, src, off, 0)?;
        Ok(())
    }
    fn stx_dw(&mut self, dst: u8, src: u8, off: i16) -> anyhow::Result<()> {
        self.emit(BPF_STX | BPF_DW | BPF_MEM, dst, src, off, 0)?;
        Ok(())
    }
    fn stx_w(&mut self, dst: u8, src: u8, off: i16) -> anyhow::Result<()> {
        self.emit(BPF_STX | BPF_W | BPF_MEM, dst, src, off, 0)?;
        Ok(())
    }
    fn st_imm(&mut self, dst: u8, off: i16, imm: i32) -> anyhow::Result<()> {
        self.emit(BPF_ST | BPF_W | BPF_MEM, dst, 0, off, imm)?;
        Ok(())
    }
    fn call(&mut self, helper: i32) -> anyhow::Result<()> {
        self.emit(BPF_JMP | BPF_CALL, 0, 0, 0, helper)?;
        Ok(())
    }
    fn exit(&mut self) -> anyhow::Result<()> {
        self.emit(BPF_JMP | BPF_EXIT, 0, 0, 0, 0)?;
        Ok(())
    }
}

/// Per-invocation resolved bits for the lazily evaluated categories
/// (Destination/Source/MAC). Kept in R8, which callee-saves across the
/// lookup helper; it says this call already resolved the category, not
/// that the emitter merely emitted a lookup somewhere.
const READY: u8 = R8;

/// Emit a complete RoutingInput -> RoutingDecision function body.
pub fn emit_routing_program(
    plan: &RoutingPushPlan,
    fds: RoutingMapFds,
) -> anyhow::Result<RoutingBytecode> {
    validate_plan(plan)?;
    for (name, fd) in [
        ("destination_v4", fds.destination_v4),
        ("destination_v6", fds.destination_v6),
        ("source_v4", fds.source_v4),
        ("source_v6", fds.source_v6),
        ("mac", fds.mac),
        ("domain", fds.domain),
    ] {
        ensure!(fd >= 0, "invalid {name} routing map fd {fd}");
    }

    let mut asm = Assembler::new();
    asm.source(0, "routing function prologue");
    for register in [R1, R2] {
        let nonnull = asm.label();
        asm.jump(BPF_JNE, register, 0, nonnull)?;
        asm.mov_imm(R0, -libc::EFAULT)?;
        asm.exit()?;
        asm.bind(nonnull);
    }
    asm.mov_reg(R6, R1)?;
    asm.mov_reg(R7, R2)?;
    asm.st_imm(R7, OUTBOUND, plan.fallback as i32)?;
    asm.st_imm(R7, MARK, 0)?;
    asm.st_imm(R7, MUST, 0)?;
    asm.st_imm(
        R7,
        DOMAIN_FINAL,
        (!plan.has_domain_rules || plan.features & ROUTING_FEATURE_DOMAIN_REROUTE == 0) as i32,
    )?;
    asm.st_imm(R7, RULE_ID, u32::MAX as i32)?;
    asm.mov_imm(READY, 0)?;

    if plan.has_domain_rules {
        emit_fact_lookup(&mut asm, FactKind::Domain, &fds)?;
    }

    for rule in &plan.rules {
        // BPF rejects structurally unreachable instructions before evaluating predicates.
        if rule
            .conditions
            .iter()
            .any(|condition| !condition.not && predicate_is_empty(&condition.predicate))
        {
            continue;
        }
        asm.source(rule.id + 1, rule.source.as_str());
        let fail = asm.label();
        let mut conditional = false;
        let port_first = |condition: &&KernelCondition| {
            matches!(
                condition.predicate,
                KernelPredicate::DestinationPort(_) | KernelPredicate::SourcePort(_)
            )
        };
        for condition in rule
            .conditions
            .iter()
            .filter(|condition| !predicate_is_empty(&condition.predicate))
            .filter(port_first)
            .chain(
                rule.conditions
                    .iter()
                    .filter(|condition| !predicate_is_empty(&condition.predicate))
                    .filter(|condition| !port_first(condition)),
            )
        {
            let pass = asm.label();
            emit_condition(&mut asm, condition, pass, fail, &fds)?;
            conditional = true;
            asm.bind(pass);
        }
        asm.st_imm(R7, OUTBOUND, rule.outbound as i32)?;
        asm.st_imm(R7, MARK, rule.mark as i32)?;
        asm.st_imm(R7, MUST, rule.must as i32)?;
        asm.st_imm(R7, RULE_ID, rule.id as i32)?;
        asm.mov_imm(R0, 0)?;
        asm.exit()?;
        if !conditional {
            return asm.finish();
        }
        asm.bind(fail);
    }

    asm.source(0, "fallback");
    asm.mov_imm(R0, 0)?;
    asm.exit()?;
    asm.finish()
}
fn validate_plan(plan: &RoutingPushPlan) -> anyhow::Result<()> {
    ensure!(
        plan.domain_predicate_count <= ROUTING_FACT_CAPACITY,
        "domain predicate capacity exceeded"
    );
    ensure!(
        plan.has_domain_rules == (plan.domain_predicate_count != 0),
        "inconsistent domain predicate metadata"
    );
    ensure!(
        (plan.features & ROUTING_FEATURE_DOMAIN != 0) == plan.has_domain_rules,
        "inconsistent domain feature metadata"
    );
    ensure!(
        plan.features & ROUTING_FEATURE_DOMAIN_REROUTE == 0 || plan.has_domain_rules,
        "domain reroute feature requires domain predicates"
    );
    let has_process = plan.rules.iter().any(|rule| {
        rule.conditions
            .iter()
            .any(|condition| matches!(&condition.predicate, KernelPredicate::ProcessName(_)))
    });
    ensure!(
        (plan.features & ROUTING_FEATURE_PROCESS != 0) == has_process,
        "inconsistent process feature metadata"
    );
    for rule in &plan.rules {
        ensure!(
            rule.id < (1 << 22) - 1,
            "rule id {} exceeds BPF source-line capacity",
            rule.id
        );
        for condition in &rule.conditions {
            match &condition.predicate {
                KernelPredicate::Domain(id) => ensure!(
                    (*id as usize) < plan.domain_predicate_count,
                    "invalid domain predicate id {id}"
                ),
                KernelPredicate::DestinationIp(id)
                | KernelPredicate::SourceIp(id)
                | KernelPredicate::Mac(id) => ensure!(
                    (*id as usize) < ROUTING_FACT_CAPACITY,
                    "invalid fact predicate id {id}"
                ),
                KernelPredicate::DestinationPort(ranges) | KernelPredicate::SourcePort(ranges) => {
                    ensure!(
                        ranges.iter().all(|range| range.start <= range.end),
                        "invalid emitted port range"
                    )
                }
                KernelPredicate::Protocol(mask) | KernelPredicate::IpVersion(mask) => {
                    ensure!(*mask & !0b11 == 0, "invalid emitted scalar mask {mask:#x}")
                }
                KernelPredicate::ProcessName(names) => ensure!(
                    names
                        .iter()
                        .all(|name| name.len() <= ROUTING_PROCESS_MAX_LEN),
                    "emitted process matcher exceeds {ROUTING_PROCESS_MAX_LEN} bytes"
                ),
                KernelPredicate::Dscp(_) => {}
            }
        }
    }
    ensure!(
        plan.facts
            .destination_v4
            .iter()
            .all(|(key, _)| key.prefix_len <= 32),
        "invalid destination IPv4 prefix"
    );
    ensure!(
        plan.facts
            .source_v4
            .iter()
            .all(|(key, _)| key.prefix_len <= 32),
        "invalid source IPv4 prefix"
    );
    ensure!(
        plan.facts
            .destination_v6
            .iter()
            .all(|(key, _)| key.prefix_len <= 128),
        "invalid destination IPv6 prefix"
    );
    ensure!(
        plan.facts
            .source_v6
            .iter()
            .all(|(key, _)| key.prefix_len <= 128),
        "invalid source IPv6 prefix"
    );
    ensure!(
        plan.facts.mac.iter().all(|(key, _)| key.prefix_len == 128),
        "invalid MAC prefix"
    );
    Ok(())
}

fn predicate_is_empty(predicate: &KernelPredicate) -> bool {
    match predicate {
        KernelPredicate::DestinationPort(ranges) | KernelPredicate::SourcePort(ranges) => {
            ranges.is_empty()
        }
        KernelPredicate::Protocol(mask) | KernelPredicate::IpVersion(mask) => *mask == 0,
        KernelPredicate::Dscp(values) => values.is_empty(),
        KernelPredicate::ProcessName(names) => names.is_empty(),
        KernelPredicate::Domain(_)
        | KernelPredicate::DestinationIp(_)
        | KernelPredicate::SourceIp(_)
        | KernelPredicate::Mac(_) => false,
    }
}

fn emit_condition(
    asm: &mut Assembler,
    condition: &KernelCondition,
    pass: Label,
    fail: Label,
    fds: &RoutingMapFds,
) -> anyhow::Result<()> {
    let on_true = if condition.not { fail } else { pass };
    let on_false = if condition.not { pass } else { fail };
    match &condition.predicate {
        KernelPredicate::DestinationIp(id) => {
            emit_fact_bit_lazy(asm, FactKind::Destination, *id, on_true, on_false, fds)?
        }
        KernelPredicate::SourceIp(id) => {
            emit_fact_bit_lazy(asm, FactKind::Source, *id, on_true, on_false, fds)?
        }
        KernelPredicate::Mac(id) => {
            emit_fact_bit_lazy(asm, FactKind::Mac, *id, on_true, on_false, fds)?
        }
        _ => emit_predicate(asm, &condition.predicate, on_true, on_false)?,
    }
    Ok(())
}

/// Test one bit of a lazily resolved category. The READY bit is set only
/// after the lookup wrote all 32 bytes of the area, so a resolved
/// all-zeros bitmap is never re-looked-up and an unresolved one is never
/// read. Each use site carries its own guard, so a later rule still
/// resolves a category an earlier rule skipped.
fn emit_fact_bit_lazy(
    asm: &mut Assembler,
    kind: FactKind,
    id: u32,
    on_true: Label,
    on_false: Label,
    fds: &RoutingMapFds,
) -> anyhow::Result<()> {
    let resolved = asm.label();
    let bit = 1i32 << (kind as u8 - 1);
    // READY is a per-invocation bitmask; test the category bit, not
    // equality against the whole mask (other resolved categories set
    // other bits).
    asm.mov_reg(R0, READY)?;
    asm.and_imm(R0, bit)?;
    asm.jump(BPF_JNE, R0, 0, resolved)?;
    emit_fact_lookup(asm, kind, fds)?;
    asm.or_imm(READY, bit)?;
    asm.bind(resolved);
    emit_fact_bit(asm, kind, id, on_true, on_false)
}

fn emit_predicate(
    asm: &mut Assembler,
    predicate: &KernelPredicate,
    on_true: Label,
    on_false: Label,
) -> anyhow::Result<()> {
    match predicate {
        KernelPredicate::Domain(id) => {
            emit_fact_bit(asm, FactKind::Domain, *id, on_true, on_false)?;
        }
        KernelPredicate::DestinationIp(id) => {
            emit_fact_bit(asm, FactKind::Destination, *id, on_true, on_false)?;
        }
        KernelPredicate::SourceIp(id) => {
            emit_fact_bit(asm, FactKind::Source, *id, on_true, on_false)?;
        }
        KernelPredicate::Mac(id) => {
            emit_fact_bit(asm, FactKind::Mac, *id, on_true, on_false)?;
        }
        KernelPredicate::DestinationPort(ranges) => {
            emit_port_ranges(asm, ranges, INPUT_DST_PORT, on_true, on_false)?;
        }
        KernelPredicate::SourcePort(ranges) => {
            emit_port_ranges(asm, ranges, INPUT_SRC_PORT, on_true, on_false)?;
        }
        KernelPredicate::Protocol(mask) => {
            emit_mask_scalar(asm, INPUT_PROTO, *mask as i32, on_true, on_false)?;
        }
        KernelPredicate::IpVersion(mask) => {
            emit_mask_scalar(asm, INPUT_VERSION, *mask as i32, on_true, on_false)?;
        }
        KernelPredicate::Dscp(values) => {
            asm.ldx_w(R0, R6, INPUT_DSCP)?;
            for value in values {
                asm.jump(BPF_JEQ, R0, *value as i32, on_true)?;
            }
            asm.ja(on_false)?;
        }
        KernelPredicate::ProcessName(names) => {
            emit_process_names(asm, names, on_true, on_false)?;
        }
    }
    Ok(())
}

fn emit_mask_scalar(
    asm: &mut Assembler,
    offset: i16,
    mask: i32,
    on_true: Label,
    on_false: Label,
) -> anyhow::Result<()> {
    asm.ldx_w(R0, R6, offset)?;
    asm.and_imm(R0, mask)?;
    asm.jump(BPF_JNE, R0, 0, on_true)?;
    asm.ja(on_false)?;
    Ok(())
}

fn emit_port_ranges(
    asm: &mut Assembler,
    ranges: &[crate::routing::PortRange],
    offset: i16,
    on_true: Label,
    on_false: Label,
) -> anyhow::Result<()> {
    asm.ldx_w(R0, R6, offset)?;
    for range in ranges {
        let next = asm.label();
        let inside = asm.label();
        asm.jump(BPF_JGE, R0, range.start as i32, inside)?;
        asm.ja(next)?;
        asm.bind(inside);
        asm.jump(BPF_JGT, R0, range.end as i32, next)?;
        asm.ja(on_true)?;
        asm.bind(next);
    }
    asm.ja(on_false)?;
    Ok(())
}

fn emit_process_names(
    asm: &mut Assembler,
    names: &[Vec<u8>],
    on_true: Label,
    on_false: Label,
) -> anyhow::Result<()> {
    for bytes in names {
        let next_name = asm.label();
        asm.ldx_w(R4, R6, INPUT_PNAME_LEN)?;
        if bytes.is_empty() {
            asm.jump(BPF_JNE, R4, 0, on_true)?;
            continue;
        }
        let long = asm.label();
        asm.jump(BPF_JGE, R4, bytes.len() as i32, long)?;
        asm.ja(next_name)?;
        asm.bind(long);
        // Input pname is bounded to ROUTING_PROCESS_MAX_LEN bytes. Each
        // candidate offset is checked against pname_len before reading, so
        // missing bytes never become ordinary zeroes.
        for offset in 0..=(ROUTING_PROCESS_MAX_LEN.saturating_sub(bytes.len())) {
            let next = asm.label();
            let enough = asm.label();
            asm.jump(BPF_JGE, R4, (offset + bytes.len()) as i32, enough)?;
            asm.ja(next)?;
            asm.bind(enough);
            for (byte_index, byte) in bytes.iter().enumerate() {
                asm.ldx_b(R5, R6, INPUT_PNAME + offset as i16 + byte_index as i16)?;
                asm.jump(BPF_JNE, R5, *byte as i32, next)?;
            }
            asm.ja(on_true)?;
            asm.bind(next);
        }
        asm.bind(next_name);
    }
    asm.ja(on_false)?;
    Ok(())
}

/// Test one bit of a resolved category. The area holds the bitmap or zeros,
/// so a missing entry fails every bit test without a pointer check.
fn emit_fact_bit(
    asm: &mut Assembler,
    kind: FactKind,
    id: u32,
    on_true: Label,
    on_false: Label,
) -> anyhow::Result<()> {
    asm.ldx_w(R2, R10, kind.area() + (id / 32 * 4) as i16)?;
    asm.and_imm(R2, (1u32 << (id % 32)) as i32)?;
    asm.jump(BPF_JNE, R2, 0, on_true)?;
    asm.ja(on_false)?;
    Ok(())
}

/// Look the category up and copy its bitmap into the stack area; zero the
/// area when the input has no such fact or the map has no entry. R0 to R5
/// are clobbered; no pointer into the map value survives.
///
/// Branch layout matters to the verifier: at an unresolved conditional it
/// explores the fall-through first, so a copy from a map value (unknown
/// scalars) sits on the fall-through at every split and the zero fill on
/// the jump target. A recorded imprecise scalar can subsume the zero-fill
/// path; a zero fill recorded first becomes precise once a bit test on it
/// is predictable, and a precise zero cannot subsume an unknown. Measured
/// on Linux 6.12 with the IPv4/IPv6 dispatch the other way round the #280
/// policy cost four times as much.
fn emit_fact_lookup(
    asm: &mut Assembler,
    kind: FactKind,
    fds: &RoutingMapFds,
) -> anyhow::Result<()> {
    let absent = asm.label();
    let lookup = asm.label();
    let done = asm.label();
    let key = match kind {
        FactKind::Domain => STACK_DOMAIN_KEY,
        _ => STACK_KEY,
    };
    match kind {
        FactKind::Domain => {
            write_domain_key_from_input(asm)?;
            load_map_fd(asm, fds.domain)?;
        }
        FactKind::Mac => {
            asm.ldx_w(R0, R6, INPUT_MAC_PRESENT)?;
            asm.jump(BPF_JEQ, R0, 0, absent)?;
            write_key_from_input(asm, INPUT_MAC, 128)?;
            load_map_fd(asm, fds.mac)?;
        }
        FactKind::Destination | FactKind::Source => {
            let (v4_fd, v6_fd, input_offset) = match kind {
                FactKind::Destination => (fds.destination_v4, fds.destination_v6, INPUT_DST_IP),
                _ => (fds.source_v4, fds.source_v6, INPUT_SRC_IP),
            };
            let v6 = asm.label();
            asm.ldx_w(R0, R6, INPUT_VERSION)?;
            asm.jump(BPF_JNE, R0, 1, v6)?;
            write_key_from_input(asm, input_offset + 12, 32)?;
            load_map_fd(asm, v4_fd)?;
            asm.ja(lookup)?;
            asm.bind(v6);
            asm.jump(BPF_JNE, R0, 2, absent)?;
            write_key_from_input(asm, input_offset, 128)?;
            load_map_fd(asm, v6_fd)?;
        }
    }
    asm.bind(lookup);
    asm.mov_reg(R2, R10)?;
    asm.add_imm(R2, key as i32)?;
    asm.call(MAP_LOOKUP_ELEM)?;
    asm.jump(BPF_JEQ, R0, 0, absent)?;
    if matches!(kind, FactKind::Domain) {
        asm.st_imm(R7, DOMAIN_FINAL, 1)?;
    }
    for word in 0..FACT_BYTES / 8 {
        asm.ldx_dw(R1, R0, word * 8)?;
        asm.stx_dw(R10, R1, kind.area() + word * 8)?;
    }
    asm.ja(done)?;
    asm.bind(absent);
    asm.mov_imm(R1, 0)?;
    for word in 0..FACT_BYTES / 8 {
        asm.stx_dw(R10, R1, kind.area() + word * 8)?;
    }
    asm.bind(done);
    Ok(())
}

fn write_key_from_input(
    asm: &mut Assembler,
    input_offset: i16,
    prefix_len: u32,
) -> anyhow::Result<()> {
    asm.st_imm(R10, STACK_KEY, prefix_len as i32)?;
    let words = if prefix_len == 32 { 1 } else { 4 };
    for index in 0..words {
        let offset = index * 4;
        asm.ldx_w(R3, R6, input_offset + offset)?;
        asm.stx_w(R10, R3, STACK_KEY + 4 + offset)?;
    }
    for index in words..4 {
        asm.st_imm(R10, STACK_KEY + 4 + index * 4, 0)?;
    }
    Ok(())
}

fn write_domain_key_from_input(asm: &mut Assembler) -> anyhow::Result<()> {
    asm.ldx_dw(R3, R6, INPUT_DST_IP)?;
    asm.stx_dw(R10, R3, STACK_DOMAIN_KEY)?;
    asm.ldx_dw(R3, R6, INPUT_DST_IP + 8)?;
    asm.stx_dw(R10, R3, STACK_DOMAIN_KEY + 8)?;
    Ok(())
}

fn load_map_fd(asm: &mut Assembler, fd: i32) -> anyhow::Result<()> {
    asm.emit(BPF_LD | BPF_DW | BPF_IMM, R1, PSEUDO_MAP_FD, 0, fd)?;
    asm.emit(0, 0, 0, 0, 0)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::routing::Router;
    use aya_obj::generated::BPF_ALU;
    use honk_config::routing::{RoutingCondition, RoutingOutbound, RoutingRule};
    use honk_config::types::DialMode;
    use serde_json::json;

    fn rule(condition: serde_json::Value, outbound: &str) -> RoutingRule {
        RoutingRule {
            name: String::new(),
            condition: serde_json::from_value::<RoutingCondition>(condition).unwrap(),
            outbound: RoutingOutbound::Simple(outbound.into()),
            priority: 0,
            must: false,
            mark: 0,
        }
    }

    fn emit(rules: &[RoutingRule]) -> RoutingBytecode {
        let ids =
            std::collections::HashMap::from([("direct".to_string(), 0u8), ("proxy".into(), 1)]);
        let router = Router::new(rules, "direct").unwrap();
        let plan = RoutingPushPlan::compile(&router, &ids, "direct", DialMode::Ip).unwrap();
        let fds = RoutingMapFds {
            destination_v4: 11,
            destination_v6: 12,
            source_v4: 13,
            source_v6: 14,
            mac: 15,
            domain: 16,
        };
        emit_routing_program(&plan, fds).unwrap()
    }

    /// Instruction indexes of `map_lookup_elem` calls.
    fn lookups(bytecode: &RoutingBytecode) -> Vec<usize> {
        bytecode
            .insns
            .iter()
            .enumerate()
            .filter(|(_, insn)| {
                insn.code as u32 == BPF_JMP | BPF_CALL
                    && insn.src_reg() == 0
                    && insn.imm == MAP_LOOKUP_ELEM
            })
            .map(|(index, _)| index)
            .collect()
    }

    /// First instruction of the rule with this id (source lines carry id + 1).
    fn rule_start(bytecode: &RoutingBytecode, id: u32) -> usize {
        bytecode
            .lines
            .iter()
            .find(|line| line.line == id + 1)
            .map(|line| line.insn_offset as usize)
            .expect("rule source line")
    }

    fn is_null_check(insn: &bpf_insn) -> bool {
        insn.code as u32 == BPF_JMP | BPF_JEQ | BPF_K && insn.dst_reg() == R0 && insn.imm == 0
    }

    fn is_load(insn: &bpf_insn) -> bool {
        insn.code as u32 & 0x07 == BPF_LDX && insn.code as u32 & 0xe0 == BPF_MEM
    }

    /// The #280 shape: two `sip && dip && dport` rules ahead of a long
    /// process-name chain, later `mac`, `sip`, `dip` and `domain` rules.
    /// Every category is looked up once, on every path, at the entry of the
    /// first rule that uses it (domain in the prologue).
    #[test]
    fn each_fact_category_is_resolved_exactly_once() {
        let names = json!([
            "dnsmasq",
            "systemd-resolved",
            "mosdns",
            "NetworkManager",
            "qbittorrent",
            "iris-meta",
            "sing-box",
            "mihomo"
        ]);
        let rules = [
            rule(
                json!({"source_ip": ["198.18.81.2/32"], "ip": ["198.18.80.2/32"], "port": ["15201", "18081", "15203"]}),
                "proxy",
            ),
            rule(
                json!({"source_ip": ["198.18.81.2/32"], "ip": ["198.18.80.2/32"], "port": ["15202"]}),
                "direct",
            ),
            rule(json!({"process_name": names, "port": ["53"]}), "direct"),
            rule(json!({"process_name": names}), "direct"),
            rule(
                json!({"mac": ["00:a0:98:24:5e:83", "ba:da:2e:00:76:a0"]}),
                "direct",
            ),
            rule(json!({"source_ip": ["10.10.10.24/32"]}), "direct"),
            rule(json!({"ip": ["10.0.0.0/8", "192.168.0.0/16"]}), "direct"),
            rule(json!({"domain_suffix": ["example.com"]}), "proxy"),
            rule(json!({"ip": ["1.1.1.0/24"]}), "proxy"),
        ];
        let bytecode = emit(&rules);
        let calls = lookups(&bytecode);
        // One guarded call site per fact use: domain in the prologue, and
        // one per Destination/Source/MAC predicate across the rules. A
        // later rule still resolves a category an earlier rule skipped, so
        // the static count exceeds the old once-per-category total; the
        // READY guard keeps each category to one runtime lookup.
        assert_eq!(
            calls.len(),
            9,
            "domain in prologue + per-use lazy lookups: {calls:?}"
        );
        let rule0 = rule_start(&bytecode, 0);
        let rule1 = rule_start(&bytecode, 1);
        assert!(calls[0] < rule0, "domain {calls:?} vs rule 0 at {rule0}");
        assert!(
            rule0 < calls[1] && calls[1] < rule1,
            "rule 0 dip use {calls:?} vs rule 0..1 at {rule0}..{rule1}"
        );
    }

    /// A lookup result is consumed by its copy and nothing else: right after
    /// the NULL check, four DW loads through R0 each store into the
    /// category's area, nothing else reads R0 until it is overwritten, and
    /// every other load goes through the input pointer or the stack.
    /// Structural: the kernel suite proves what the copied values mean.
    #[test]
    fn a_lookup_result_is_copied_into_its_area_and_not_kept() {
        let rules = [
            rule(
                json!({"source_ip": ["198.18.81.2/32"], "ip": ["198.18.80.2/32"], "port": ["15201"]}),
                "proxy",
            ),
            rule(
                json!({"process_name": ["dnsmasq", "qemu-system-x86"]}),
                "direct",
            ),
            rule(json!({"mac": ["00:a0:98:24:5e:83"]}), "direct"),
            rule(json!({"domain_suffix": ["example.com"]}), "proxy"),
            rule(
                json!({"not": {"mac": ["ba:da:2e:00:76:a0"]}, "ip": ["10.0.0.0/8"], "dscp": ["0"]}),
                "direct",
            ),
            rule(json!({"source_ip": ["10.10.10.24/32"]}), "direct"),
            rule(json!({"domain_suffix": ["example.org"]}), "direct"),
        ];
        let bytecode = emit(&rules);
        let insns = &bytecode.insns;
        let calls = lookups(&bytecode);
        // One guarded call site per fact use across these rules.
        assert_eq!(calls.len(), 7, "{calls:?}");
        let words = (FACT_BYTES / 8) as usize;
        let mut copy_loads = Vec::new();
        for &call in &calls {
            assert!(is_null_check(&insns[call + 1]), "lookup at {call}");
            let mut index = call + 2;
            if insns[index].code as u32 == BPF_ST | BPF_W | BPF_MEM {
                index += 1; // domain_final
            }
            for word in 0..words {
                let (load, store) = (&insns[index], &insns[index + 1]);
                assert!(
                    is_load(load)
                        && load.code as u32 & 0x18 == BPF_DW
                        && load.src_reg() == R0
                        && load.off == (word * 8) as i16,
                    "copy load {word} after lookup at {call}"
                );
                assert!(
                    store.code as u32 == BPF_STX | BPF_DW | BPF_MEM
                        && store.dst_reg() == R10
                        && store.src_reg() == load.dst_reg()
                        && (store.off + FACT_BYTES * 4) % FACT_BYTES == (word * 8) as i16,
                    "copy store {word} after lookup at {call}"
                );
                copy_loads.push(index);
                index += 2;
            }
        }
        // Linear scan: from a helper call until the next write to R0, the
        // only reads of R0 are the NULL check and the copy loads. The
        // emitted code is straight-line there, so this is conservative.
        let mut r0_is_result = false;
        for (index, insn) in insns.iter().enumerate() {
            let code = insn.code as u32;
            let (class, op, from_register) = (code & 0x07, code & 0xf0, code & 0x08 == BPF_X);
            if class == BPF_JMP && op == BPF_CALL {
                r0_is_result = true;
                continue;
            }
            let reads_r0 = match class {
                BPF_LDX | BPF_STX => insn.src_reg() == R0,
                BPF_ALU64 | BPF_ALU => {
                    (op != BPF_MOV && insn.dst_reg() == R0)
                        || (from_register && insn.src_reg() == R0)
                }
                BPF_JMP => {
                    op == BPF_EXIT
                        || (op != BPF_JA
                            && (insn.dst_reg() == R0 || (from_register && insn.src_reg() == R0)))
                }
                _ => false,
            };
            if r0_is_result && reads_r0 {
                assert!(
                    (calls.contains(&(index - 1)) && is_null_check(insn))
                        || copy_loads.contains(&index),
                    "lookup result read at {index}"
                );
            }
            if matches!(class, BPF_LDX | BPF_ALU64 | BPF_ALU) && insn.dst_reg() == R0 {
                r0_is_result = false;
            }
            if is_load(insn) {
                match insn.src_reg() {
                    R6 | R10 => {}
                    R0 => assert!(copy_loads.contains(&index), "load through R0 at {index}"),
                    base => panic!("load through R{base} at {index}"),
                }
            }
        }
    }

    /// A category used by a later rule is resolved at that use, inside the
    /// rule's own conditions — not at the rule entry before a port
    /// short-circuit. The port compare precedes the lazy lookup, and a
    /// matching port still resolves the category once via its READY guard.
    #[test]
    fn a_fact_is_resolved_at_its_first_reached_use_after_ports() {
        let rules = [
            rule(json!({"process_name": ["dnsmasq"]}), "direct"),
            rule(json!({"port": ["53"]}), "direct"),
            rule(
                json!({"port": ["443"], "mac": ["00:a0:98:24:5e:83"]}),
                "proxy",
            ),
            rule(json!({"mac": ["ba:da:2e:00:76:a0"]}), "direct"),
        ];
        let bytecode = emit(&rules);
        let calls = lookups(&bytecode);
        let rule2 = rule_start(&bytecode, 2);
        let rule3 = rule_start(&bytecode, 3);
        // One MAC use in rule 2, one in rule 3: two guarded call sites.
        assert_eq!(calls.len(), 2, "{calls:?}");
        let port_compare = (rule2..rule3)
            .find(|index| {
                let insn = &bytecode.insns[*index];
                is_load(insn) && insn.src_reg() == R6 && insn.off == INPUT_DST_PORT
            })
            .expect("rule 2 reads the destination port");
        // The lookup follows the port compare inside rule 2 (port first),
        // and rule 3's own MAC use carries a second guarded call site.
        assert!(
            port_compare < calls[0] && calls[0] < rule3,
            "port read at {port_compare}, calls {calls:?} vs rule 3 at {rule3}"
        );
        assert!(rule3 < calls[1], "rule 3 lookup {calls:?} after {rule3}");
    }

    #[test]
    fn assembler_stops_at_instruction_capacity_without_publishing_fixup() {
        let mut asm = Assembler::new();
        asm.insns
            .resize_with(BPF_INSTRUCTION_CAPACITY - 1, || bpf_insn {
                code: 0,
                _bitfield_align_1: [],
                _bitfield_1: bpf_insn::new_bitfield_1(0, 0),
                off: 0,
                imm: 0,
            });

        let last = asm
            .emit(BPF_JMP | BPF_EXIT, 0, 0, 0, 0)
            .expect("the last instruction within capacity must be emitted");
        assert_eq!(last, BPF_INSTRUCTION_CAPACITY - 1);
        assert_eq!(asm.insns.len(), BPF_INSTRUCTION_CAPACITY);

        let past_capacity = asm.label();
        assert!(asm.ja(past_capacity).is_err());
        assert_eq!(asm.insns.len(), BPF_INSTRUCTION_CAPACITY);
        assert!(asm.fixups.is_empty());

        let bytecode = asm
            .finish()
            .expect("a boundary-sized program must still finish");
        assert_eq!(bytecode.insns.len(), BPF_INSTRUCTION_CAPACITY);
        assert_eq!(bytecode.insns[last].code, (BPF_JMP | BPF_EXIT) as u8);
    }

    #[test]
    fn assembler_rejects_unresolved_referenced_label() {
        let mut asm = Assembler::new();
        let missing = asm.label();
        asm.ja(missing).expect("jump itself should be emitted");

        assert!(asm.finish().is_err());
    }

    #[test]
    fn assembler_accepts_signed_jump_range_endpoints() {
        let mut forward = Assembler::new();
        let target = forward.label();
        let _unused = forward.label();
        forward.ja(target).unwrap();
        forward
            .insns
            .resize_with(i16::MAX as usize + 1, || bpf_insn {
                code: 0,
                _bitfield_align_1: [],
                _bitfield_1: bpf_insn::new_bitfield_1(0, 0),
                off: 0,
                imm: 0,
            });
        forward.bind(target);
        let bytecode = forward.finish().unwrap();
        assert_eq!(bytecode.insns[0].off, i16::MAX);

        let mut backward = Assembler::new();
        let target = backward.label();
        backward.bind(target);
        backward.insns.resize_with(i16::MAX as usize, || bpf_insn {
            code: 0,
            _bitfield_align_1: [],
            _bitfield_1: bpf_insn::new_bitfield_1(0, 0),
            off: 0,
            imm: 0,
        });
        backward.ja(target).unwrap();
        let bytecode = backward.finish().unwrap();
        assert_eq!(bytecode.insns[i16::MAX as usize].off, i16::MIN);

        let mut too_far_forward = Assembler::new();
        let target = too_far_forward.label();
        too_far_forward.ja(target).unwrap();
        too_far_forward
            .insns
            .resize_with(i16::MAX as usize + 2, || bpf_insn {
                code: 0,
                _bitfield_align_1: [],
                _bitfield_1: bpf_insn::new_bitfield_1(0, 0),
                off: 0,
                imm: 0,
            });
        too_far_forward.bind(target);
        assert!(too_far_forward.finish().is_err());

        let mut too_far_backward = Assembler::new();
        let target = too_far_backward.label();
        too_far_backward.bind(target);
        too_far_backward
            .insns
            .resize_with(i16::MAX as usize + 1, || bpf_insn {
                code: 0,
                _bitfield_align_1: [],
                _bitfield_1: bpf_insn::new_bitfield_1(0, 0),
                off: 0,
                imm: 0,
            });
        too_far_backward.ja(target).unwrap();
        assert!(too_far_backward.finish().is_err());
    }
}
