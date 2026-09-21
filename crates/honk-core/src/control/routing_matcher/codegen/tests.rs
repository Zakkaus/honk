use super::*;
use crate::routing::Router;
use aya_obj::generated::BPF_ALU;
use honk_config::routing::{RoutingCondition, RoutingOutbound, RoutingRule};
use honk_config::types::DialMode;
use serde_json::json;

fn fields(insn: &bpf_insn) -> (u32, u8, u8, i16, i32) {
    (
        insn.code as u32,
        insn.dst_reg(),
        insn.src_reg(),
        insn.off,
        insn.imm,
    )
}

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
    let ids = std::collections::HashMap::from([("direct".to_string(), 0u8), ("proxy".into(), 1)]);
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
    assert_eq!(
        calls.len(),
        4,
        "domain, destination, source and MAC: {calls:?}"
    );
    let rule0 = rule_start(&bytecode, 0);
    let rule1 = rule_start(&bytecode, 1);
    let rule4 = rule_start(&bytecode, 4);
    let rule5 = rule_start(&bytecode, 5);
    assert!(calls[0] < rule0, "domain {calls:?} vs rule 0 at {rule0}");
    assert!(
        rule0 < calls[1] && calls[2] < rule1,
        "{calls:?} vs rule 0..1 at {rule0}..{rule1}"
    );
    assert!(
        rule4 < calls[3] && calls[3] < rule5,
        "MAC {calls:?} vs rule 4 at {rule4}..{rule5}"
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
    assert_eq!(calls.len(), 4, "{calls:?}");
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
                (op != BPF_MOV && insn.dst_reg() == R0) || (from_register && insn.src_reg() == R0)
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

/// A category first used by a later rule is resolved at that rule's
/// entry: after the previous rule's action (flows decided earlier skip
/// the lookup) and before the rule's own predicates, even one that
/// would short-circuit ahead of the fact. Conditions are emitted in
/// canonical order, port before MAC, so the port compare comes first
/// and a lookup at the first reached condition would follow it.
#[test]
fn a_fact_is_resolved_at_the_entry_of_its_first_use_rule() {
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
    assert_eq!(calls.len(), 1, "{calls:?}");
    let port_compare = (rule2..rule3)
        .find(|index| {
            let insn = &bytecode.insns[*index];
            is_load(insn) && insn.src_reg() == R6 && insn.off == INPUT_DST_PORT
        })
        .expect("rule 2 reads the destination port");
    assert!(
        rule2 < calls[0] && calls[0] < port_compare,
        "{calls:?} vs rule 2 at {rule2}, port read at {port_compare}"
    );
}

// The verifier explores fall-through first, so it must copy unknown map scalars
// before visiting the absent path's zeros.
#[test]
fn fact_lookup_copies_or_zeros_its_stack_area_before_rejoining() {
    let fds = RoutingMapFds {
        destination_v4: 11,
        destination_v6: 12,
        source_v4: 13,
        source_v6: 14,
        mac: 15,
        domain: 16,
    };
    for (kind, area) in [
        (FactKind::Domain, -32),
        (FactKind::Destination, -64),
        (FactKind::Source, -96),
        (FactKind::Mac, -128),
    ] {
        let mut asm = Assembler::new();
        emit_fact_lookup(&mut asm, kind, &fds).unwrap();
        let bytecode = asm.finish().unwrap();
        let insns = &bytecode.insns;
        let calls = lookups(&bytecode);
        assert_eq!(calls.len(), 1);
        let call = calls[0];
        let mut copy = call + 2;
        if matches!(kind, FactKind::Domain) {
            assert_eq!(
                fields(&insns[copy]),
                (BPF_ST | BPF_W | BPF_MEM, R7, 0, DOMAIN_FINAL, 1)
            );
            copy += 1;
        }
        let absent = copy + 9;
        assert_eq!(
            fields(&insns[call + 1]),
            (
                BPF_JMP | BPF_JEQ | BPF_K,
                R0,
                0,
                (absent - call - 2) as i16,
                0
            )
        );
        for (word, offset) in [0, 8, 16, 24].into_iter().enumerate() {
            assert_eq!(
                fields(&insns[copy + word * 2]),
                (BPF_LDX | BPF_DW | BPF_MEM, R1, R0, offset, 0)
            );
            assert_eq!(
                fields(&insns[copy + word * 2 + 1]),
                (BPF_STX | BPF_DW | BPF_MEM, R10, R1, area + offset, 0)
            );
            assert_eq!(
                fields(&insns[absent + 1 + word]),
                (BPF_STX | BPF_DW | BPF_MEM, R10, R1, area + offset, 0)
            );
        }
        assert_eq!(
            fields(&insns[absent]),
            (BPF_ALU64 | BPF_MOV | BPF_K, R1, 0, 0, 0)
        );
        assert_eq!(fields(&insns[copy + 8]), (BPF_JMP | BPF_JA, 0, 0, 5, 0));
        assert_eq!(insns.len(), absent + 5);
    }
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
