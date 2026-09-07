//! AP6: the topology a MainDevice already discovered must be readable from outside.
//!
//! EtherCrab walks every port of every SubDevice during `init()` and knows exactly how the
//! network is wired - `Topology`, `entry_port()`, `port_assigned_to()` all exist and are
//! tested. None of it was reachable from a dependent crate, because `mod subdevice` is
//! private and nothing re-exported the types.
//!
//! This file lives in `tests/` on purpose: an integration test compiles against the
//! crate's *public* surface, so it fails to build while a re-export is missing. A unit
//! test inside the crate would compile either way and prove nothing.
//!
//! It deliberately asserts nothing about behaviour. `Ports` cannot be built from outside -
//! that is the point, its port numbering carries an invariant - so behaviour is checked
//! by the crate's own unit tests, where a `Ports` can be constructed correctly.

use ethercrab::{Port, Ports, SubDevice, Topology};

/// Everything AP6 has to make reachable, named in one place.
///
/// If any of these types or methods stops being public, this fails to compile.
#[allow(dead_code)]
fn the_public_surface(subdevice: &SubDevice) -> (Topology, Port, bool) {
    let ports: &Ports = subdevice.ports();

    let topology: Topology = ports.topology();
    let entry: Port = ports.entry_port();
    let assigned: Option<&Port> = ports.port_assigned_to(subdevice);

    // `Port`'s fields are plain data and stay readable.
    let _: bool = entry.active;
    let _: u8 = entry.number;
    let _: u32 = entry.dc_receive_time;

    (
        topology,
        entry,
        topology.is_junction() || assigned.is_some(),
    )
}

#[test]
fn the_four_shapes_are_distinguishable_from_outside() {
    // Comparing the variants needs them to be public, nameable and `PartialEq`.
    assert_ne!(Topology::LineEnd, Topology::Passthrough);
    assert!(Topology::Fork.is_junction());
    assert!(Topology::Cross.is_junction());
    assert!(!Topology::LineEnd.is_junction());
    assert!(!Topology::Passthrough.is_junction());
}

#[test]
fn topology_is_copy_so_reading_it_does_not_move_it() {
    let topology = Topology::Fork;
    let copy = topology;
    assert_eq!(topology, copy);
}
