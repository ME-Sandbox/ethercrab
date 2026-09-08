//! The EoE surface has to be reachable from outside the crate.
//!
//! An **integration** test on purpose: it compiles against the public API, so it fails to
//! build while a method is missing or a type is `pub` without being exported. A unit test
//! inside the crate would pass either way and prove nothing - which is exactly what
//! happened twice in this module, with `Fragment` and with `IpParam`: both were `pub`,
//! neither was reachable, and only `cargo doc` noticed.
//!
//! It asserts no behaviour. Nothing here can be *called* without a bus; what is checked is
//! that a dependent crate can name it.

use ethercrab::{
    EoeHeader, EoeResult, Fragment, Fragments, FrameType, InProgress, IpParam, Reassembled,
    Reassembly, SecondWord, SubDevice, SubDeviceRef,
};

#[test]
fn the_eoe_wire_types_can_be_named_from_outside_the_crate() {
    // Naming them is the whole test: `use` above fails to compile otherwise.
    fn takes<T>(_: core::marker::PhantomData<T>) {}

    takes::<EoeHeader>(core::marker::PhantomData);
    takes::<EoeResult>(core::marker::PhantomData);
    takes::<Fragment>(core::marker::PhantomData);
    takes::<Fragments<'_>>(core::marker::PhantomData);
    takes::<FrameType>(core::marker::PhantomData);
    takes::<InProgress>(core::marker::PhantomData);
    takes::<IpParam>(core::marker::PhantomData);
    takes::<Reassembled<'_>>(core::marker::PhantomData);
    takes::<Reassembly<'_>>(core::marker::PhantomData);
    takes::<SecondWord>(core::marker::PhantomData);
}

#[test]
fn a_frame_can_be_cut_and_put_back_together_from_outside_the_crate() {
    // The two pure halves are usable without a bus, so this checks the shape a consumer
    // actually gets: capacity in, fragments out, fragments in, frame out.
    let frame = (0..70u8).collect::<Vec<_>>();

    let mut buffer = [0u8; 128];
    let mut reassembly = Reassembly::new(&mut buffer, 0).expect("A reassembly");

    let mut rebuilt = None;

    for (header, data) in Fragments::new(&frame, 32, 1, 0).expect("Fits") {
        match reassembly.push(header, data).expect("A fragment") {
            Reassembled::More => assert!(reassembly.in_progress().is_some()),
            Reassembled::Frame(done) => rebuilt = Some(done.to_vec()),
        }
    }

    assert_eq!(rebuilt.as_deref(), Some(frame.as_slice()));
}

/// The two mailbox paths, named but never called: reaching them needs a `SubDeviceRef`,
/// and building one needs a `MainDevice` and a bus. Naming them is what this file is for -
/// a method that is not `pub` does not compile here.
#[allow(dead_code)]
async fn the_mailbox_paths_are_callable_from_outside_the_crate(
    subdevice: &SubDeviceRef<'_, &SubDevice>,
    buffer: &mut [u8],
) {
    let _ = subdevice.eoe_send(0, b"a frame").await;
    let _ = subdevice.eoe_receive(0, buffer).await;
}
