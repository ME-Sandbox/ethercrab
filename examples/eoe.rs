//! Send one Ethernet frame to every EoE capable SubDevice on the bus, and read one back.
//!
//! Ethernet over EtherCAT tunnels ordinary Ethernet frames through a SubDevice's mailbox.
//! This example does the two halves of that and nothing else: it does not configure an IP
//! address, and it is not a network interface. What it demonstrates is the shape - which
//! devices can do it, what goes out, what comes back.
//!
//! **Receiving blocks until a frame arrives.** A SubDevice sends EoE frames when it has
//! something to send, so a device that is not talking will make this example wait for
//! `Timeouts::mailbox_response` and then report a timeout. That is the normal outcome
//! against a quiet device, and the reason the receive is behind a flag here.
//!
//! Run with e.g.
//!
//! Linux
//!
//! ```bash
//! cargo build --release --example eoe
//! # avoid sudo with `sudo setcap cap_net_raw=pe /path/to/eoe`
//! RUST_LOG=debug sudo -E ./target/release/eoe eth0
//! # also wait for a frame from each device
//! RUST_LOG=debug sudo -E ./target/release/eoe eth0 --receive
//! ```
//!
//! Windows
//!
//! ```ps
//! $env:RUST_LOG="debug" ; cargo run --example eoe --release -- '\Device\NPF_{FF0ACEE6-E8CD-48D5-A399-619CD2340465}'
//! ```

use env_logger::Env;
use ethercrab::{
    MainDevice, MainDeviceConfig, PduStorage, Timeouts, error::Error, std::ethercat_now,
};
use std::{sync::Arc, time::Duration};

/// Maximum number of SubDevices that can be stored. This must be a power of 2 greater than 1.
const MAX_SUBDEVICES: usize = 16;
/// Maximum PDU data payload size - set this to the max PDI size or higher.
const MAX_PDU_DATA: usize = PduStorage::element_size(1100);
/// Maximum number of EtherCAT frames that can be in flight at any one time.
const MAX_FRAMES: usize = 16;
/// Maximum total PDI length.
const PDI_LEN: usize = 64;

/// An Ethernet frame is at most 1514 bytes, and EoE caps a frame at 63 blocks of 32.
const MAX_ETHERNET_FRAME: usize = 1514;

static PDU_STORAGE: PduStorage<MAX_FRAMES, MAX_PDU_DATA> = PduStorage::new();

fn main() -> Result<(), Error> {
    smol::block_on(async {
        env_logger::Builder::from_env(Env::default().default_filter_or("info")).init();

        let interface = std::env::args()
            .nth(1)
            .expect("Provide network interface as first argument.");

        let receive = std::env::args().any(|arg| arg == "--receive");

        let (tx, rx, pdu_loop) = PDU_STORAGE.try_split().expect("can only split once");

        let maindevice = Arc::new(MainDevice::new(
            pdu_loop,
            Timeouts {
                wait_loop_delay: Duration::from_millis(2),
                mailbox_response: Duration::from_millis(1000),
                ..Default::default()
            },
            MainDeviceConfig::default(),
        ));

        #[cfg(target_os = "windows")]
        std::thread::spawn(move || {
            ethercrab::std::tx_rx_task_blocking(
                &interface,
                tx,
                rx,
                ethercrab::std::TxRxTaskConfig { spinloop: false },
            )
            .expect("TX/RX task")
        });
        #[cfg(not(target_os = "windows"))]
        smol::spawn(ethercrab::std::tx_rx_task(&interface, tx, rx).expect("spawn TX/RX task"))
            .detach();

        let group = maindevice
            .init_single_group::<MAX_SUBDEVICES, PDI_LEN>(ethercat_now)
            .await
            .expect("Init");

        // The first question an EoE program asks. A device that did not announce EoE in
        // its EEPROM has no mailbox to put a frame in, and sending anyway only produces an
        // error further down.
        for subdevice in group.iter(&maindevice) {
            if !subdevice.supports_eoe() {
                println!("{}: no EoE", subdevice.name());

                continue;
            }

            println!("{}: EoE", subdevice.name());

            // Port 0: a SubDevice with one EoE port uses it, and most have one. The bytes
            // are not a valid Ethernet frame and are not meant to be - what is being shown
            // is that they arrive as one payload, cut into mailbox sized fragments and put
            // back together on the other side.
            match subdevice.eoe_send(0, b"hello over EtherCAT").await {
                Ok(()) => println!("  sent 19 bytes"),
                Err(e) => println!("  send failed: {}", e),
            }

            if !receive {
                continue;
            }

            let mut buffer = [0u8; MAX_ETHERNET_FRAME];

            match subdevice.eoe_receive(0, &mut buffer).await {
                Ok(frame) => println!("  received {} bytes: {:02x?}", frame.len(), frame),
                // A quiet device times out here, and that is not a fault of the bus.
                Err(e) => println!("  receive failed: {}", e),
            }
        }

        Ok(())
    })
}
