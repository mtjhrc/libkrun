// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::fmt;
use std::result;
use std::sync::{Arc, Mutex};

use devices::virtio::Net;
use utils::net::mac::MacAddr;

#[derive(Debug, PartialEq)]
//#[serde(deny_unknown_fields)]
pub struct NetworkInterfaceConfig {
    /// ID of the guest network interface.
    pub iface_id: String,
    /// Guest MAC address.
    pub guest_mac: Option<MacAddr>,
}

/// Errors associated with `NetworkInterfaceConfig`.
#[derive(Debug)]
pub enum NetworkInterfaceError {
    /// Could not create Network Device.
    CreateNetworkDevice(devices::virtio::net::Error),
    /// The MAC address is already in use.
    GuestMacAddressInUse(String),
    /// Couldn't find the interface to update (patch).
    DeviceIdNotFound,
}

impl fmt::Display for NetworkInterfaceError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use self::NetworkInterfaceError::*;
        match *self {
            CreateNetworkDevice(ref e) => write!(f, "Could not create Network Device: {:?}", e),
            GuestMacAddressInUse(ref mac_addr) => {
                write!(f, "The guest MAC address {} is already in use.", mac_addr)
            }
            DeviceIdNotFound => write!(f, "Invalid interface ID - not found."),
        }
    }
}

type Result<T> = result::Result<T, NetworkInterfaceError>;

/// Builder for a list of network devices.
#[derive(Default)]
pub struct NetBuilder {
    net_devices: Vec<Arc<Mutex<Net>>>,
}

impl NetBuilder {
    /// Creates an empty list of Network Devices.
    pub fn new() -> Self {
        NetBuilder {
            /// List of built network devices.
            net_devices: Vec::new(),
        }
    }

    /// Returns a immutable iterator over the network devices.
    pub fn iter(&self) -> ::std::slice::Iter<Arc<Mutex<Net>>> {
        self.net_devices.iter()
    }

    /// Returns a mutable iterator over the network devices.
    pub fn iter_mut(&mut self) -> ::std::slice::IterMut<Arc<Mutex<Net>>> {
        self.net_devices.iter_mut()
    }

    /// Builds a network device based on a network interface config. Keeps a device reference
    /// in the builder's internal list.
    pub fn build(&mut self, netif_config: NetworkInterfaceConfig) -> Result<Arc<Mutex<Net>>> {
        let mac_conflict = |net: &Arc<Mutex<Net>>| {
            let net = net.lock().expect("Poisoned lock");
            // Check if another net dev has same MAC.
            netif_config.guest_mac.is_some()
                && netif_config.guest_mac.as_ref() == net.guest_mac()
                && &netif_config.iface_id != net.id()
        };
        // Validate there is no Mac conflict.
        if self.net_devices.iter().any(mac_conflict) {
            return Err(NetworkInterfaceError::GuestMacAddressInUse(
                netif_config.guest_mac.unwrap().to_string(),
            ));
        }

        // If this is an update, just remove the old one.
        if let Some(index) = self
            .net_devices
            .iter()
            .position(|net| net.lock().expect("Poisoned lock").id() == &netif_config.iface_id)
        {
            self.net_devices.swap_remove(index);
        }

        // Add new device.
        let net = Arc::new(Mutex::new(Self::create_net(netif_config)?));
        self.net_devices.push(net.clone());

        Ok(net)
    }

    /// Creates a Net device from a NetworkInterfaceConfig.
    pub fn create_net(cfg: NetworkInterfaceConfig) -> Result<Net> {
        // Create and return the Net device
        Net::new(cfg.iface_id, cfg.guest_mac.as_ref())
            .map_err(NetworkInterfaceError::CreateNetworkDevice)
    }
}
