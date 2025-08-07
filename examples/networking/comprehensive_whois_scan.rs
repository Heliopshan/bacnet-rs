//! Network Object Scanner V2 - Improved parsing
//!
//! This example scans all devices on the network and displays their objects
//! with properly parsed names and values.

use bacnet_rs::{
    service::{WhoIsRequest, IAmRequest},
    network::{Npdu, NetworkAddress},
    datalink::bip::{BvlcHeader, BvlcFunction},
    vendor::get_vendor_name,
    object::{ObjectType, PropertyIdentifier},
};
use hex;
use std::{
    net::{SocketAddr, UdpSocket},
    time::{Duration, Instant},
    collections::HashMap,
    sync::atomic::{AtomicU8, Ordering},
};

const BACNET_PORT: u16 = 0xBAC0;

#[derive(Debug, Clone)]
struct DeviceInfo {
    instance: u32,
    address: SocketAddr,
    network_number: u16,
    vendor_name: String,
    mac_address: Vec<u8>,
}

#[derive(Debug, Clone)]
struct ObjectInfo {
    object_type: ObjectType,
    instance: u32,
    name: String,
    present_value: String,
    units: String,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("BACnet Network Object Scanner V2");
    println!("=================================\n");

    // Bind to BACnet port
    let socket = match UdpSocket::bind("0.0.0.0:47808") {
        Ok(s) => s,
        Err(_) => {
            println!("Standard port busy, using alternative port...");
            UdpSocket::bind("0.0.0.0:0")?
        }
    };

    socket.set_broadcast(true)?;
    socket.set_read_timeout(Some(Duration::from_millis(100)))?;

    println!("📡 Listening on {}\n", socket.local_addr()?);

    // Get broadcast addresses
    let broadcast_addresses = get_broadcast_addresses();
    println!("Found {} network interfaces\n", broadcast_addresses.len());

    // Discover devices
    println!("Discovering devices...");
    let devices = discover_devices(&socket, &broadcast_addresses)?;
    println!("Found {} devices\n", devices.len());

    // Process each device
    for device in devices.values() {
        println!("\n========================================");
        println!("Device {} - {}", device.instance, device.vendor_name);
        println!("Address: {}", device.address);
        if device.network_number != 0 {
            println!("Network: {}", device.network_number);
        }
        println!("========================================\n");

        // Get object list
        match get_object_list(&socket, device) {
            Ok(object_ids) => {
                println!("Found {} objects in device\n", object_ids.len());

                // Filter to I/O objects only
                let io_objects: Vec<_> = object_ids.into_iter()
                    .filter(|(obj_type, _)| is_io_object(*obj_type))
                    .collect();

                if io_objects.is_empty() {
                    println!("No I/O objects found");
                    continue;
                }

                println!("Reading {} I/O objects:", io_objects.len());

                let mut objects = Vec::new();
                for (i, (obj_type, instance)) in io_objects.iter().enumerate() {
                    if i % 10 == 0 {
                        print!("  Progress: {}/{}\r", i, io_objects.len());
                        std::io::Write::flush(&mut std::io::stdout())?;
                    }

                    let mut obj_info = ObjectInfo {
                        object_type: *obj_type,
                        instance: *instance,
                        name: String::new(),
                        present_value: String::new(),
                        units: String::new(),
                    };

                    // Read name
                    if let Ok(name) = read_and_parse_property(&socket, device, *obj_type, *instance, PropertyIdentifier::ObjectName as u32) {
                        obj_info.name = name;
                    }

                    // Read present value
                    if let Ok(value) = read_and_parse_property(&socket, device, *obj_type, *instance, PropertyIdentifier::PresentValue as u32) {
                        obj_info.present_value = value;
                    }

                    // Read units for analog objects only
                    let is_analog = matches!(
                        obj_type,
                        ObjectType::AnalogInput | ObjectType::AnalogOutput | ObjectType::AnalogValue
                    );

                    if is_analog {
                        if let Ok(units_str) = read_and_parse_property(&socket, device, *obj_type, *instance, 117) {
                            obj_info.units = units_str;
                        }
                    }

                    // Only add if we got a proper name
                    if !obj_info.name.is_empty() && !obj_info.name.contains(':') {
                        objects.push(obj_info);
                    }
                }

                println!("  Completed reading objects          ");

                // Display results
                if objects.is_empty() {
                    println!("\nNo objects with valid data");
                } else {
                    println!("\nObjects with valid data ({}):", objects.len());

                    // Group by type
                    let mut by_type: HashMap<ObjectType, Vec<&ObjectInfo>> = HashMap::new();
                    for obj in &objects {
                        by_type.entry(obj.object_type).or_insert(Vec::new()).push(obj);
                    }

                    // Display each type
                    let mut sorted_types: Vec<_> = by_type.keys().cloned().collect();
                    sorted_types.sort_by_key(|t| *t as u16);

                    for obj_type in sorted_types {
                        if let Some(type_objects) = by_type.get(&obj_type) {
                            println!("\n  {} ({}):", format_object_type(&obj_type), type_objects.len());

                            let mut sorted_objs = type_objects.clone();
                            sorted_objs.sort_by_key(|o| o.instance);

                            for obj in sorted_objs {
                                let value_display = if obj.present_value.is_empty() {
                                    "N/A".to_string()
                                } else if !obj.units.is_empty() {
                                    format!("{} {}", obj.present_value, obj.units)
                                } else {
                                    obj.present_value.clone()
                                };

                                println!("    [{:3}] {:<40} = {}",
                                         obj.instance,
                                         obj.name,
                                         value_display);
                            }
                        }
                    }
                }
            }
            Err(e) => {
                println!("Error reading object list: {}", e);
            }
        }
    }

    println!("\n\nScan complete!");
    Ok(())
}

fn get_broadcast_addresses() -> Vec<SocketAddr> {
    let mut addresses = Vec::new();

    if let Ok(interfaces) = if_addrs::get_if_addrs() {
        for interface in interfaces {
            if !interface.is_loopback() {
                if let if_addrs::IfAddr::V4(ref addr) = interface.addr {
                    let broadcast = if let Some(broadcast) = addr.broadcast {
                        broadcast
                    } else {
                        let ip = addr.ip.octets();
                        let mask = addr.netmask.octets();
                        let broadcast = [
                            ip[0] | !mask[0],
                            ip[1] | !mask[1],
                            ip[2] | !mask[2],
                            ip[3] | !mask[3],
                        ];
                        std::net::Ipv4Addr::from(broadcast)
                    };
                    addresses.push(SocketAddr::from((broadcast, BACNET_PORT)));
                }
            }
        }
    }

    addresses.push(SocketAddr::from(([255, 255, 255, 255], BACNET_PORT)));
    addresses.sort();
    addresses.dedup();
    addresses
}

fn discover_devices(
    socket: &UdpSocket,
    broadcast_addresses: &[SocketAddr],
) -> Result<HashMap<u32, DeviceInfo>, Box<dyn std::error::Error>> {
    let mut devices = HashMap::new();

    // Create Who-Is request
    let who_is = WhoIsRequest::new();
    let mut who_is_data = Vec::new();
    who_is.encode(&mut who_is_data)?;

    let mut apdu = vec![0x10, 0x08];
    apdu.extend_from_slice(&who_is_data);

    let npdu = Npdu::global_broadcast();
    let mut npdu_bytes = npdu.encode();
    npdu_bytes.extend_from_slice(&apdu);

    let header = BvlcHeader::new(BvlcFunction::OriginalBroadcastNpdu, 4 + npdu_bytes.len() as u16);
    let mut frame = header.encode();
    frame.extend_from_slice(&npdu_bytes);

    // Send to all broadcast addresses
    for addr in broadcast_addresses {
        let _ = socket.send_to(&frame, addr);
    }

    // Collect responses
    let start = Instant::now();
    let mut buffer = [0u8; 1500];

    while start.elapsed() < Duration::from_secs(3) {
        match socket.recv_from(&mut buffer) {
            Ok((len, src)) => {
                if len > 4 {
                    let npdu_data = &buffer[4..len];
                    if let Ok((npdu, offset)) = Npdu::decode(npdu_data) {
                        if !npdu.is_network_message() && npdu_data.len() > offset {
                            let apdu_data = &npdu_data[offset..];
                            if apdu_data.len() > 1 && apdu_data[0] == 0x10 && apdu_data[1] == 0x00 {
                                if let Ok(iam) = IAmRequest::decode(&apdu_data[2..]) {
                                    let device_id = iam.device_identifier.instance;

                                    if !devices.contains_key(&device_id) {
                                        let network_number = if let Some(source) = &npdu.source {
                                            source.network
                                        } else {
                                            0
                                        };

                                        let mac_address = if let Some(source) = &npdu.source {
                                            source.address.clone()
                                        } else {
                                            vec![]
                                        };

                                        devices.insert(device_id, DeviceInfo {
                                            instance: device_id,
                                            address: src,
                                            network_number,
                                            vendor_name: get_vendor_name(iam.vendor_identifier as u16)
                                                .unwrap_or("Unknown").to_string(),
                                            mac_address,
                                        });
                                    }
                                }
                            }
                        }
                    }
                }
            }
            Err(_) => continue,
        }
    }

    Ok(devices)
}

fn get_object_list(
    socket: &UdpSocket,
    device: &DeviceInfo,
) -> Result<Vec<(ObjectType, u32)>, Box<dyn std::error::Error>> {
    let response = read_property(socket, device, ObjectType::Device, device.instance, PropertyIdentifier::ObjectList as u32)?;

    let mut objects = Vec::new();

    if response.starts_with("0x") {
        let bytes = hex::decode(&response[2..])?;
        let mut i = 0;

        // Skip APDU header
        if bytes.len() > 2 && bytes[0] == 0x30 {
            i = 2;
        }

        // Find opening tag
        while i < bytes.len() && bytes[i] != 0x3E {
            i += 1;
        }
        if i < bytes.len() && bytes[i] == 0x3E {
            i += 1;
        }

        // Parse object identifiers
        while i < bytes.len() {
            if bytes[i] == 0x3F {
                break;
            }

            if bytes[i] == 0xC4 && i + 4 < bytes.len() {
                let obj_bytes = [bytes[i+1], bytes[i+2], bytes[i+3], bytes[i+4]];
                let obj_id = u32::from_be_bytes(obj_bytes);
                let obj_type_num = (obj_id >> 22) & 0x3FF;
                let instance = obj_id & 0x3FFFFF;

                if let Ok(obj_type) = ObjectType::try_from(obj_type_num as u16) {
                    objects.push((obj_type, instance));
                }
                i += 5;
            } else {
                i += 1;
            }
        }
    }

    Ok(objects)
}

fn read_property(
    socket: &UdpSocket,
    device: &DeviceInfo,
    object_type: ObjectType,
    object_instance: u32,
    property_id: u32,
) -> Result<String, Box<dyn std::error::Error>> {
    static INVOKE_ID: AtomicU8 = AtomicU8::new(1);
    let invoke_id = INVOKE_ID.fetch_add(1, Ordering::SeqCst);
    let invoke_id = if invoke_id == 0 { 1 } else { invoke_id };

    // Build APDU
    let mut apdu = Vec::new();
    apdu.push(0x00); // Confirmed request
    apdu.push(0x05); // Max segments
    apdu.push(invoke_id);
    apdu.push(0x0C); // ReadProperty

    // Object identifier
    let obj_id = ((object_type as u32) << 22) | (object_instance & 0x3FFFFF);
    apdu.push(0x0C);
    apdu.extend_from_slice(&obj_id.to_be_bytes());

    // Property identifier
    if property_id <= 255 {
        apdu.push(0x19);
        apdu.push(property_id as u8);
    } else {
        apdu.push(0x1A);
        apdu.push((property_id >> 8) as u8);
        apdu.push((property_id & 0xFF) as u8);
    }

    // Build NPDU
    let npdu = if device.network_number == 0 {
        Npdu::new()
    } else {
        let mut npdu = Npdu::new();
        npdu.control.destination_present = true;
        npdu.destination = Some(NetworkAddress {
            network: device.network_number,
            address: device.mac_address.clone(),
        });
        npdu.hop_count = Some(255);
        npdu
    };

    let mut npdu_bytes = npdu.encode();
    npdu_bytes.extend_from_slice(&apdu);

    let header = BvlcHeader::new(BvlcFunction::OriginalUnicastNpdu, 4 + npdu_bytes.len() as u16);
    let mut frame = header.encode();
    frame.extend_from_slice(&npdu_bytes);

    // Send request
    socket.send_to(&frame, device.address)?;

    // Wait for response
    let timeout = if device.network_number == 2001 {
        Duration::from_millis(1000)
    } else {
        Duration::from_millis(500)
    };

    let mut buffer = [0u8; 1500];
    let start = Instant::now();

    while start.elapsed() < timeout {
        match socket.recv_from(&mut buffer) {
            Ok((len, src_addr)) => {
                if len > 4 {
                    let npdu_data = &buffer[4..len];
                    if let Ok((_, offset)) = Npdu::decode(npdu_data) {
                        if npdu_data.len() > offset {
                            let apdu_data = &npdu_data[offset..];
                            let pdu_type = (apdu_data[0] & 0xF0) >> 4;
                            let resp_invoke_id = apdu_data[0] & 0x0F;

                            if resp_invoke_id == (invoke_id & 0x0F) || src_addr == device.address {
                                if pdu_type == 0x3 {
                                    return Ok(format!("0x{}", hex::encode(apdu_data)));
                                } else if pdu_type == 0x5 {
                                    return Err("BACnet Error".into());
                                } else if pdu_type == 0x6 || pdu_type == 0x7 {
                                    return Err("Property not supported".into());
                                }
                            }
                        }
                    }
                }
            }
            Err(_) => continue,
        }
    }

    Err("Timeout".into())
}

fn read_and_parse_property(
    socket: &UdpSocket,
    device: &DeviceInfo,
    object_type: ObjectType,
    instance: u32,
    property_id: u32,
) -> Result<String, Box<dyn std::error::Error>> {
    let response = read_property(socket, device, object_type, instance, property_id)?;

    match property_id {
        77 => parse_name(&response), // ObjectName
        85 => parse_present_value(&response), // PresentValue
        117 => parse_units(&response), // Units
        _ => Ok(response),
    }
}

fn parse_name(response: &str) -> Result<String, Box<dyn std::error::Error>> {
    if !response.starts_with("0x") {
        return Ok(response.to_string());
    }

    let bytes = hex::decode(&response[2..])?;

    // Try UTF-16 first (Tridium)
    if let Some(name) = try_parse_utf16(&bytes) {
        return Ok(name);
    }

    // Try ASCII with length tag (BELIMO)
    if let Some(name) = try_parse_bacnet_string(&bytes) {
        return Ok(name);
    }

    Err("Could not parse name".into())
}

fn parse_present_value(response: &str) -> Result<String, Box<dyn std::error::Error>> {
    if !response.starts_with("0x") {
        return Ok(response.to_string());
    }

    let bytes = hex::decode(&response[2..])?;
    let mut i = 0;

    // Skip APDU header
    if bytes.len() > 2 && bytes[0] == 0x30 {
        i = 2;
    }

    // Find property value after 0x3E
    while i < bytes.len() {
        if bytes[i] == 0x3E {
            i += 1;
            break;
        }
        i += 1;
    }

    if i < bytes.len() {
        let tag = bytes[i];

        // Parse based on tag type
        match tag {
            0x44 if i + 4 < bytes.len() => {
                // Real (float)
                let value_bytes = [bytes[i+1], bytes[i+2], bytes[i+3], bytes[i+4]];
                let value = f32::from_be_bytes(value_bytes);
                if value.is_finite() && value.abs() < 1e10 {
                    return Ok(format!("{:.2}", value));
                }
            }
            0x21..=0x24 if i + ((tag & 0x07) as usize) < bytes.len() => {
                // Unsigned integer
                let len = (tag & 0x07) as usize;
                let mut value = 0u32;
                for j in 0..len {
                    value = (value << 8) | (bytes[i + 1 + j] as u32);
                }
                return Ok(value.to_string());
            }
            0x10 | 0x11 => {
                // Boolean
                return Ok(if tag == 0x11 { "Active" } else { "Inactive" }.to_string());
            }
            0x91 if i + 1 < bytes.len() => {
                // Enumerated (single byte)
                let value = bytes[i+1];
                return Ok(value.to_string());
            }
            // Try to handle character string values (sometimes values are strings)
            0x74 | 0x75 => {
                // Character string - try to parse as string
                if let Ok(s) = parse_name(response) {
                    // Check if it's a number in string format
                    if let Ok(num) = s.trim().parse::<f32>() {
                        return Ok(format!("{:.2}", num));
                    }
                    return Ok(s);
                }
            }
            _ => {}
        }
    }

    Err("Could not parse value".into())
}

fn parse_units(response: &str) -> Result<String, Box<dyn std::error::Error>> {
    if !response.starts_with("0x") {
        return Ok(response.to_string());
    }

    let bytes = hex::decode(&response[2..])?;
    let mut i = 0;

    // Skip APDU header
    if bytes.len() > 2 && bytes[0] == 0x30 {
        i = 2;
    }

    // Find property value after 0x3E
    while i < bytes.len() {
        if bytes[i] == 0x3E {
            i += 1;
            break;
        }
        i += 1;
    }

    if i < bytes.len() && bytes[i] == 0x91 && i + 1 < bytes.len() {
        // Enumerated units
        let unit_id = bytes[i+1];
        return Ok(format_units(unit_id as u32));
    }

    Err("Could not parse units".into())
}

fn try_parse_utf16(bytes: &[u8]) -> Option<String> {
    let mut i = 0;

    // Skip to 0x3E
    while i < bytes.len() && bytes[i] != 0x3E {
        i += 1;
    }
    if i < bytes.len() && bytes[i] == 0x3E {
        i += 1;
    }

    // Look for UTF-16 pattern
    let mut chars = Vec::new();
    while i + 1 < bytes.len() {
        if bytes[i] == 0x00 && bytes[i+1] >= 0x20 && bytes[i+1] <= 0x7E {
            chars.push(bytes[i+1]);
            i += 2;
        } else if bytes[i] >= 0x20 && bytes[i] <= 0x7E && bytes[i+1] == 0x00 {
            chars.push(bytes[i]);
            i += 2;
        } else if !chars.is_empty() {
            break;
        } else {
            i += 1;
        }
    }

    if chars.len() >= 2 {
        return Some(String::from_utf8_lossy(&chars).trim().to_string());
    }

    None
}

fn try_parse_bacnet_string(bytes: &[u8]) -> Option<String> {
    let mut i = 0;

    // Skip to 0x3E
    while i < bytes.len() && bytes[i] != 0x3E {
        i += 1;
    }
    if i < bytes.len() && bytes[i] == 0x3E {
        i += 1;
    }

    // Look for string tag 0x75 or 0x74
    if i < bytes.len() && (bytes[i] == 0x75 || bytes[i] == 0x74) {
        let len = bytes[i+1] as usize;
        let start = i + 2;

        if start < bytes.len() && start + len <= bytes.len() {
            // Check for encoding byte
            if bytes[start] == 0x00 && len > 1 {
                let text = &bytes[start+1..start+len];
                return Some(String::from_utf8_lossy(text).trim().to_string());
            } else if bytes[start] >= 0x20 && bytes[start] <= 0x7E {
                let text = &bytes[start..start+len];
                return Some(String::from_utf8_lossy(text).trim().to_string());
            }
        }
    }

    None
}

fn format_units(unit_id: u32) -> String {
    match unit_id {
        // Acceleration
        166 => "m/s²",

        // Area
        0 => "m²",
        116 => "cm²",
        1 => "ft²",
        115 => "in²",

        // Currency
        105 => "currency1",
        106 => "currency2",
        107 => "currency3",
        108 => "currency4",
        109 => "currency5",
        110 => "currency6",
        111 => "currency7",
        112 => "currency8",
        113 => "currency9",
        114 => "currency10",

        // Electrical
        2 => "mA",
        3 => "A",
        167 => "A/m",
        168 => "A/m²",
        169 => "A·m²",
        199 => "dB",
        200 => "dB(mV)",
        201 => "dB(V)",
        170 => "F",
        171 => "H",
        4 => "Ω",
        237 => "Ω·m²/m",
        172 => "Ω·m",
        145 => "mΩ",
        122 => "kΩ",
        123 => "MΩ",
        190 => "µS",
        202 => "mS",
        173 => "S",
        174 => "S/m",
        175 => "T",
        5 => "V",
        124 => "mV",
        6 => "kV",
        7 => "MV",
        8 => "VA",
        9 => "kVA",
        10 => "MVA",
        11 => "VAR",
        12 => "kVAR",
        13 => "MVAR",
        176 => "V/°K",
        177 => "V/m",
        14 => "°",
        15 => "pf",
        178 => "Wb",
        238 => "A·s",
        239 => "VA·h",
        240 => "kVA·h",
        241 => "MVA·h",
        242 => "VAR·h",
        243 => "kVAR·h",
        244 => "MVAR·h",
        245 => "V²·h",
        246 => "A²·h",

        // Energy
        16 => "J",
        17 => "kJ",
        125 => "kJ/kg",
        126 => "MJ",
        18 => "Wh",
        19 => "kWh",
        146 => "MWh",
        203 => "Wh(reactive)",
        204 => "kWh(reactive)",
        205 => "MWh(reactive)",
        20 => "BTU",
        147 => "kBTU",
        148 => "MBTU",
        21 => "therms",
        22 => "ton·h",

        // Enthalpy
        23 => "J/kg(dry air)",
        149 => "kJ/kg(dry air)",
        150 => "MJ/kg(dry air)",
        24 => "BTU/lb(dry air)",
        117 => "BTU/lb",

        // Entropy
        127 => "J/°K",
        151 => "kJ/°K",
        152 => "MJ/°K",
        128 => "J/(kg·°K)",

        // Force
        153 => "N",

        // Frequency
        25 => "cycles/h",
        26 => "cycles/min",
        27 => "Hz",
        129 => "kHz",
        130 => "MHz",
        131 => "/h",

        // Humidity
        28 => "g(water)/kg(dry air)",
        29 => "%RH",

        // Length
        194 => "µm",
        30 => "mm",
        118 => "cm",
        193 => "km",
        31 => "m",
        32 => "in",
        33 => "ft",

        // Light
        179 => "cd",
        180 => "cd/m²",
        34 => "W/ft²",
        35 => "W/m²",
        36 => "lm",
        37 => "lux",
        38 => "fc",

        // Mass
        196 => "mg",
        195 => "g",
        39 => "kg",
        40 => "lb",
        41 => "tons",

        // Mass Flow
        154 => "g/s",
        155 => "g/min",
        42 => "kg/s",
        43 => "kg/min",
        44 => "kg/h",
        119 => "lb/s",
        45 => "lb/min",
        46 => "lb/h",
        156 => "tons/h",

        // Power
        132 => "mW",
        47 => "W",
        48 => "kW",
        49 => "MW",
        50 => "BTU/h",
        157 => "kBTU/h",
        247 => "J/h",
        51 => "hp",
        52 => "tons(refrigeration)",

        // Pressure
        53 => "Pa",
        133 => "hPa",
        54 => "kPa",
        134 => "mbar",
        55 => "bar",
        56 => "psi",
        206 => "mmH₂O",
        57 => "cmH₂O",
        58 => "inH₂O",
        59 => "mmHg",
        60 => "cmHg",
        61 => "inHg",

        // Temperature
        62 => "°C",
        63 => "K",
        181 => "K/h",
        182 => "K/min",
        64 => "°F",
        65 => "degree-days-C",
        66 => "degree-days-F",
        120 => "Δ°F",
        121 => "ΔK",

        // Time
        67 => "years",
        68 => "months",
        69 => "weeks",
        70 => "days",
        71 => "h",
        72 => "min",
        73 => "s",
        158 => "cs",
        159 => "ms",

        // Torque
        160 => "N·m",

        // Velocity
        161 => "mm/s",
        162 => "mm/min",
        74 => "m/s",
        163 => "m/min",
        164 => "m/h",
        75 => "km/h",
        76 => "ft/s",
        77 => "ft/min",
        78 => "mph",

        // Volume
        79 => "ft³",
        80 => "m³",
        81 => "imperial gal",
        197 => "mL",
        82 => "L",
        83 => "US gal",

        // Volumetric Flow
        142 => "ft³/s",
        84 => "CFM",
        254 => "million SCFM",
        191 => "ft³/h",
        248 => "ft³/day",
        47808 => "SCFD",
        47809 => "million SCFD",
        47810 => "thousand ft³/day",
        47811 => "thousand SCFD",
        47812 => "lb/day",
        85 => "m³/s",
        165 => "m³/min",
        135 => "m³/h",
        249 => "m³/day",
        86 => "imperial gal/min",
        198 => "mL/s",
        87 => "L/s",
        88 => "L/min",
        136 => "L/h",
        89 => "US gal/min",
        192 => "US gal/h",

        // Other
        90 => "°",
        91 => "°C/h",
        92 => "°C/min",
        93 => "°F/h",
        94 => "°F/min",
        183 => "J·s",
        186 => "kg/m³",
        137 => "kWh/m²",
        138 => "kWh/ft²",
        250 => "Wh/m³",
        251 => "J/m³",
        139 => "MJ/m²",
        140 => "MJ/ft²",
        252 => "mol%",
        95 => "",  // no-units
        187 => "N·s",
        188 => "N/m",
        96 => "ppm",
        97 => "ppb",
        253 => "Pa·s",
        98 => "%",
        143 => "%obscuration/ft",
        144 => "%obscuration/m",
        99 => "%/s",
        100 => "/min",
        101 => "/s",
        102 => "psi/°F",
        103 => "rad",
        184 => "rad/s",
        104 => "rpm",
        185 => "m²/N",
        189 => "W/(m·°K)",
        141 => "W/(m²·°K)",
        207 => "‰",
        208 => "g/g",
        209 => "kg/kg",
        210 => "g/kg",
        211 => "mg/g",
        212 => "mg/kg",
        213 => "g/mL",
        214 => "g/L",
        215 => "mg/L",
        216 => "µg/L",
        217 => "g/m³",
        218 => "mg/m³",
        219 => "µg/m³",
        220 => "ng/m³",
        221 => "g/cm³",
        222 => "Bq",
        223 => "kBq",
        224 => "MBq",
        225 => "Gy",
        226 => "mGy",
        227 => "µGy",
        228 => "Sv",
        229 => "mSv",
        230 => "µSv",
        231 => "µSv/h",
        47814 => "mrem",
        47815 => "mrem/h",
        232 => "dB(A)",
        233 => "NTU",
        234 => "pH",
        235 => "g/m²",
        236 => "min/°K",

        _ => return format!("Units({})", unit_id),
    }.to_string()
}

fn is_io_object(obj_type: ObjectType) -> bool {
    matches!(
        obj_type,
        ObjectType::AnalogInput
        | ObjectType::AnalogOutput
        | ObjectType::AnalogValue
        | ObjectType::BinaryInput
        | ObjectType::BinaryOutput
        | ObjectType::BinaryValue
        | ObjectType::MultiStateInput
        | ObjectType::MultiStateOutput
        | ObjectType::MultiStateValue
    )
}

fn format_object_type(obj_type: &ObjectType) -> String {
    match obj_type {
        ObjectType::AnalogInput => "Analog Inputs",
        ObjectType::AnalogOutput => "Analog Outputs",
        ObjectType::AnalogValue => "Analog Values",
        ObjectType::BinaryInput => "Binary Inputs",
        ObjectType::BinaryOutput => "Binary Outputs",
        ObjectType::BinaryValue => "Binary Values",
        ObjectType::MultiStateInput => "Multistate Inputs",
        ObjectType::MultiStateOutput => "Multistate Outputs",
        ObjectType::MultiStateValue => "Multistate Values",
        _ => "Other",
    }.to_string()
}