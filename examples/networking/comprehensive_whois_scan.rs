//! Comprehensive BACnet Who-Is Scan
//!
//! This example performs a complete BACnet network scan to discover all devices
//! and their objects, including devices behind routers on different networks.

use bacnet_rs::{
    service::{WhoIsRequest, IAmRequest, ReadPropertyResponse},
    network::{Npdu, NetworkAddress},
    datalink::bip::{BvlcHeader, BvlcFunction},
    vendor::get_vendor_name,
    object::{ObjectType, PropertyIdentifier},
    encoding::{
        decode_application_tag, decode_unsigned, 
        decode_real, decode_enumerated, decode_signed,
        ApplicationTag
    },
};
use encoding_rs::{UTF_16BE, UTF_8};
use std::{
    net::{SocketAddr, UdpSocket},
    time::{Duration, Instant},
    collections::HashMap,
    sync::atomic::{AtomicU8, Ordering},
    io::Write,
};

const BACNET_PORT: u16 = 0xBAC0; // 47808

#[derive(Debug, Clone)]
struct BACnetDevice {
    device_id: u32,
    network_number: u16,
    mac_address: Vec<u8>,
    socket_addr: SocketAddr,
    vendor_id: u32,
    vendor_name: String,
    // Device properties
    model_name: Option<String>,
    firmware_revision: Option<String>,
    max_apdu: u16,
    segmentation: u8,
    // Objects in this device
    objects: Vec<BACnetObject>,
}

#[derive(Debug, Clone)]
struct BACnetObject {
    object_type: ObjectType,
    instance: u32,
    name: Option<String>,
    present_value: Option<String>,
    description: Option<String>,
    units: Option<String>,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("===========================================");
    println!("  BACnet Comprehensive Network Scan");
    println!("===========================================\n");


    // Bind to standard BACnet port
    let socket = match UdpSocket::bind("0.0.0.0:47808") {
        Ok(s) => s,
        Err(_) => {
            println!("Standard port busy, using alternative port...");
            UdpSocket::bind("0.0.0.0:0")?
        }
    };

    socket.set_broadcast(true)?;
    socket.set_read_timeout(Some(Duration::from_millis(100)))?;

    println!("📡 Listening on {}", socket.local_addr()?);
    println!("🔍 Starting network discovery...\n");

    // Get all broadcast addresses for all interfaces
    let broadcast_addresses = get_broadcast_addresses();

    // Step 1: Discover routers
    println!("\nStep 1: Router Discovery");
    println!("========================");
    let routers = discover_routers(&socket, &broadcast_addresses)?;

    if routers.is_empty() {
        println!("ℹ️  No routers found on the network");
    } else {
        println!("🔗 Found {} router(s):", routers.len());
        for (network, addr) in &routers {
            println!("   Network {:>4}: Router at {}", network, addr);
        }
    }

    // Step 2: Discover all devices
    println!("\nStep 2: Device Discovery");
    println!("========================");
    let mut devices = HashMap::new();

    // Global broadcast first
    println!("🌐 Performing broadcast discovery on all interfaces...");
    discover_devices_global(&socket, &mut devices, &broadcast_addresses)?;

    // Then directed discovery for each known network
    for (network, _) in &routers {
        println!("🎯 Scanning network {}...", network);
        discover_devices_on_network(&socket, *network, &mut devices, &broadcast_addresses)?;
    }

    if devices.is_empty() {
        println!("❌ No BACnet devices found");
        return Ok(());
    }

    // Show a dot for each device discovered
    for _ in 0..devices.len() {
        print!(".");
        std::io::Write::flush(&mut std::io::stdout())?;
    }
    println!();

    println!("📱 Discovered {} device(s):", devices.len());
    for device in devices.values() {
        let network_info = if device.network_number == 0 {
            "Local".to_string()
        } else {
            format!("Network {}", device.network_number)
        };
        println!("   Device {:>4}: {} ({})", device.device_id, device.vendor_name, network_info);
    }

    // Step 3: Read device properties and objects
    println!("\nStep 3: Detailed Device Analysis");
    println!("=================================");

    for device in devices.values_mut() {
        analyze_device(&socket, device)?;
    }

    // Step 4: Display comprehensive summary
    println!("\n");
    println!("===========================================");
    println!("           NETWORK SCAN SUMMARY");
    println!("===========================================");

    display_comprehensive_summary(&devices);

    Ok(())
}

fn get_broadcast_addresses() -> Vec<SocketAddr> {
    use std::net::IpAddr;

    let mut broadcast_addresses = Vec::new();

    // Try to get network interfaces
    if let Ok(interfaces) = if_addrs::get_if_addrs() {
        for interface in interfaces {
            match interface.addr {
                if_addrs::IfAddr::V4(ref addr) => {
                    if !addr.ip.is_loopback() {
                        // Add interface-specific broadcast address
                        let broadcast = if let Some(broadcast) = addr.broadcast {
                            broadcast
                        } else {
                            // Calculate broadcast address
                            let ip_u32 = u32::from(addr.ip);
                            let mask_u32 = u32::from(addr.netmask);
                            let broadcast_u32 = ip_u32 | !mask_u32;
                            std::net::Ipv4Addr::from(broadcast_u32)
                        };
                        broadcast_addresses.push(SocketAddr::new(IpAddr::V4(broadcast), BACNET_PORT));
                    }
                }
                _ => {} // Ignore IPv6 and other address types
            }
        }
    }

    // Always include global broadcast
    broadcast_addresses.push(SocketAddr::new(
        IpAddr::V4(std::net::Ipv4Addr::new(255, 255, 255, 255)),
        BACNET_PORT
    ));

    // Remove duplicates and sort for consistent output
    broadcast_addresses.sort();
    broadcast_addresses.dedup();

    println!("🌐 Found {} broadcast addresses:", broadcast_addresses.len());
    for addr in &broadcast_addresses {
        println!("   - {}", addr);
    }

    broadcast_addresses
}

fn discover_routers(socket: &UdpSocket, broadcast_addresses: &[SocketAddr]) -> Result<HashMap<u16, SocketAddr>, Box<dyn std::error::Error>> {
    let mut routers = HashMap::new();

    // Create Who-Is-Router-To-Network NPDU
    let mut npdu = Npdu::new();
    npdu.control.network_message = true;

    let network_msg = vec![0x01]; // Who-Is-Router-To-Network
    let npdu_bytes = encode_npdu_with_data(&npdu, &network_msg);

    let header = BvlcHeader::new(BvlcFunction::OriginalBroadcastNpdu, 4 + npdu_bytes.len() as u16);
    let mut frame = header.encode();
    frame.extend_from_slice(&npdu_bytes);

    // Send to all broadcast addresses
    for addr in broadcast_addresses {
        let _ = socket.send_to(&frame, addr);
    }

    // Listen for I-Am-Router-To-Network responses
    let start = Instant::now();
    let mut buffer = [0u8; 1500];

    while start.elapsed() < Duration::from_secs(3) {
        match socket.recv_from(&mut buffer) {
            Ok((len, src_addr)) => {
                if len > 4 {
                    let npdu_data = &buffer[4..len];
                    if let Ok((npdu, offset)) = Npdu::decode(npdu_data) {
                        if npdu.is_network_message() && npdu_data.len() > offset && npdu_data[offset] == 0x02 {
                            let mut idx = offset + 1;
                            while idx + 1 < npdu_data.len() {
                                let network = u16::from_be_bytes([npdu_data[idx], npdu_data[idx + 1]]);
                                routers.insert(network, src_addr);
                                idx += 2;
                            }
                        }
                    }
                }
            }
            Err(_) => {}
        }
    }

    Ok(routers)
}

fn discover_devices_global(socket: &UdpSocket, devices: &mut HashMap<u32, BACnetDevice>, broadcast_addresses: &[SocketAddr]) -> Result<(), Box<dyn std::error::Error>> {
    let who_is = WhoIsRequest::new();
    let mut who_is_data = Vec::new();
    who_is.encode(&mut who_is_data)?;

    let mut apdu = vec![0x10, 0x08]; // Unconfirmed-Request, Who-Is
    apdu.extend_from_slice(&who_is_data);

    let npdu = Npdu::global_broadcast();
    let npdu_bytes = encode_npdu_with_data(&npdu, &apdu);

    let header = BvlcHeader::new(BvlcFunction::OriginalBroadcastNpdu, 4 + npdu_bytes.len() as u16);
    let mut frame = header.encode();
    frame.extend_from_slice(&npdu_bytes);

    // Send to all broadcast addresses
    for addr in broadcast_addresses {
        let _ = socket.send_to(&frame, addr);
    }

    collect_i_am_responses(socket, devices, Duration::from_secs(5))?;
    Ok(())
}

fn discover_devices_on_network(socket: &UdpSocket, network: u16, devices: &mut HashMap<u32, BACnetDevice>, broadcast_addresses: &[SocketAddr]) -> Result<(), Box<dyn std::error::Error>> {
    let who_is = WhoIsRequest::new();
    let mut who_is_data = Vec::new();
    who_is.encode(&mut who_is_data)?;

    let mut apdu = vec![0x10, 0x08]; // Unconfirmed-Request, Who-Is
    apdu.extend_from_slice(&who_is_data);

    let mut npdu = Npdu::new();
    npdu.control.destination_present = true;
    npdu.destination = Some(NetworkAddress {
        network,
        address: vec![], // Broadcast on the remote network
    });
    npdu.hop_count = Some(255);

    let npdu_bytes = encode_npdu_with_data(&npdu, &apdu);

    let header = BvlcHeader::new(BvlcFunction::OriginalBroadcastNpdu, 4 + npdu_bytes.len() as u16);
    let mut frame = header.encode();
    frame.extend_from_slice(&npdu_bytes);

    // Send to all broadcast addresses
    for addr in broadcast_addresses {
        let _ = socket.send_to(&frame, addr);
    }

    collect_i_am_responses(socket, devices, Duration::from_secs(3))?;
    Ok(())
}

fn collect_i_am_responses(socket: &UdpSocket, devices: &mut HashMap<u32, BACnetDevice>, timeout: Duration) -> Result<(), Box<dyn std::error::Error>> {
    let start = Instant::now();
    let mut buffer = [0u8; 1500];

    while start.elapsed() < timeout {
        match socket.recv_from(&mut buffer) {
            Ok((len, src_addr)) => {
                if len > 4 {
                    let npdu_data = &buffer[4..len];
                    if let Ok((npdu, offset)) = Npdu::decode(npdu_data) {
                        if !npdu.is_network_message() && npdu_data.len() > offset {
                            let apdu_data = &npdu_data[offset..];
                            if apdu_data.len() > 1 && apdu_data[0] == 0x10 && apdu_data[1] == 0x00 {
                                if let Ok(i_am) = IAmRequest::decode(&apdu_data[2..]) {
                                    let device_id = i_am.device_identifier.instance;
                                    let vendor_id = i_am.vendor_identifier;

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

                                        // Only insert if device doesn't already exist
                                        if !devices.contains_key(&device_id) {
                                            let device = BACnetDevice {
                                                device_id,
                                                network_number,
                                                mac_address,
                                                socket_addr: src_addr,
                                                vendor_id,
                                                vendor_name: get_vendor_name(vendor_id as u16).unwrap_or("Unknown").to_string(),
                                                model_name: None,
                                                firmware_revision: None,
                                                max_apdu: i_am.max_apdu_length_accepted as u16,
                                                segmentation: i_am.segmentation_supported as u8,
                                                objects: Vec::new(),
                                            };

                                            devices.insert(device_id, device);
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
            Err(_) => {}
        }
    }

    Ok(())
}

fn analyze_device(socket: &UdpSocket, device: &mut BACnetDevice) -> Result<(), Box<dyn std::error::Error>> {
    println!("\n📱 Analyzing Device {} - {}", device.device_id, device.vendor_name);
    let network_info = if device.network_number == 0 {
        format!("Local, Address: {}", device.socket_addr)
    } else {
        format!("Network {}, Address: {}", device.network_number, device.socket_addr)
    };
    println!("   Network: {}", network_info);

    // Read basic device properties
    println!("   📋 Reading device properties...");

    // Read model name
    match read_device_property(socket, device, PropertyIdentifier::ModelName as u32) {
        Ok(model) => {
            if let Ok(parsed_model) = parse_string_from_response(&model) {
                device.model_name = Some(parsed_model);
            }
        }
        Err(_) => {
            // Try alternative approach
            if let Ok(model) = read_device_property_alternative(socket, device, PropertyIdentifier::ModelName as u32) {
                if let Ok(parsed_model) = parse_string_from_response(&model) {
                    device.model_name = Some(parsed_model);
                }
            }
        }
    }

    // Read firmware revision
    if let Ok(firmware) = read_device_property(socket, device, PropertyIdentifier::ApplicationSoftwareVersion as u32) {
        if let Ok(parsed_firmware) = parse_string_from_response(&firmware) {
            device.firmware_revision = Some(parsed_firmware);
        }
    }

    // Show device name property
    if let Ok(device_name) = read_device_property(socket, device, PropertyIdentifier::ObjectName as u32) {
        if let Ok(parsed_name) = parse_string_from_response(&device_name) {
            println!("   Device Name: \"{}\"", parsed_name);
        }
    }

    // Read object list
    println!("   🔍 Discovering objects...");
    let object_count = match read_object_list(socket, device) {
        Ok(count) => {
            println!("      Found {} objects using standard method", count);
            count
        }
        Err(_) => {
            // Try different approaches to read object list
            match try_read_object_list_multiple_approaches(socket, device) {
                Ok(count) => {
                    println!("      Found {} objects using alternative method", count);
                    count
                }
                Err(_) => 0
            }
        }
    };

    // Read details for each object if we found any
    if object_count > 1 { // More than just the device object
        println!("      Reading object details using ReadPropertyMultiple...
      Progress: ");
        let objects_to_read = device.objects.len(); // Read all objects
        let use_rpm_all = true; // Option to use ReadPropertyMultiple with ALL


        for i in 0..objects_to_read {
            // Show progress every 5 objects for better feedback
            if i % 5 == 0 {
                print!("\r      Progress: {}/{} objects scanned", i, objects_to_read);
                std::io::stdout().flush().unwrap();
            }
            
            let mut used_rpm = false;
            
            // Try ReadPropertyMultiple with ALL first
            if use_rpm_all {
                if let Ok(all_props) = read_all_properties_rpm(socket, device, &device.objects[i]) {
                    // Check if we got properties
                    if !all_props.is_empty() {
                        used_rpm = true;
                        // Successfully got properties
                        
                        // Debug for BELIMO device to see what properties are returned
                        if device.network_number == 2001 && !all_props.contains_key(&77) {
                            println!("        DEBUG: {} {} missing ObjectName, got properties: {:?}", 
                                     object_type_name(device.objects[i].object_type),
                                     device.objects[i].instance,
                                     all_props.keys().collect::<Vec<_>>());
                        }
                    }
                    
                    // Extract properties from the response
                    if let Some(name) = all_props.get(&77) { // ObjectName
                        // For RPM with ALL, we get the full string directly
                        // Skip empty or null names
                        if !name.is_empty() && name != "null" {
                            device.objects[i].name = Some(name.clone());
                        }
                    }
                    
                    if let Some(value) = all_props.get(&85) { // PresentValue
                        // Store the raw value string for now
                        device.objects[i].present_value = Some(value.clone());
                    }
                    
                    if let Some(units) = all_props.get(&117) { // Units
                        // Use the existing parse_units_from_response function
                        if let Ok(parsed_units) = parse_units_from_response(units) {
                            device.objects[i].units = Some(parsed_units);
                        } else {
                            device.objects[i].units = Some(units.clone());
                        }
                    }
                }
            }

            // DISABLED: No fallback to individual ReadProperty - only use ReadPropertyMultiple
            // This ensures we only use ReadPropertyMultiple as requested

            // If we couldn't get a name, use a generic name based on object type and instance
            if device.objects[i].name.is_none() {
                let obj = &device.objects[i];
                let default_name = format!("{}_{}", object_type_name(obj.object_type), obj.instance);
                device.objects[i].name = Some(default_name);
            }

            // Only add delay if we used individual ReadProperty (not for successful ReadPropertyMultiple)
            if !used_rpm {
                std::thread::sleep(Duration::from_millis(50)); // Small delay between reads
            }
        }
        // Clear the progress line and show completion
        print!("\r      Progress: {}/{} objects scanned - Complete!\n", objects_to_read, objects_to_read);
        std::io::stdout().flush().unwrap();
    }
    
    // Display objects
    if !device.objects.is_empty() {
        println!("   OBJECTS ({} total):", device.objects.len());
        
        // Track objects where property ID 8 (ALL) didn't work
        let mut objects_without_names = Vec::new();
        
        // Show ALL objects - always display at minimum the name
        for (i, obj) in device.objects.iter().enumerate() {
            let type_name = object_type_name(obj.object_type);
            let default_name = format!("{}_{}", type_name, obj.instance);
            let has_default_name = obj.name.as_ref().map_or(false, |n| n == &default_name);
            let obj_name = obj.name.as_deref().unwrap_or(&default_name);
            
            // Track objects using default names (property ID 8 didn't return ObjectName)
            if has_default_name || obj.name.is_none() {
                objects_without_names.push((type_name, obj.instance));
            }
            
            // Always show object type, instance and name
            print!("      {:3}. {} {:>3} - {}", 
                i + 1, 
                type_name, 
                obj.instance, 
                obj_name
            );
            
            // If there's a present value, add it
            if let Some(value) = &obj.present_value {
                if !value.is_empty() {
                    print!(" = {}", value);
                    
                    // If there's also units, add them
                    if let Some(units) = &obj.units {
                        if !units.is_empty() && units != "no-units" {
                            print!(" {}", units);
                        }
                    }
                }
            }
            
            println!();
        }
        
        // Report objects where property ID 8 (ALL) didn't work
        if !objects_without_names.is_empty() {
            println!("\n   WARNING: Objects where property ID 8 (ALL) did not return ObjectName:");
            for (obj_type, instance) in objects_without_names {
                println!("      - {} {}", obj_type, instance);
            }
        }
    } else {
        println!("   OBJECTS: Unable to read object list");
    }

    Ok(())
}

// Try multiple approaches to read object list
fn try_read_object_list_multiple_approaches(socket: &UdpSocket, device: &mut BACnetDevice) -> Result<usize, Box<dyn std::error::Error>> {
    // Method 1: Try reading the array length first
    match read_property_with_array_index(socket, device, PropertyIdentifier::ObjectList as u32, 0) {
        Ok(length_response) => {
            println!("      Got object list length response (len: {}), parsing...", length_response.len());

            // Check if response starts with 0x (hex encoded)
            if length_response.starts_with("0x") && length_response.len() >= 10 {
                println!("        Warning: Got hex response for array length");
            }

            // Try to extract length from different response formats
            let length = if let Ok(len) = length_response.parse::<u32>() {
                len
            } else {
                // Try to extract a number from the response
                100 // Default max if we can't parse length
            };

            // Read each object identifier by array index
            for i in 1..=std::cmp::min(length, 1000) { // Limit to 1000 objects
                match read_property_with_array_index(socket, device, PropertyIdentifier::ObjectList as u32, i) {
                    Ok(obj_response) => {
                        // Parse different response formats
                        let mut parsed = false;

                        // Format 1: "Object(type,instance)"
                        if let Some(captures) = obj_response.strip_prefix("Object(").and_then(|s| s.strip_suffix(")")) {
                            let parts: Vec<&str> = captures.split(',').collect();
                            if parts.len() == 2 {
                                if let (Ok(obj_type), Ok(instance)) = (parts[0].parse::<u16>(), parts[1].parse::<u32>()) {
                                    if let Ok(object_type) = ObjectType::try_from(obj_type) {
                                        let obj = BACnetObject {
                                            object_type,
                                            instance,
                                            name: None,
                                            present_value: None,
                                            description: None,
                                            units: None,
                                        };
                                        device.objects.push(obj);
                                        parsed = true;
                                    }
                                }
                            }
                        }

                        // Format 2: "Objects: [TYPE:instance]"
                        if !parsed && obj_response.starts_with("Objects: [") && obj_response.ends_with("]") {
                            let objects_str = &obj_response[10..obj_response.len()-1];
                            if let Some(colon_pos) = objects_str.find(':') {
                                let type_str = &objects_str[..colon_pos];
                                let instance_str = &objects_str[colon_pos+1..];

                                if let Ok(instance) = instance_str.parse::<u32>() {
                                    let object_type = match type_str {
                                        "DEV" => Some(ObjectType::Device),
                                        "AI" => Some(ObjectType::AnalogInput),
                                        "AO" => Some(ObjectType::AnalogOutput),
                                        "AV" => Some(ObjectType::AnalogValue),
                                        "BI" => Some(ObjectType::BinaryInput),
                                        "BO" => Some(ObjectType::BinaryOutput),
                                        "BV" => Some(ObjectType::BinaryValue),
                                        "MSI" => Some(ObjectType::MultiStateInput),
                                        "MSO" => Some(ObjectType::MultiStateOutput),
                                        "MSV" => Some(ObjectType::MultiStateValue),
                                        _ => None,
                                    };

                                    if let Some(obj_type) = object_type {
                                        let obj = BACnetObject {
                                            object_type: obj_type,
                                            instance,
                                            name: None,
                                            present_value: None,
                                            description: None,
                                            units: None,
                                        };
                                        device.objects.push(obj);
                                        parsed = true;
                                    }
                                }
                            }
                        }

                    }
                    Err(_) => {
                        // Stop on first error, assuming we've reached the end
                        break;
                    }
                }
                std::thread::sleep(Duration::from_millis(50)); // Small delay between reads
            }

            if !device.objects.is_empty() {
                return Ok(device.objects.len());
            }
        }
        Err(_) => {}
    }

    // Method 2: Try reading the entire object list as a property
    match read_device_property_simple(socket, device, PropertyIdentifier::ObjectList as u32) {
        Ok(response) => {
            println!("      Got object list response (len: {}), parsing...", response.len());

            // Check if response starts with 0x (hex encoded)
            if response.starts_with("0x") && response.len() > 10 {
                println!("        Warning: Got non-hex response data");
            }

            // Try to parse as object identifiers
            if let Ok(objects) = parse_object_identifiers_from_response(&response) {
                println!("      Successfully parsed {} objects from response", objects.len());
                for obj_id in objects {
                    let obj = BACnetObject {
                        object_type: obj_id.object_type,
                        instance: obj_id.instance,
                        name: None,
                        present_value: None,
                        description: None,
                        units: None,
                    };
                    device.objects.push(obj);
                }
                return Ok(device.objects.len());
            } else {
                println!("      Failed to parse object list response");
            }
        }
        Err(_) => {}
    }

    Err("Could not read object list using any method".into())
}

fn read_device_property(socket: &UdpSocket, device: &BACnetDevice, property_id: u32) -> Result<String, Box<dyn std::error::Error>> {
    static INVOKE_ID: AtomicU8 = AtomicU8::new(1);
    let invoke_id = INVOKE_ID.fetch_add(1, Ordering::SeqCst);
    let invoke_id = if invoke_id == 0 { 1 } else { invoke_id }; // Never use 0

    // Create ReadProperty request following the official BACnet C stack implementation
    let mut apdu = Vec::new();

    // APDU Header (4 bytes) - following rp_encode_apdu()
    apdu.push(0x00); // PDU_TYPE_CONFIRMED_SERVICE_REQUEST
    apdu.push(0x05); // encode_max_segs_max_apdu(0, MAX_APDU) - no segmentation, 1476 bytes
    apdu.push(invoke_id); // invoke_id
    apdu.push(0x0C); // SERVICE_CONFIRMED_READ_PROPERTY (12)

    // ReadProperty Service Data - following read_property_request_encode()
    // Context tag 0: Object Identifier (BACnetObjectIdentifier)
    // Encode as 4-byte object identifier: (object_type << 22) | instance
    let object_type = ObjectType::Device as u32; // 8
    let object_id = (object_type << 22) | (device.device_id & 0x3FFFFF);
    apdu.push(0x0C); // Context tag [0], length 4
    apdu.extend_from_slice(&object_id.to_be_bytes());

    // Context tag 1: Property Identifier (BACnetPropertyIdentifier)
    // Encode as enumerated value
    if property_id <= 255 {
        apdu.push(0x19); // Context tag [1], length 1
        apdu.push(property_id as u8);
    } else if property_id <= 65535 {
        apdu.push(0x1A); // Context tag [1], length 2
        apdu.extend_from_slice(&(property_id as u16).to_be_bytes());
    } else {
        apdu.push(0x1C); // Context tag [1], length 4
        apdu.extend_from_slice(&property_id.to_be_bytes());
    }

    send_request_and_get_response(socket, device, &apdu, invoke_id)
}

fn read_device_property_simple(socket: &UdpSocket, device: &BACnetDevice, property_id: u32) -> Result<String, Box<dyn std::error::Error>> {
    static INVOKE_ID: AtomicU8 = AtomicU8::new(100);
    let invoke_id = INVOKE_ID.fetch_add(1, Ordering::SeqCst);
    let invoke_id = if invoke_id == 0 { 1 } else { invoke_id };

    // Simpler APDU construction
    let mut apdu = Vec::new();
    apdu.push(0x00); // Confirmed-Request
    apdu.push(0x05); // Max segments/APDU
    apdu.push(invoke_id);
    apdu.push(0x0C); // ReadProperty

    // Object ID for device
    let obj_id = ((ObjectType::Device as u32) << 22) | (device.device_id & 0x3FFFFF);
    apdu.push(0x0C); // Context tag 0, length 4
    apdu.extend_from_slice(&obj_id.to_be_bytes());

    // Property ID
    apdu.push(0x19); // Context tag 1, length 1
    apdu.push(property_id as u8);

    send_request_and_get_response(socket, device, &apdu, invoke_id)
}

fn read_device_property_alternative(socket: &UdpSocket, device: &BACnetDevice, property_id: u32) -> Result<String, Box<dyn std::error::Error>> {
    static INVOKE_ID: AtomicU8 = AtomicU8::new(150);
    let invoke_id = INVOKE_ID.fetch_add(1, Ordering::SeqCst);
    let invoke_id = if invoke_id == 0 { 1 } else { invoke_id };

    // Alternative encoding - try different max APDU
    let mut apdu = Vec::new();
    apdu.push(0x00); // Confirmed-Request
    apdu.push(0x00); // No segmentation, 50 byte APDU
    apdu.push(invoke_id);
    apdu.push(0x0C); // ReadProperty

    // Object ID for device
    let obj_id = ((ObjectType::Device as u32) << 22) | (device.device_id & 0x3FFFFF);
    apdu.push(0x0C); // Context tag 0, length 4
    apdu.extend_from_slice(&obj_id.to_be_bytes());

    // Property ID
    apdu.push(0x19); // Context tag 1, length 1
    apdu.push(property_id as u8);

    send_request_and_get_response(socket, device, &apdu, invoke_id)
}

fn read_property_with_array_index(socket: &UdpSocket, device: &BACnetDevice, property_id: u32, array_index: u32) -> Result<String, Box<dyn std::error::Error>> {
    static INVOKE_ID: AtomicU8 = AtomicU8::new(50);
    let invoke_id = INVOKE_ID.fetch_add(1, Ordering::SeqCst);
    let invoke_id = if invoke_id == 0 { 1 } else { invoke_id }; // Never use 0

    // Create ReadProperty request following the official BACnet C stack implementation
    let mut apdu = Vec::new();

    // APDU Header (4 bytes) - following rp_encode_apdu()
    apdu.push(0x00); // PDU_TYPE_CONFIRMED_SERVICE_REQUEST
    apdu.push(0x05); // encode_max_segs_max_apdu(0, MAX_APDU) - no segmentation, 1476 bytes
    apdu.push(invoke_id); // invoke_id
    apdu.push(0x0C); // SERVICE_CONFIRMED_READ_PROPERTY (12)

    // ReadProperty Service Data - following read_property_request_encode()
    // Context tag 0: Object Identifier (BACnetObjectIdentifier)
    // Encode as 4-byte object identifier: (object_type << 22) | instance
    let object_type = ObjectType::Device as u32; // 8
    let object_id = (object_type << 22) | (device.device_id & 0x3FFFFF);
    apdu.push(0x0C); // Context tag [0], length 4
    apdu.extend_from_slice(&object_id.to_be_bytes());

    // Context tag 1: Property Identifier (BACnetPropertyIdentifier)
    // Encode as enumerated value
    if property_id <= 255 {
        apdu.push(0x19); // Context tag [1], length 1
        apdu.push(property_id as u8);
    } else if property_id <= 65535 {
        apdu.push(0x1A); // Context tag [1], length 2
        apdu.extend_from_slice(&(property_id as u16).to_be_bytes());
    } else {
        apdu.push(0x1C); // Context tag [1], length 4
        apdu.extend_from_slice(&property_id.to_be_bytes());
    }

    // Context tag 2: Property Array Index (optional)
    if array_index <= 255 {
        apdu.push(0x29); // Context tag [2], length 1
        apdu.push(array_index as u8);
    } else if array_index <= 65535 {
        apdu.push(0x2A); // Context tag [2], length 2
        apdu.extend_from_slice(&(array_index as u16).to_be_bytes());
    } else {
        apdu.push(0x2C); // Context tag [2], length 4
        apdu.extend_from_slice(&array_index.to_be_bytes());
    }

    send_request_and_get_response(socket, device, &apdu, invoke_id)
}

fn read_object_property_simple(socket: &UdpSocket, device: &BACnetDevice, object: &BACnetObject, property_id: u32) -> Result<String, Box<dyn std::error::Error>> {
    static INVOKE_ID: AtomicU8 = AtomicU8::new(180);
    let invoke_id = INVOKE_ID.fetch_add(1, Ordering::SeqCst);
    let invoke_id = if invoke_id == 0 { 1 } else { invoke_id };

    // Simple APDU construction for object properties
    let mut apdu = Vec::new();
    apdu.push(0x00); // Confirmed-Request
    apdu.push(0x05); // Max segments/APDU
    apdu.push(invoke_id);
    apdu.push(0x0C); // ReadProperty

    // Object ID
    let obj_id = ((object.object_type as u32) << 22) | (object.instance & 0x3FFFFF);
    apdu.push(0x0C); // Context tag 0, length 4
    apdu.extend_from_slice(&obj_id.to_be_bytes());

    // Property ID
    apdu.push(0x19); // Context tag 1, length 1
    apdu.push(property_id as u8);

    send_request_and_get_response(socket, device, &apdu, invoke_id)
}


fn read_all_properties_rpm(socket: &UdpSocket, device: &BACnetDevice, object: &BACnetObject) -> Result<HashMap<u32, String>, Box<dyn std::error::Error>> {
    static INVOKE_ID: AtomicU8 = AtomicU8::new(100);
    let invoke_id = INVOKE_ID.fetch_add(1, Ordering::SeqCst);
    let invoke_id = if invoke_id == 0 { 1 } else { invoke_id };

    // Create ReadPropertyMultiple request with ALL property
    let mut apdu = Vec::new();
    apdu.push(0x02); // Confirmed-Request (with segmentation bit)
    apdu.push(0x75); // Segmentation accepted, max APDU 1476
    apdu.push(invoke_id);
    apdu.push(0x0E); // ReadPropertyMultiple service (14)

    // Object ID
    let obj_id = ((object.object_type as u32) << 22) | (object.instance & 0x3FFFFF);
    apdu.push(0x0C); // Context tag 0, length 4
    apdu.extend_from_slice(&obj_id.to_be_bytes());

    // Property list - request ALL properties
    apdu.push(0x1E); // Opening tag 1 (property list)
    apdu.push(0x09); // Context tag 0, unsigned int, length 1
    apdu.push(8);    // Property ID 8 = ALL
    apdu.push(0x1F); // Closing tag 1

    // Use shorter timeout for RPM requests to avoid getting stuck
    // Adjust timeout based on device - some devices are slower
    let timeout = if device.device_id == 5047 {
        Duration::from_millis(150) // Even shorter timeout for device 5047
    } else {
        Duration::from_millis(250)
    };
    match send_request_and_get_response_with_timeout(socket, device, &apdu, invoke_id, timeout) {
        Ok(response) => {
            // Debug for BELIMO device
            if device.network_number == 2001 {
                if response.starts_with("0x50") {
                    println!("        DEBUG: BELIMO device returned error response for {} {}", 
                             object_type_name(object.object_type), object.instance);
                } else if response.len() > 10 {
                    // Check if this looks like a property list response
                    if response.contains("2a01") || response.contains("2a02") {
                        println!("        DEBUG: BELIMO {} {} returned property list format", 
                                 object_type_name(object.object_type), object.instance);
                    }
                }
            }
            parse_rpm_all_response(&response)
        }
        Err(e) => {
            // Debug errors for BELIMO device
            if device.network_number == 2001 {
                println!("        DEBUG: BELIMO device RPM request failed for {} {}: {}", 
                         object_type_name(object.object_type), object.instance, e);
            }
            // Return empty map on error
            Ok(HashMap::new())
        }
    }
}


fn parse_rpm_all_response(data: &str) -> Result<HashMap<u32, String>, Box<dyn std::error::Error>> {
    let mut properties = HashMap::new();
    
    if data.starts_with("0x") {
        let hex_str = &data[2..];
        if let Ok(bytes) = decode_hex(hex_str) {
            // Check for error PDU
            if bytes.len() > 0 && bytes[0] == 0x50 {
                return Ok(properties);
            }
            
            // Debug: Show first 100 bytes for problematic responses
            if bytes.len() > 20 && bytes.windows(2).any(|w| w[0] > 127 || w[1] > 127) {
                let preview: String = bytes.iter().take(100)
                    .map(|b| format!("{:02x}", b))
                    .collect::<Vec<_>>()
                    .chunks(2)
                    .map(|c| c.join(""))
                    .collect::<Vec<_>>()
                    .join(" ");
                println!("        DEBUG: Raw response with high bytes: {}", preview);
            }
            
            // Skip PDU header if present
            let mut start_pos = 0;
            if bytes.len() > 3 && (bytes[0] == 0x30 || bytes[0] == 0x3C) {
                start_pos = if bytes[0] == 0x30 { 3 } else { 5 }; // Skip PDU header
            }
            
            // For property ID 8 (ALL), we might get a structured response
            // Look for property-value pairs
            let mut i = start_pos;
            let mut in_property_list = false;
            
            while i < bytes.len() {
                // Check for opening/closing tags
                if bytes[i] == 0x1E {
                    in_property_list = true;
                    i += 1;
                    continue;
                }
                if bytes[i] == 0x1F {
                    in_property_list = false;
                    i += 1;
                    continue;
                }
                
                // Look for property identifier context tags (0x28, 0x29, 0x2A, etc)
                if i + 1 < bytes.len() && (bytes[i] & 0xF8) == 0x28 {
                    let prop_id = bytes[i + 1] as u32;
                    i += 2;
                    
                    // Look for the value after property ID
                    if i < bytes.len() && bytes[i] == 0x4E { // Opening tag for value
                        i += 1;
                        
                        // Now decode the actual value
                        if i < bytes.len() {
                            match bytes[i] {
                                0x75 => { // Character string
                                    if let Some((value, consumed)) = decode_any_bacnet_value(&bytes[i..]) {
                                        if prop_id == 77 { // ObjectName
                                            let cleaned: String = value.chars()
                                                .filter(|c| c.is_ascii_graphic() || c.is_ascii_whitespace())
                                                .collect();
                                            if !cleaned.is_empty() {
                                                properties.insert(77, cleaned);
                                            }
                                        }
                                        i += consumed;
                                    } else {
                                        i += 1;
                                    }
                                }
                                0x44 => { // Real
                                    if let Some((value, consumed)) = decode_any_bacnet_value(&bytes[i..]) {
                                        if prop_id == 85 { // PresentValue
                                            properties.insert(85, value);
                                        }
                                        i += consumed;
                                    } else {
                                        i += 1;
                                    }
                                }
                                0x91 => { // Enumerated
                                    if prop_id == 117 { // Units
                                        if let Ok((enum_val, consumed)) = decode_enumerated(&bytes[i..]) {
                                            if let Some(unit_str) = get_units_string(enum_val) {
                                                properties.insert(117, unit_str);
                                            }
                                            i += consumed;
                                        } else {
                                            i += 1;
                                        }
                                    } else {
                                        i += 1;
                                    }
                                }
                                _ => i += 1,
                            }
                        }
                        
                        // Skip closing tag if present
                        if i < bytes.len() && bytes[i] == 0x4F {
                            i += 1;
                        }
                    }
                } else {
                    // Simple scanning for values without property context
                    match bytes[i] {
                        0x75 => { // Character string
                            if let Some((value, consumed)) = decode_any_bacnet_value(&bytes[i..]) {
                                let cleaned: String = value.chars()
                                    .filter(|c| c.is_ascii_graphic() || c.is_ascii_whitespace())
                                    .collect();
                                
                                if !cleaned.is_empty() && cleaned != "null" && !properties.contains_key(&77) {
                                    properties.insert(77, cleaned); // ObjectName
                                }
                                i += consumed;
                            } else {
                                i += 1;
                            }
                        }
                        0x44 => { // Real
                            if let Some((value, consumed)) = decode_any_bacnet_value(&bytes[i..]) {
                                if !properties.contains_key(&85) {
                                    properties.insert(85, value); // PresentValue
                                }
                                i += consumed;
                            } else {
                                i += 1;
                            }
                        }
                        0x91 => { // Enumerated
                            if !properties.contains_key(&117) {
                                if let Ok((enum_val, consumed)) = decode_enumerated(&bytes[i..]) {
                                    if let Some(unit_str) = get_units_string(enum_val) {
                                        properties.insert(117, unit_str); // Units
                                    }
                                    i += consumed;
                                } else {
                                    i += 1;
                                }
                            } else {
                                i += 1;
                            }
                        }
                        _ => i += 1,
                    }
                }
            }
        }
    }
    
    Ok(properties)
}

// Helper function to get units string
fn get_units_string(units_enum: u32) -> Option<String> {
    let unit_str = match units_enum {
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
        200 => "dBmV",
        201 => "dBV",
        170 => "F",
        171 => "H",
        4 => "Ω",
        237 => "Ω·m²/m",
        172 => "Ω·m",
        145 => "mΩ",
        122 => "kΩ",
        123 => "MΩ",
        190 => "μS",
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
        11 => "VAr",
        12 => "kVAr",
        13 => "MVAr",
        176 => "V/°K",
        177 => "V/m",
        14 => "°",
        15 => "power factor",
        178 => "Wb",
        
        // Energy
        238 => "A·s",
        239 => "VA·h",
        240 => "kVA·h",
        241 => "MVA·h",
        242 => "VAr·h",
        243 => "kVAr·h",
        244 => "MVAr·h",
        245 => "V²·h",
        246 => "A²·h",
        16 => "J",
        17 => "kJ",
        125 => "kJ/kg",
        126 => "MJ",
        18 => "W·h",
        19 => "kW·h",
        146 => "MW·h",
        203 => "W·h reactive",
        204 => "kW·h reactive",
        205 => "MW·h reactive",
        20 => "BTU",
        147 => "kBTU",
        148 => "MBTU",
        21 => "therm",
        22 => "ton·h",
        
        // Enthalpy
        23 => "J/kg dry air",
        149 => "kJ/kg dry air",
        150 => "MJ/kg dry air",
        24 => "BTU/lb dry air",
        117 => "BTU/lb",
        
        // Entropy
        127 => "J/°K",
        151 => "kJ/°K",
        152 => "MJ/°K",
        128 => "J/kg·°K",
        
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
        28 => "g water/kg dry air",
        29 => "%RH",
        
        // Length
        194 => "μm",
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
        41 => "ton",
        
        // Mass Flow
        154 => "g/s",
        155 => "g/min",
        42 => "kg/s",
        43 => "kg/min",
        44 => "kg/h",
        119 => "lb/s",
        45 => "lb/min",
        46 => "lb/h",
        156 => "ton/h",
        
        // Power
        132 => "mW",
        47 => "W",
        48 => "kW",
        49 => "MW",
        50 => "BTU/h",
        157 => "kBTU/h",
        247 => "J/h",
        51 => "hp",
        52 => "ton refrigeration",
        
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
        65 => "degree days °C",
        66 => "degree days °F",
        120 => "Δ°F",
        121 => "ΔK",
        
        // Time
        67 => "year",
        68 => "month",
        69 => "week",
        70 => "day",
        71 => "h",
        72 => "min",
        73 => "s",
        158 => "hundredths s",
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
        84 => "ft³/min",
        254 => "million ft³/min",
        191 => "ft³/h",
        248 => "ft³/day",
        47808 => "standard ft³/day",
        47809 => "million standard ft³/day",
        47810 => "thousand ft³/day",
        47811 => "thousand standard ft³/day",
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
        137 => "kW·h/m²",
        138 => "kW·h/ft²",
        250 => "W·h/m³",
        251 => "J/m³",
        139 => "MJ/m²",
        140 => "MJ/ft²",
        252 => "mol%",
        95 => "",
        187 => "N·s",
        188 => "N/m",
        96 => "ppm",
        97 => "ppb",
        253 => "Pa·s",
        98 => "%",
        143 => "% obscuration/ft",
        144 => "% obscuration/m",
        99 => "%/s",
        100 => "/min",
        101 => "/s",
        102 => "psi/°F",
        103 => "rad",
        184 => "rad/s",
        104 => "rpm",
        185 => "m²/N",
        189 => "W/m·K",
        141 => "W/m²·K",
        207 => "‰",
        208 => "g/g",
        209 => "kg/kg",
        210 => "g/kg",
        211 => "mg/g",
        212 => "mg/kg",
        213 => "g/mL",
        214 => "g/L",
        215 => "mg/L",
        216 => "μg/L",
        217 => "g/m³",
        218 => "mg/m³",
        219 => "μg/m³",
        220 => "ng/m³",
        221 => "g/cm³",
        222 => "Bq",
        223 => "kBq",
        224 => "MBq",
        225 => "Gy",
        226 => "mGy",
        227 => "μGy",
        228 => "Sv",
        229 => "mSv",
        230 => "μSv",
        231 => "μSv/h",
        47814 => "mrem",
        47815 => "mrem/h",
        232 => "dBA",
        233 => "NTU",
        234 => "pH",
        235 => "g/m²",
        236 => "min/K",
        
        _ => return None,
    };
    Some(unit_str.to_string())
}

// Decode any BACnet value to string
fn decode_any_bacnet_value(data: &[u8]) -> Option<(String, usize)> {
    if data.is_empty() {
        return None;
    }
    
    // Use the crate's decoding functions
    if let Ok((tag, length, tag_consumed)) = decode_application_tag(data) {
        let total_consumed = tag_consumed + length;
        
        match tag {
            ApplicationTag::Null => Some(("null".to_string(), total_consumed)),
            ApplicationTag::Boolean => {
                let value = if length == 0 { "false" } else { "true" };
                Some((value.to_string(), tag_consumed))
            }
            ApplicationTag::UnsignedInt => {
                if let Ok((value, _)) = decode_unsigned(data) {
                    Some((value.to_string(), total_consumed))
                } else {
                    None
                }
            }
            ApplicationTag::SignedInt => {
                if let Ok((value, _)) = decode_signed(data) {
                    Some((value.to_string(), total_consumed))
                } else {
                    None
                }
            }
            ApplicationTag::Real => {
                if let Ok((value, _)) = decode_real(data) {
                    Some((value.to_string(), total_consumed))
                } else {
                    None
                }
            }
            ApplicationTag::CharacterString => {
                // Use encoding_rs for proper character decoding
                if data.len() >= tag_consumed + length && length > 0 {
                    // Check encoding byte
                    let encoding = data[tag_consumed];
                    let string_data = &data[tag_consumed + 1..tag_consumed + length];
                    
                    // Debug problematic strings
                    if string_data.len() > 0 && string_data.iter().any(|&b| b > 127) {
                        let hex_preview: String = string_data.iter().take(20)
                            .map(|b| format!("{:02x}", b))
                            .collect::<Vec<_>>()
                            .join(" ");
                        println!("          DEBUG: String with encoding {} data: {}", encoding, hex_preview);
                    }
                    
                    let decoded = match encoding {
                        0 => {
                            // UTF-8
                            let (cow, _, had_errors) = UTF_8.decode(string_data);
                            if had_errors {
                                // Try to extract printable ASCII characters
                                string_data.iter()
                                    .filter(|&&b| b >= 32 && b <= 126)
                                    .map(|&b| b as char)
                                    .collect()
                            } else {
                                cow.into_owned()
                            }
                        }
                        4 | 5 => {
                            // UTF-16BE (UCS-2 or UTF-16)
                            let (cow, _, had_errors) = UTF_16BE.decode(string_data);
                            let result = cow.into_owned();
                            // Filter out non-printable characters
                            if had_errors || result.chars().any(|c| c == '\u{fffd}' || (c as u32) > 127 && !c.is_alphabetic()) {
                                // Try to extract ASCII from UTF-16
                                let mut clean = String::new();
                                for chunk in string_data.chunks(2) {
                                    if chunk.len() == 2 {
                                        // Try BE
                                        if chunk[0] == 0 && chunk[1] >= 32 && chunk[1] <= 126 {
                                            clean.push(chunk[1] as char);
                                        }
                                        // Try LE
                                        else if chunk[1] == 0 && chunk[0] >= 32 && chunk[0] <= 126 {
                                            clean.push(chunk[0] as char);
                                        }
                                    }
                                }
                                if !clean.is_empty() {
                                    clean
                                } else {
                                    result
                                }
                            } else {
                                result
                            }
                        }
                        _ => {
                            // Unknown encoding, try to extract printable ASCII
                            string_data.iter()
                                .filter(|&&b| b >= 32 && b <= 126)
                                .map(|&b| b as char)
                                .collect()
                        }
                    };
                    
                    Some((decoded, total_consumed))
                } else {
                    None
                }
            }
            ApplicationTag::Enumerated => {
                if let Ok((value, _)) = decode_enumerated(data) {
                    Some((value.to_string(), total_consumed))
                } else {
                    None
                }
            }
            ApplicationTag::ObjectIdentifier => {
                // Decode object identifier
                if data.len() >= tag_consumed + 4 {
                    let obj_data = &data[tag_consumed..tag_consumed + 4];
                    let obj_id = u32::from_be_bytes([obj_data[0], obj_data[1], obj_data[2], obj_data[3]]);
                    let obj_type = (obj_id >> 22) & 0x3FF;
                    let instance = obj_id & 0x3FFFFF;
                    Some((format!("{}:{}", obj_type, instance), total_consumed))
                } else {
                    None
                }
            }
            _ => {
                // For other types, return hex representation
                let hex_str = hex::encode(&data[tag_consumed..tag_consumed + length]);
                Some((format!("0x{}", hex_str), total_consumed))
            }
        }
    } else {
        None
    }
}

// Keep the old parser for compatibility but simplified
fn parse_rpm_all_response_old(data: &str) -> Result<HashMap<u32, String>, Box<dyn std::error::Error>> {
    let mut properties = HashMap::new();
    
    if data.starts_with("0x") {
        let hex_str = &data[2..];
        if let Ok(bytes) = decode_hex(hex_str) {
            let mut i = 0;
            
            let pdu_type = bytes[0] & 0xF0;
            
            // Handle different PDU types
            if pdu_type == 0x30 { // Complex-ACK
                i = 2; // Skip PDU type and invoke ID to get to service choice
                
                if i < bytes.len() && bytes[i] == 0x0E { // ReadPropertyMultiple ACK
                    i += 1; // Skip service choice
                    
                    // Skip object ID (0x0C)
                    if i + 4 < bytes.len() && bytes[i] == 0x0C {
                        i += 5; // Skip tag and 4 bytes
                        
                        // Look for property list opening tag (0x1E)
                        if i < bytes.len() && bytes[i] == 0x1E {
                            i += 1;
                            
                            // Parse properties until closing tag
                            while i < bytes.len() && bytes[i] != 0x1F {
                                // Property ID (context tag 2)
                                if bytes[i] == 0x29 && i + 1 < bytes.len() {
                                    let prop_id = bytes[i + 1] as u32;
                                    i += 2;
                                } else if bytes[i] == 0x2A && i + 2 < bytes.len() {
                                    // Context tag 2 with length 2 - extended property ID
                                    let prop_id = ((bytes[i + 1] as u32) << 8) | (bytes[i + 2] as u32);
                                    i += 3;
                                    
                                    // Skip opening tag 4E if present
                                    if i < bytes.len() && bytes[i] == 0x4E {
                                        i += 1;
                                    }
                                    
                                    // Parse the value based on tag type
                                    if i < bytes.len() {
                                        let mut value_end = i;
                                        
                                        // Find the closing tag 4F
                                        while value_end < bytes.len() && bytes[value_end] != 0x4F {
                                            value_end += 1;
                                        }
                                        
                                        // Parse value in this range
                                        if value_end > i {
                                            // Parse the entire value using decode_bacnet_value
                                            if let Ok(value) = decode_bacnet_value(&bytes[i..value_end]) {
                                                properties.insert(prop_id, value);
                                            }
                                        }
                                        
                                        // Skip to after closing tag
                                        if value_end < bytes.len() && bytes[value_end] == 0x4F {
                                            i = value_end + 1;
                                        } else {
                                            i = value_end;
                                        }
                                    }
                                } else if bytes[i] == 0x2A && i + 2 < bytes.len() {
                                    // Context tag 2 with length 2 (0x2A) - extended property list
                                    // This contains the count of properties that follow
                                    let count = bytes[i + 1] as usize;
                                    i += 2;
                                    
                                    // Skip the property IDs
                                    while i < bytes.len() && bytes[i] == 0x4E {
                                        i += 1; // Skip opening tag
                                        // Skip enumerated property IDs
                                        if i + 1 < bytes.len() && bytes[i] == 0x91 {
                                            i += 2; // Skip enumerated value
                                        }
                                        if i < bytes.len() && bytes[i] == 0x4F {
                                            i += 1; // Skip closing tag
                                        }
                                    }
                                } else {
                                    i += 1;
                                }
                            }
                        }
                    }
                } else {
                    return Ok(properties);
                }
            } else if pdu_type == 0x50 { // Error
                return Ok(properties);
            } else if pdu_type == 0x60 || pdu_type == 0x70 { // Abort
                return Ok(properties);
            } else if pdu_type == 0x30 && (bytes[0] & 0x08) != 0 { // Segmented Complex-ACK
                // For now, skip segmented responses
                return Ok(properties);
            } else if bytes[0] == 0x3C { // Segmented Complex-ACK
                // This is a segmented response - check if it's the first segment
                if (bytes[0] & 0x04) != 0 { // More segments follow
                    return Ok(properties);
                }
                
                // For segmented responses, the structure is different
                // byte 0: PDU type/flags
                // byte 1: invoke ID  
                // byte 2-3: sequence number and window size
                // byte 4+: service data
                i = 4; // Skip to service data
                
                if i < bytes.len() && bytes[i] == 0x0E { // ReadPropertyMultiple ACK
                    i += 1; // Skip service choice
                    // Continue with normal parsing...
                    // Skip object ID (0x0C)
                    if i + 4 < bytes.len() && bytes[i] == 0x0C {
                        i += 5; // Skip tag and 4 bytes
                        
                        // Look for property list opening tag (0x1E)
                        if i < bytes.len() && bytes[i] == 0x1E {
                            i += 1;
                            
                            // Parse properties until closing tag
                            while i < bytes.len() && bytes[i] != 0x1F {
                                // Property ID (context tag 2)
                                if bytes[i] == 0x29 && i + 1 < bytes.len() {
                                        let prop_id = bytes[i + 1] as u32;
                                        i += 2;
                                        
                                        // Skip opening tag 4E if present
                                        if i < bytes.len() && bytes[i] == 0x4E {
                                            i += 1;
                                        }
                                        
                                        // Parse the value based on tag type
                                        if i < bytes.len() {
                                            let mut value_end = i;
                                            
                                            // Find the closing tag 4F
                                            while value_end < bytes.len() && bytes[value_end] != 0x4F {
                                                value_end += 1;
                                            }
                                            
                                            // Parse value in this range
                                            if value_end > i {
                                                if let Ok(value) = decode_bacnet_value(&bytes[i..value_end]) {
                                                    properties.insert(prop_id, value);
                                                }
                                            }
                                            
                                            // Skip to after closing tag
                                            if value_end < bytes.len() && bytes[value_end] == 0x4F {
                                                i = value_end + 1;
                                            } else {
                                                i = value_end;
                                            }
                                        }
                                } else if bytes[i] == 0x2A && i + 2 < bytes.len() {
                                    // Context tag 2 with length 1 (0x2A) - list of property IDs at end
                                    // Skip the entire list
                                    i += 2;
                                    while i < bytes.len() && bytes[i] == 0x91 {
                                        i += 2; // Skip enumerated values
                                    }
                                } else {
                                    i += 1;
                                }
                            }
                        }
                    }
                }
                return Ok(properties);
            } else {
                return Ok(properties);
            }
        }
    } else {
        // Handle non-hex responses (shouldn't happen with our current implementation)
        return Ok(properties);
    }

    Ok(properties)
}

fn read_object_property(socket: &UdpSocket, device: &BACnetDevice, object: &BACnetObject, property_id: u32) -> Result<String, Box<dyn std::error::Error>> {
    static INVOKE_ID: AtomicU8 = AtomicU8::new(200);
    let invoke_id = INVOKE_ID.fetch_add(1, Ordering::SeqCst);
    let invoke_id = if invoke_id == 0 { 1 } else { invoke_id }; // Never use 0

    // Create ReadProperty request following the official BACnet C stack implementation
    let mut apdu = Vec::new();

    // APDU Header (4 bytes) - following rp_encode_apdu()
    apdu.push(0x00); // PDU_TYPE_CONFIRMED_SERVICE_REQUEST
    apdu.push(0x05); // encode_max_segs_max_apdu(0, MAX_APDU) - no segmentation, 1476 bytes
    apdu.push(invoke_id); // invoke_id
    apdu.push(0x0C); // SERVICE_CONFIRMED_READ_PROPERTY (12)

    // ReadProperty Service Data - following read_property_request_encode()
    // Context tag 0: Object Identifier (BACnetObjectIdentifier)
    // Encode as 4-byte object identifier: (object_type << 22) | instance
    let object_id = ((object.object_type as u32) << 22) | (object.instance & 0x3FFFFF);
    apdu.push(0x0C); // Context tag [0], length 4
    apdu.extend_from_slice(&object_id.to_be_bytes());

    // Context tag 1: Property Identifier (BACnetPropertyIdentifier)
    // Encode as enumerated value
    if property_id <= 255 {
        apdu.push(0x19); // Context tag [1], length 1
        apdu.push(property_id as u8);
    } else if property_id <= 65535 {
        apdu.push(0x1A); // Context tag [1], length 2
        apdu.extend_from_slice(&(property_id as u16).to_be_bytes());
    } else {
        apdu.push(0x1C); // Context tag [1], length 4
        apdu.extend_from_slice(&property_id.to_be_bytes());
    }

    send_request_and_get_response(socket, device, &apdu, invoke_id)
}

fn send_request_and_get_response(socket: &UdpSocket, device: &BACnetDevice, apdu: &[u8], invoke_id: u8) -> Result<String, Box<dyn std::error::Error>> {
    send_request_and_get_response_with_timeout(socket, device, apdu, invoke_id, Duration::from_millis(500))
}

fn send_request_and_get_response_with_timeout(socket: &UdpSocket, device: &BACnetDevice, apdu: &[u8], invoke_id: u8, timeout: Duration) -> Result<String, Box<dyn std::error::Error>> {
    // Create NPDU based on device location
    let npdu = if device.network_number == 0 {
        // Local device
        Npdu::new()
    } else {
        // Remote device
        let mut npdu = Npdu::new();
        npdu.control.destination_present = true;
        npdu.destination = Some(NetworkAddress {
            network: device.network_number,
            address: device.mac_address.clone(),
        });
        npdu.hop_count = Some(255);
        npdu
    };

    let npdu_bytes = encode_npdu_with_data(&npdu, apdu);

    // Create BACnet/IP header
    let header = BvlcHeader::new(BvlcFunction::OriginalUnicastNpdu, 4 + npdu_bytes.len() as u16);
    let mut frame = header.encode();
    frame.extend_from_slice(&npdu_bytes);

    // Send the request
    socket.send_to(&frame, device.socket_addr)?;

    // Wait for response
    let start = Instant::now();
    let mut buffer = [0u8; 1500];

    while start.elapsed() < Duration::from_secs(2) {
        match socket.recv_from(&mut buffer) {
            Ok((len, src_addr)) => {
                if len > 4 {
                    let npdu_data = &buffer[4..len];
                    if let Ok((npdu, offset)) = Npdu::decode(npdu_data) {
                        if !npdu.is_network_message() && npdu_data.len() > offset {
                            let apdu_data = &npdu_data[offset..];
                            let pdu_type = (apdu_data[0] & 0xF0) >> 4;
                            let resp_invoke_id = apdu_data[0] & 0x0F;

                            // Some devices don't echo invoke ID correctly, so accept any response from our target device
                            if resp_invoke_id == (invoke_id & 0x0F) || src_addr == device.socket_addr {
                                if pdu_type == 0x3 { // Complex ACK
                                    // Check service choice
                                    if apdu_data.len() >= 2 {
                                        let service_choice = apdu_data[1];

                                        // For ReadPropertyMultiple responses (service choice 0x0E)
                                        if service_choice == 0x0E {

                                            // Return as hex for parsing
                                            return Ok(format!("0x{}", hex::encode(apdu_data)));
                                        }

                                        // Some devices might respond with ReadProperty (0x0C) even though we sent ReadPropertyMultiple
                                        // This is non-standard but happens in practice
                                        if service_choice == 0x0C && apdu_data.len() > 10 {
                                            // Return as hex for special parsing
                                            return Ok(format!("0x{}", hex::encode(apdu_data)));
                                        }

                                        // For ReadProperty responses (service choice 0x0C)
                                        if service_choice == 0x0C {
                                            // Check if this is likely an object list response by looking for multiple C4 tags
                                            let mut c4_count = 0;
                                            for i in 0..apdu_data.len() {
                                                if apdu_data[i] == 0xC4 {
                                                    c4_count += 1;
                                                }
                                            }
                                            if c4_count > 1 {
                                                // This is likely an object list - return as hex
                                                return Ok(format!("0x{}", hex::encode(apdu_data)));
                                            }

                                            // Try normal decoding
                                            if let Ok(response) = ReadPropertyResponse::decode(&apdu_data[2..]) {
                                                return decode_bacnet_value(&response.property_value);
                                            }
                                        }
                                    }

                                    // For ReadPropertyMultiple, return as hex for proper parsing
                                    return Ok(format!("0x{}", hex::encode(apdu_data)));
                                } else if pdu_type == 0x5 { // Error
                                    if apdu_data.len() >= 4 {
                                        let error_class = apdu_data[2];
                                        let error_code = apdu_data[3];
                                        return Err(format!("BACnet Error: class={}, code={}", error_class, error_code).into());
                                    }
                                    return Err("Device returned error".into());
                                } else if pdu_type == 0x6 || pdu_type == 0x7 { // Abort
                                    if apdu_data.len() >= 2 {
                                        let abort_reason = apdu_data[1];
                                        return Err(format!("BACnet Abort: reason={}", abort_reason).into());
                                    }
                                    return Err("Property not supported (abort)".into());
                                } else {
                                    // Return raw response as hex for unsupported PDU types
                                    return Ok(format!("0x{}", hex::encode(apdu_data)));
                                }
                            }
                        }
                    }
                }
            }
            Err(e) => {
                if e.kind() != std::io::ErrorKind::WouldBlock && e.kind() != std::io::ErrorKind::TimedOut {
                    return Err(Box::new(e));
                }
            }
        }
    }

    Err("Timeout waiting for response".into())
}

fn read_object_list(socket: &UdpSocket, device: &mut BACnetDevice) -> Result<usize, Box<dyn std::error::Error>> {
    // First try to read the entire object list at once
    match read_device_property(socket, device, PropertyIdentifier::ObjectList as u32) {
        Ok(obj_list_data) => {
            match parse_object_list_response(&obj_list_data) {
                Ok(objects) => {
                    println!("      Successfully parsed {} objects from response", objects.len());
                    for obj_id in objects {
                        let obj = BACnetObject {
                            object_type: obj_id.object_type,
                            instance: obj_id.instance,
                            name: None,
                            present_value: None,
                            description: None,
                            units: None,
                        };
                        device.objects.push(obj);
                    }
                    return Ok(device.objects.len());
                }
                Err(_) => {
                    println!("      Failed to parse object list response");
                }
            }
        }
        Err(_) => {}
    }

    // Fallback to reading array length first
    match read_property_with_array_index(socket, device, PropertyIdentifier::ObjectList as u32, 0) {
        Ok(length_str) => {
            if let Ok(length) = length_str.parse::<u32>() {
                // Read each object identifier
                for i in 1..=std::cmp::min(length, 1000) {
                    match read_property_with_array_index(socket, device, PropertyIdentifier::ObjectList as u32, i) {
                        Ok(obj_data) => {
                            if let Ok(obj_id) = parse_object_identifier(&obj_data) {
                                let obj = BACnetObject {
                                    object_type: obj_id.object_type,
                                    instance: obj_id.instance,
                                    name: None,
                                    present_value: None,
                                    description: None,
                                    units: None,
                                };
                                device.objects.push(obj);
                            }
                        }
                        Err(_) => break,
                    }
                    std::thread::sleep(Duration::from_millis(30));
                }
                Ok(device.objects.len())
            } else {
                Err("Could not parse object list length".into())
            }
        }
        Err(_) => {
            // Fallback: try reading indices until we get errors
            for i in 1..=20 {
                match read_property_with_array_index(socket, device, PropertyIdentifier::ObjectList as u32, i) {
                    Ok(obj_data) => {
                        if let Ok(obj_id) = parse_object_identifier(&obj_data) {
                            let obj = BACnetObject {
                                object_type: obj_id.object_type,
                                instance: obj_id.instance,
                                name: None,
                                present_value: None,
                                description: None,
                                units: None,
                            };
                            device.objects.push(obj);
                        }
                    }
                    Err(_) => break,
                }
                std::thread::sleep(Duration::from_millis(30));
            }
            Ok(device.objects.len())
        }
    }
}

fn display_comprehensive_summary(devices: &HashMap<u32, BACnetDevice>) {
    let total_objects: usize = devices.values().map(|d| d.objects.len()).sum();
    let networks: std::collections::HashSet<u16> = devices.values()
        .map(|d| d.network_number)
        .collect();

    println!("STATISTICS:");
    println!("   Total Devices: {}", devices.len());
    println!("   Total Objects: {}", total_objects);
    println!("   Networks: {:?}", networks);

    println!("\nDEVICE INVENTORY:");
    println!("{}", "=".repeat(80));

    for device in devices.values() {
        let network_info = if device.network_number == 0 {
            "Local".to_string()
        } else {
            format!("Network {}", device.network_number)
        };
        println!("\nDEVICE {} - {} ({})",
                 device.device_id,
                 device.vendor_name,
                 network_info
        );

        if let Some(name) = read_device_property_sync(&device) {
            println!("   Name: {}", name);
        }

        if let Some(model) = &device.model_name {
            println!("   Model: {}", model);
        }

        if let Some(firmware) = &device.firmware_revision {
            println!("   Firmware: {}", firmware);
        }

        println!("   Address: {}", device.socket_addr);
        println!("   Max APDU: {}, Segmentation: {}", device.max_apdu, device.segmentation);

        if !device.objects.is_empty() {
            println!("   OBJECTS ({}):", device.objects.len());

            for (i, obj) in device.objects.iter().enumerate() {
                // No limit - print all objects

                let obj_name = match obj.name.as_deref() {
                    Some("null") => "<unnamed>",
                    Some(name) => name,
                    None => "<unnamed>"
                };

                let type_name = object_type_name(obj.object_type);

                // Always show object type, instance and name
                print!("      {:3}. {} {:>3} - {}", 
                    i + 1, 
                    type_name, 
                    obj.instance, 
                    obj_name
                );
                
                // If there's a present value, add it
                if let Some(value) = &obj.present_value {
                    if !value.is_empty() && value != "N/A" && value != "null" {
                        print!(" = {}", value);
                        
                        // If there's also units, add them
                        if let Some(units) = &obj.units {
                            if !units.is_empty() && units != "no-units" {
                                print!(" {}", units);
                            }
                        }
                    }
                }
                
                println!();
            }
        } else {
            println!("   OBJECTS: Unable to read object list");
        }
    }

    // Summary of objects where property ID 8 (ALL) didn't work
    println!("\n{}", "=".repeat(80));
    println!("Summary: Objects where property ID 8 (ALL) did not work");
    println!("{}", "=".repeat(80));
    
    let mut total_objects_without_names = 0;
    for (device_id, device) in devices.iter() {
        let mut device_objects_without_names = Vec::new();
        
        for obj in &device.objects {
            let type_name = object_type_name(obj.object_type);
            let default_name = format!("{}_{}", type_name, obj.instance);
            let has_default_name = obj.name.as_ref().map_or(false, |n| n == &default_name);
            
            if has_default_name || obj.name.is_none() {
                device_objects_without_names.push((obj.object_type, obj.instance));
                total_objects_without_names += 1;
            }
        }
        
        if !device_objects_without_names.is_empty() {
            println!("\nDevice {} - {} ({})", 
                     device_id, 
                     device.vendor_name,
                     if device.network_number == 0 { "Local".to_string() } else { format!("Network {}", device.network_number) });
            for (obj_type, instance) in device_objects_without_names {
                println!("   - {} {}", object_type_name(obj_type), instance);
            }
        }
    }
    
    if total_objects_without_names == 0 {
        println!("\nSUCCESS: All objects successfully returned ObjectName using property ID 8 (ALL)");
    } else {
        println!("\nWARNING: Total objects where property ID 8 (ALL) did not return ObjectName: {}", total_objects_without_names);
    }
    
    println!("\n{}", "=".repeat(80));
    println!("Network scan complete!");
}

// Helper to read device name synchronously
fn read_device_property_sync(_device: &BACnetDevice) -> Option<String> {
    // This is a placeholder - in a real implementation, we'd store this during the scan
    None
}

fn encode_npdu_with_data(npdu: &Npdu, data: &[u8]) -> Vec<u8> {
    let mut npdu_bytes = npdu.encode();
    npdu_bytes.extend_from_slice(data);
    npdu_bytes
}

#[derive(Debug)]
struct BACnetObjectId {
    object_type: ObjectType,
    instance: u32,
}

fn parse_object_identifier(data: &str) -> Result<BACnetObjectId, Box<dyn std::error::Error>> {
    if data.starts_with("0x") && data.len() >= 10 {
        if let Ok(obj_id_value) = u32::from_str_radix(&data[2..], 16) {
            let object_type_num = (obj_id_value >> 22) & 0x3FF;
            let instance = obj_id_value & 0x3FFFFF;
            let object_type = ObjectType::try_from(object_type_num as u16)
                .unwrap_or(ObjectType::Device);
            return Ok(BACnetObjectId { object_type, instance });
        }
    }

    // Try parsing as "Object(type,instance)"
    if data.starts_with("Object(") && data.ends_with(")") {
        let inner = &data[7..data.len()-1];
        let parts: Vec<&str> = inner.split(',').collect();
        if parts.len() == 2 {
            if let (Ok(type_num), Ok(instance)) = (parts[0].parse::<u16>(), parts[1].parse::<u32>()) {
                let object_type = ObjectType::try_from(type_num)
                    .unwrap_or(ObjectType::Device);
                return Ok(BACnetObjectId { object_type, instance });
            }
        }
    }

    Err("Could not parse object identifier".into())
}

fn parse_object_list_response(data: &str) -> Result<Vec<BACnetObjectId>, Box<dyn std::error::Error>> {
    // Handle "Objects: [...]" format
    if data.starts_with("Objects: [") && data.ends_with("]") {
        return parse_object_identifiers_from_response(data);
    }

    // Try to parse as hex string
    if data.starts_with("0x") {
        let hex_str = &data[2..];
        if let Ok(bytes) = decode_hex(hex_str) {
            return parse_object_list_from_bytes(&bytes);
        }
    }

    Err("No objects found in response".into())
}

fn parse_object_list_from_bytes(data: &[u8]) -> Result<Vec<BACnetObjectId>, Box<dyn std::error::Error>> {
    let mut objects = Vec::new();
    let mut i = 0;

    // Skip BACnet headers and find the actual object list data
    // The response should have opening tag 3E for the property value
    while i < data.len() && data[i] != 0x3E {
        i += 1;
    }
    if i < data.len() && data[i] == 0x3E {
        i += 1; // Skip opening tag
    }

    // Now parse all object identifiers until closing tag or end of data
    while i < data.len() {
        if data[i] == 0x3F {
            // Closing tag - we're done
            break;
        }

        if data[i] == 0xC4 && i + 4 < data.len() {
            // Extract the 4-byte object identifier
            let obj_bytes = [data[i+1], data[i+2], data[i+3], data[i+4]];
            let obj_id_value = u32::from_be_bytes(obj_bytes);
            let object_type_num = (obj_id_value >> 22) & 0x3FF;
            let instance = obj_id_value & 0x3FFFFF;

            // Convert to ObjectType enum
            if let Ok(object_type) = ObjectType::try_from(object_type_num as u16) {
                objects.push(BACnetObjectId {
                    object_type,
                    instance,
                });
            }
            i += 5; // Skip the C4 tag and 4 bytes of data
        } else {
            i += 1;
        }
    }

    // println!("        Found {} objects in response", objects.len());
    Ok(objects)
}

fn parse_object_identifiers_from_response(response: &str) -> Result<Vec<BACnetObjectId>, Box<dyn std::error::Error>> {
    // Handle hex-encoded response
    if response.starts_with("0x") {
        let hex_str = &response[2..];
        if let Ok(bytes) = decode_hex(hex_str) {
            return parse_object_list_from_bytes(&bytes);
        }
        return Err("Failed to decode hex response".into());
    }

    // Handle "Objects: [...]" format
    if response.starts_with("Objects: [") {
        let objects_str = &response[10..response.len()-1]; // Remove "Objects: [" and "]"
        let mut objects = Vec::new();

        for obj_str in objects_str.split(", ") {
            if let Some(colon_pos) = obj_str.find(':') {
                let type_str = &obj_str[..colon_pos];
                let instance_str = &obj_str[colon_pos+1..];

                if let Ok(instance) = instance_str.parse::<u32>() {
                    let object_type = match type_str {
                        "Device" => ObjectType::Device,
                        "AnalogInput" => ObjectType::AnalogInput,
                        "AnalogOutput" => ObjectType::AnalogOutput,
                        "AnalogValue" => ObjectType::AnalogValue,
                        "BinaryInput" => ObjectType::BinaryInput,
                        "BinaryOutput" => ObjectType::BinaryOutput,
                        "BinaryValue" => ObjectType::BinaryValue,
                        "MultiStateInput" => ObjectType::MultiStateInput,
                        "MultiStateOutput" => ObjectType::MultiStateOutput,
                        "MultiStateValue" => ObjectType::MultiStateValue,
                        "StructuredView" => ObjectType::StructuredView,
                        _ => continue, // Skip unknown types
                    };

                    objects.push(BACnetObjectId { object_type, instance });
                }
            }
        }

        return Ok(objects);
    }

    Err("Unknown response format".into())
}

fn parse_raw_response(apdu_data: &[u8]) -> Result<String, Box<dyn std::error::Error>> {
    // For object list responses, we want to return the raw hex data
    // so it can be properly parsed by parse_object_list_response

    // Skip the ACK header and service choice if present
    let start_idx = if apdu_data.len() > 2 && apdu_data[0] == 0x30 && apdu_data[1] == 0x0C {
        2 // Skip complex ACK header
    } else {
        0
    };

    // Check if this looks like an object list response
    // Object lists contain multiple C4 tags (object identifiers)
    let mut obj_count = 0;
    for i in start_idx..apdu_data.len() {
        if apdu_data[i] == 0xC4 && i + 4 < apdu_data.len() {
            obj_count += 1;
        }
    }

    // If we found multiple object identifiers, return the hex-encoded data
    // starting from the actual data (after headers)
    if obj_count > 1 {
        return Ok(format!("0x{}", hex::encode(&apdu_data[start_idx..])));
    }

    // For single values, try to decode
    if apdu_data.len() > start_idx {
        let data = &apdu_data[start_idx..];

        // Try to decode as BACnet value
        if let Ok(value) = decode_bacnet_value(data) {
            return Ok(value);
        }
    }

    // Fallback: look for object identifiers in the response (pattern: C4 XX XX XX XX for object IDs)
    let mut objects = Vec::new();
    let mut i = 0;
    while i + 4 < apdu_data.len() {
        if apdu_data[i] == 0xC4 {
            let obj_bytes = [apdu_data[i+1], apdu_data[i+2], apdu_data[i+3], apdu_data[i+4]];
            let obj_id_value = u32::from_be_bytes(obj_bytes);
            let object_type_num = (obj_id_value >> 22) & 0x3FF;
            let instance = obj_id_value & 0x3FFFFF;

            if let Ok(object_type) = ObjectType::try_from(object_type_num as u16) {
                objects.push(format!("{}:{}", object_type_name(object_type), instance));
            }
            i += 5;
        } else {
            i += 1;
        }
    }

    if !objects.is_empty() {
        Ok(format!("Objects: [{}]", objects.join(", ")))
    } else {
        // Final fallback to hex dump - but try to decode strings first
        if apdu_data.len() > 5 && (apdu_data[0] == 0x30 || apdu_data[0] == 0x3E) {
            // Skip to actual data and try to extract string value
            for i in 0..apdu_data.len() {
                if apdu_data[i] == 0x75 || apdu_data[i] == 0x74 {
                    // Try to decode the value
                    if let Ok(value) = decode_bacnet_value(&apdu_data[i..]) {
                        return Ok(value);
                    }
                    // If decoding fails, fall back to hex using hex crate
                    return Ok(format!("0x{}", hex::encode(&apdu_data[i..])));
                }
            }
        }
        // Use hex crate for final fallback
        Ok(format!("0x{}", hex::encode(apdu_data)))
    }
}

fn decode_hex(hex_str: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    hex::decode(hex_str).map_err(|e| e.to_string().into())
}


fn parse_string_from_response(response: &str) -> Result<String, Box<dyn std::error::Error>> {
    // Handle hex response starting with 0x
    if response.starts_with("0x") {
        let hex_str = &response[2..];
        if let Ok(bytes) = decode_hex(hex_str) {
            // Try multiple approaches to extract the string

            // Use universal decoder
            return decode_bacnet_value(&bytes);
        }
    }

    // Clean up raw string responses
    Ok(response.trim_end_matches('\0').trim().to_string())
}

fn parse_value_from_response(response: &str) -> Result<String, Box<dyn std::error::Error>> {
    // Handle hex response starting with 0x
    if response.starts_with("0x") {
        let hex_str = &response[2..];
        if let Ok(bytes) = decode_hex(hex_str) {
            // Use universal BACnet decoder
            return decode_bacnet_value(&bytes);
        }
    }
    Ok(response.to_string())
}

// Universal BACnet value decoder based on application tag types
fn decode_bacnet_value(data: &[u8]) -> Result<String, Box<dyn std::error::Error>> {
    if data.is_empty() {
        return Ok("(empty)".to_string());
    }

    // Skip BACnet Complex ACK header if present
    let mut idx = 0;
    if data.len() > 2 && data[0] == 0x30 {
        idx = 2;
        // Skip object identifier and property identifier context tags
        while idx < data.len() {
            match data[idx] >> 4 {
                0x0 | 0x1 => idx += 2 + (data[idx] & 0x07) as usize, // Context tags
                _ => break,
            }
        }
    }

    // Skip opening tag if present
    if idx < data.len() && data[idx] == 0x3E {
        idx += 1;
    }

    // Parse BACnet application tags from this position
    if idx < data.len() {
        return parse_bacnet_application_tag(&data[idx..]);
    }

    // Fallback - hex encode
    Ok(format!("0x{}", hex::encode(data)))
}

// Extract characters from UTF-16 encoded data using encoding_rs
fn extract_ascii_from_utf16(data: &[u8]) -> Result<String, Box<dyn std::error::Error>> {
    use encoding_rs::UTF_16LE;
    
    if data.len() % 2 != 0 {
        return Err("Invalid UTF-16 data length".into());
    }

    // Try UTF-16BE first (BACnet standard)
    let (text_be, _, had_errors_be) = UTF_16BE.decode(data);
    if !had_errors_be && !text_be.trim().is_empty() {
        return Ok(text_be.into_owned());
    }
    
    // Try UTF-16LE as fallback
    let (text_le, _, had_errors_le) = UTF_16LE.decode(data);
    if !had_errors_le && !text_le.trim().is_empty() {
        return Ok(text_le.into_owned());
    }
    
    // If both had errors, use the one with better results
    if text_be.len() > text_le.len() {
        Ok(text_be.into_owned())
    } else {
        Ok(text_le.into_owned())
    }
}

// Check if a string contains only printable ASCII characters
fn is_printable_ascii(s: &str) -> bool {
    s.chars().all(|c| c.is_ascii() && (c.is_ascii_graphic() || c.is_ascii_whitespace()))
}

// Decode UCS-2 or UTF-16 string data using encoding_rs
fn decode_ucs2_or_utf16(data: &[u8]) -> Result<String, Box<dyn std::error::Error>> {
    use encoding_rs::UTF_16LE;

    if data.is_empty() {
        return Ok("".to_string());
    }

    // Try UTF-16BE first (BACnet standard)
    let (result_be, _, _) = UTF_16BE.decode(data);
    let cleaned_be = result_be.trim_end_matches('\0').trim();
    if !cleaned_be.is_empty() && is_printable_ascii(cleaned_be) {
        return Ok(cleaned_be.to_string());
    }
    
    // Try UTF-16LE as fallback
    let (result_le, _, _) = UTF_16LE.decode(data);
    let cleaned_le = result_le.trim_end_matches('\0').trim();
    if !cleaned_le.is_empty() && is_printable_ascii(cleaned_le) {
        return Ok(cleaned_le.to_string());
    }
    
    // Try UTF-8 as last resort
    let (result_utf8, _, _) = UTF_8.decode(data);
    let cleaned_utf8 = result_utf8.trim_end_matches('\0').trim();
    if !cleaned_utf8.is_empty() {
        return Ok(cleaned_utf8.to_string());
    }
    
    // If all else fails, return hex representation
    Ok(format!("0x{}", hex::encode(data)))
}

// Convert hex bytes to a more readable string representation
fn hex_to_readable_string(data: &[u8]) -> String {
    let mut result = String::new();
    let mut i = 0;
    while i < data.len() {
        if i > 0 {
            result.push(' ');
        }
        if i + 1 < data.len() {
            result.push_str(&format!("{:02X}{:02X}", data[i], data[i+1]));
            i += 2;
        } else {
            result.push_str(&format!("{:02X}", data[i]));
            i += 1;
        }
    }
    result
}

// Parse BACnet application tags according to the protocol specification
fn parse_bacnet_application_tag(data: &[u8]) -> Result<String, Box<dyn std::error::Error>> {
    if data.is_empty() {
        return Err("Empty data".into());
    }

    let tag = data[0];
    let tag_number = (tag >> 4) & 0x0F;
    let length_value_type = tag & 0x07;

    // Determine the length of the data
    let (data_len, data_start) = if tag & 0x08 != 0 {
        // Extended tag
        if data.len() < 2 {
            return Err("Incomplete extended tag".into());
        }
        (0, 1) // Extended tags handled differently
    } else if length_value_type <= 4 {
        // Length is in the tag
        (length_value_type as usize, 1)
    } else if length_value_type == 5 {
        // Length in next octet
        if data.len() < 2 {
            return Err("Incomplete length encoding".into());
        }
        let len = data[1] as usize;
        if len == 254 && data.len() >= 4 {
            // 2-byte length
            ((data[2] as usize) << 8 | data[3] as usize, 4)
        } else if len == 255 && data.len() >= 6 {
            // 4-byte length
            ((data[2] as usize) << 24 | (data[3] as usize) << 16 |
                 (data[4] as usize) << 8 | data[5] as usize, 6)
        } else {
            (len, 2)
        }
    } else {
        // Reserved
        return Err("Reserved length encoding".into());
    };

    // Make sure we have enough data
    if data.len() < data_start + data_len {
        return Err("Insufficient data for tag value".into());
    }

    let value_data = &data[data_start..data_start + data_len];

    // Parse based on tag number (BACnet application tags)
    match tag_number {
        0 => { // Null
            Ok("null".to_string())
        },
        1 => { // Boolean
            if length_value_type == 0 {
                Ok("false".to_string())
            } else {
                Ok("true".to_string())
            }
        },
        2 => { // Unsigned Integer
            let mut value = 0u64;
            for &byte in value_data {
                value = (value << 8) | (byte as u64);
            }
            Ok(value.to_string())
        },
        3 => { // Signed Integer
            let mut value = 0i64;
            if value_data.len() > 0 {
                // Sign extend the first byte
                if value_data[0] & 0x80 != 0 {
                    value = -1; // Start with all 1s for negative numbers
                }
                for &byte in value_data {
                    value = (value << 8) | (byte as i64);
                }
            }
            Ok(value.to_string())
        },
        4 => { // Real
            if value_data.len() == 4 {
                let bytes = [value_data[0], value_data[1], value_data[2], value_data[3]];
                let real_value = f32::from_be_bytes(bytes);
                if real_value.is_nan() {
                    Ok("NaN".to_string())
                } else if real_value.is_infinite() {
                    if real_value.is_sign_positive() {
                        Ok("Infinity".to_string())
                    } else {
                        Ok("-Infinity".to_string())
                    }
                } else {
                    Ok(format!("{:.2}", real_value))
                }
            } else {
                Err("Invalid REAL length".into())
            }
        },
        5 => { // Double
            if value_data.len() == 8 {
                let bytes = [
                    value_data[0], value_data[1], value_data[2], value_data[3],
                    value_data[4], value_data[5], value_data[6], value_data[7]
                ];
                let double_value = f64::from_be_bytes(bytes);
                if double_value.is_nan() {
                    Ok("NaN".to_string())
                } else if double_value.is_infinite() {
                    if double_value.is_sign_positive() {
                        Ok("Infinity".to_string())
                    } else {
                        Ok("-Infinity".to_string())
                    }
                } else {
                    Ok(format!("{:.2}", double_value))
                }
            } else {
                Err("Invalid DOUBLE length".into())
            }
        },
        6 => { // Octet String
            Ok(format!("0x{}", hex::encode(value_data)))
        },
        7 => { // Character String
            // First byte is character set
            if value_data.len() > 0 {
                let charset = value_data[0];
                let string_data = &value_data[1..];
                match charset {
                    0 => { // UTF-8
                        match std::str::from_utf8(string_data) {
                            Ok(s) => Ok(s.trim_end_matches('\0').trim().to_string()),
                            Err(_) => {
                                // Some devices incorrectly report UTF-8 for UTF-16 data
                                match decode_ucs2_or_utf16(string_data) {
                                    Ok(s) if !s.is_empty() => Ok(s),
                                    _ => Ok(format!("(invalid UTF-8: 0x{})", hex::encode(string_data)))
                                }
                            }
                        }
                    },
                    4 => { // UCS-2
                        // UCS-2 is a subset of UTF-16, so we can use the same decoder
                        decode_ucs2_or_utf16(string_data)
                    },
                    5 => { // UTF-16
                        decode_ucs2_or_utf16(string_data)
                    },
                    _ => {
                        // For unknown character sets, try multiple approaches
                        // First try UTF-8
                        if let Ok(s) = std::str::from_utf8(string_data) {
                            let cleaned = s.trim_end_matches('\0').trim().to_string();
                            if !cleaned.is_empty() {
                                return Ok(cleaned);
                            }
                        }

                        // Then try UTF-16 as many devices incorrectly report charset
                        if let Ok(s) = decode_ucs2_or_utf16(string_data) {
                            if !s.is_empty() {
                                return Ok(s);
                            }
                        }

                        // Last resort: try to extract ASCII characters
                        let ascii_result: String = string_data.iter()
                            .filter(|&&b| b >= 32 && b <= 126) // Only printable ASCII
                            .map(|&b| b as char)
                            .collect();
                        if !ascii_result.is_empty() {
                            Ok(ascii_result)
                        } else {
                            Ok(format!("(charset {}: 0x{})", charset, hex::encode(string_data)))
                        }
                    }
                }
            } else {
                Ok("".to_string())
            }
        },
        8 => { // Bit String
            if value_data.len() > 0 {
                let unused_bits = value_data[0];
                let bit_data = &value_data[1..];
                Ok(format!("bits({} unused): 0x{}", unused_bits, hex::encode(bit_data)))
            } else {
                Ok("bits()".to_string())
            }
        },
        9 => { // Enumerated
            let mut value = 0u32;
            for &byte in value_data {
                value = (value << 8) | (byte as u32);
            }
            Ok(value.to_string())
        },
        10 => { // Date
            if value_data.len() == 4 {
                let year = 1900 + value_data[0] as i32;
                let month = value_data[1];
                let day = value_data[2];
                let dow = value_data[3];
                Ok(format!("{:04}-{:02}-{:02} (dow:{})", year, month, day, dow))
            } else {
                Err("Invalid DATE length".into())
            }
        },
        11 => { // Time
            if value_data.len() == 4 {
                let hour = value_data[0];
                let minute = value_data[1];
                let second = value_data[2];
                let hundredths = value_data[3];
                Ok(format!("{:02}:{:02}:{:02}.{:02}", hour, minute, second, hundredths))
            } else {
                Err("Invalid TIME length".into())
            }
        },
        12 => { // BACnetObjectIdentifier
            if value_data.len() == 4 {
                let obj_id = u32::from_be_bytes([value_data[0], value_data[1], value_data[2], value_data[3]]);
                let obj_type = (obj_id >> 22) & 0x3FF;
                let instance = obj_id & 0x3FFFFF;
                Ok(format!("Object({},{})", obj_type, instance))
            } else {
                Err("Invalid ObjectIdentifier length".into())
            }
        },
        _ => {
            // Unknown or reserved tag
            Ok(format!("Tag{}:0x{}", tag_number, hex::encode(value_data)))
        }
    }
}

fn get_property_name(prop_id: u32) -> &'static str {
    match prop_id {
        75 => "Object_Identifier",
        76 => "Object_List",
        77 => "Object_Name",
        79 => "Object_Type",
        85 => "Present_Value",
        28 => "Description",
        117 => "Units",
        111 => "Status_Flags",
        62 => "Max_APDU_Length_Accepted",
        _ => "Unknown"
    }
}

fn find_tag_in_slice(data: &[u8], tag: u8) -> Option<usize> {
    data.iter().position(|&b| b == tag)
}

fn parse_bacnet_string_at(data: &[u8], start: usize) -> Result<String, Box<dyn std::error::Error>> {
    if start >= data.len() {
        return Err("Invalid start position".into());
    }

    let tag = data[start];
    if (tag >> 4) != 7 { // Not a character string
        return Err("Not a character string tag".into());
    }

    let length_value_type = tag & 0x07;
    let (data_len, data_start) = if length_value_type <= 4 {
        // Length is in the tag
        (length_value_type as usize, start + 1)
    } else if length_value_type == 5 {
        // Length in next octet
        if start + 1 >= data.len() {
            return Err("Incomplete length encoding".into());
        }
        let len = data[start + 1] as usize;
        (len, start + 2)
    } else {
        return Err("Unsupported length encoding".into());
    };

    if data_start + data_len > data.len() {
        return Err("Insufficient data for string".into());
    }

    if data_len == 0 {
        return Ok("".to_string());
    }

    let charset = data[data_start];
    let string_data = &data[data_start + 1..data_start + data_len];

    match charset {
        0 => { // UTF-8
            match std::str::from_utf8(string_data) {
                Ok(s) => Ok(s.trim_end_matches('\0').trim().to_string()),
                Err(_) => {
                    // Try to decode as UTF-16 if UTF-8 fails
                    match decode_ucs2_or_utf16(string_data) {
                        Ok(s) if !s.is_empty() => Ok(s),
                        _ => Ok(format!("(invalid UTF-8: 0x{})", hex::encode(string_data)))
                    }
                }
            }
        },
        4 => { // UCS-2
            decode_ucs2_or_utf16(string_data)
        },
        5 => { // UTF-16
            decode_ucs2_or_utf16(string_data)
        },
        _ => {
            // For unknown character sets, try UTF-8 first, then UTF-16
            match std::str::from_utf8(string_data) {
                Ok(s) => Ok(s.trim_end_matches('\0').trim().to_string()),
                Err(_) => {
                    match decode_ucs2_or_utf16(string_data) {
                        Ok(s) if !s.is_empty() => Ok(s),
                        _ => Ok(format!("(charset {}: 0x{})", charset, hex::encode(string_data)))
                    }
                }
            }
        }
    }
}

fn object_type_name(obj_type: ObjectType) -> &'static str {
    match obj_type {
        ObjectType::AnalogInput => "AnalogInput",
        ObjectType::AnalogOutput => "AnalogOutput",
        ObjectType::AnalogValue => "AnalogValue",
        ObjectType::BinaryInput => "BinaryInput",
        ObjectType::BinaryOutput => "BinaryOutput",
        ObjectType::BinaryValue => "BinaryValue",
        ObjectType::Device => "Device",
        ObjectType::MultiStateInput => "MultiStateInput",
        ObjectType::MultiStateOutput => "MultiStateOutput",
        ObjectType::MultiStateValue => "MultiStateValue",
        ObjectType::StructuredView => "StructuredView",
        ObjectType::File => "File",
        ObjectType::Calendar => "Calendar",
        ObjectType::Command => "Command",
        ObjectType::EventEnrollment => "EventEnrollment",
        ObjectType::Group => "Group",
        ObjectType::Loop => "Loop",
        ObjectType::NotificationClass => "NotificationClass",
        ObjectType::Program => "Program",
        ObjectType::Schedule => "Schedule",
        ObjectType::Averaging => "Averaging",
        ObjectType::TrendLog => "TrendLog",
        ObjectType::LifeSafetyPoint => "LifeSafetyPoint",
        ObjectType::LifeSafetyZone => "LifeSafetyZone",
        ObjectType::Accumulator => "Accumulator",
        ObjectType::PulseConverter => "PulseConverter",
        ObjectType::EventLog => "EventLog",
        ObjectType::GlobalGroup => "GlobalGroup",
        ObjectType::TrendLogMultiple => "TrendLogMultiple",
        ObjectType::LoadControl => "LoadControl",
        ObjectType::AccessDoor => "AccessDoor",
        #[allow(unreachable_patterns)]
        _ => "Unknown",
    }
}

fn parse_units_from_response(response: &str) -> Result<String, Box<dyn std::error::Error>> {
    // Function to convert unit ID to human-readable name
    fn unit_id_to_name(unit_id: &str) -> String {
        match unit_id {
            // Area units
            "0" => "square-meters".to_string(),
            "116" => "square-centimeters".to_string(),
            "1" => "square-feet".to_string(),
            "115" => "square-inches".to_string(),
            
            // Currency units
            "105" => "currency1".to_string(),
            "106" => "currency2".to_string(),
            "107" => "currency3".to_string(),
            "108" => "currency4".to_string(),
            "109" => "currency5".to_string(),
            "110" => "currency6".to_string(),
            "111" => "currency7".to_string(),
            "112" => "currency8".to_string(),
            "113" => "currency9".to_string(),
            "114" => "currency10".to_string(),
            
            // Electrical units
            "2" => "milliamperes".to_string(),
            "3" => "amperes".to_string(),
            "4" => "ohms".to_string(),
            "122" => "kilohms".to_string(),
            "123" => "megohms".to_string(),
            "5" => "volts".to_string(),
            "124" => "millivolts".to_string(),
            "6" => "kilovolts".to_string(),
            "7" => "megavolts".to_string(),
            "8" => "volt-amperes".to_string(),
            "9" => "kilovolt-amperes".to_string(),
            "10" => "megavolt-amperes".to_string(),
            "11" => "volt-amperes-reactive".to_string(),
            "12" => "kilovolt-amperes-reactive".to_string(),
            "13" => "megavolt-amperes-reactive".to_string(),
            "14" => "degrees-phase".to_string(),
            "15" => "power-factor".to_string(),
            
            // Energy units
            "16" => "joules".to_string(),
            "17" => "kilojoules".to_string(),
            "125" => "kilojoules-per-kilogram".to_string(),
            "126" => "megajoules".to_string(),
            "18" => "watt-hours".to_string(),
            "19" => "kilowatt-hours".to_string(),
            "20" => "btus".to_string(),
            "21" => "therms".to_string(),
            "22" => "ton-hours".to_string(),
            
            // Enthalpy units
            "23" => "joules-per-kilogram-dry-air".to_string(),
            "24" => "btus-per-pound-dry-air".to_string(),
            "117" => "btus-per-pound".to_string(),
            
            // Entropy units
            "127" => "joules-per-degree-Kelvin".to_string(),
            "128" => "joules-per-kilogram-degree-Kelvin".to_string(),
            
            // Temperature units
            "62" => "degrees-Celsius".to_string(),
            "63" => "degrees-Kelvin".to_string(),
            "64" => "degrees-Fahrenheit".to_string(),
            "65" => "degrees-days-Celsius".to_string(),
            "66" => "degrees-days-Fahrenheit".to_string(),
            "120" => "delta-degrees-Fahrenheit".to_string(),
            "121" => "delta-degrees-Kelvin".to_string(),
            
            // Frequency units
            "25" => "cycles-per-hour".to_string(),
            "26" => "cycles-per-minute".to_string(),
            "27" => "hertz".to_string(),
            "129" => "kilohertz".to_string(),
            "130" => "megahertz".to_string(),
            "131" => "per-hour".to_string(),
            
            // Humidity units
            "28" => "grams-of-water-per-kilogram-dry-air".to_string(),
            "29" => "percent-relative-humidity".to_string(),
            
            // Length units
            "30" => "millimeters".to_string(),
            "118" => "centimeters".to_string(),
            "31" => "meters".to_string(),
            "32" => "inches".to_string(),
            "33" => "feet".to_string(),
            
            // Light units
            "34" => "watts-per-square-foot".to_string(),
            "35" => "watts-per-square-meter".to_string(),
            "36" => "lumens".to_string(),
            "37" => "luxes".to_string(),
            "38" => "foot-candles".to_string(),
            
            // Mass units
            "39" => "kilograms".to_string(),
            "40" => "pounds-mass".to_string(),
            "41" => "tons".to_string(),
            
            // Mass Flow units
            "42" => "kilograms-per-second".to_string(),
            "43" => "kilograms-per-minute".to_string(),
            "44" => "kilograms-per-hour".to_string(),
            "119" => "pounds-mass-per-second".to_string(),
            "45" => "pounds-mass-per-minute".to_string(),
            "46" => "pounds-mass-per-hour".to_string(),
            
            // Power units
            "132" => "milliwatts".to_string(),
            "47" => "watts".to_string(),
            "48" => "kilowatts".to_string(),
            "49" => "megawatts".to_string(),
            "50" => "btus-per-hour".to_string(),
            "51" => "horsepower".to_string(),
            "52" => "tons-refrigeration".to_string(),
            
            // Pressure units
            "53" => "pascals".to_string(),
            "133" => "hectopascals".to_string(),
            "54" => "kilopascals".to_string(),
            "134" => "millibars".to_string(),
            "55" => "bars".to_string(),
            "56" => "pounds-force-per-square-inch".to_string(),
            "57" => "centimeters-of-water".to_string(),
            "58" => "inches-of-water".to_string(),
            "59" => "millimeters-of-mercury".to_string(),
            "60" => "centimeters-of-mercury".to_string(),
            "61" => "inches-of-mercury".to_string(),
            
            // Time units
            "67" => "years".to_string(),
            "68" => "months".to_string(),
            "69" => "weeks".to_string(),
            "70" => "days".to_string(),
            "71" => "hours".to_string(),
            "72" => "minutes".to_string(),
            "73" => "seconds".to_string(),
            
            // Velocity units
            "74" => "meters-per-second".to_string(),
            "75" => "kilometers-per-hour".to_string(),
            "76" => "feet-per-second".to_string(),
            "77" => "feet-per-minute".to_string(),
            "78" => "miles-per-hour".to_string(),
            
            // Volume units
            "79" => "cubic-feet".to_string(),
            "80" => "cubic-meters".to_string(),
            "81" => "imperial-gallons".to_string(),
            "82" => "liters".to_string(),
            "83" => "us-gallons".to_string(),
            
            // Volumetric Flow units
            "142" => "cubic-feet-per-second".to_string(),
            "84" => "cubic-feet-per-minute".to_string(),
            "85" => "cubic-meters-per-second".to_string(),
            "135" => "cubic-meters-per-hour".to_string(),
            "86" => "imperial-gallons-per-minute".to_string(),
            "87" => "liters-per-second".to_string(),
            "88" => "liters-per-minute".to_string(),
            "136" => "liters-per-hour".to_string(),
            "89" => "us-gallons-per-minute".to_string(),
            
            // Other units
            "90" => "degrees-angular".to_string(),
            "91" => "degrees-Celsius-per-hour".to_string(),
            "92" => "degrees-Celsius-per-minute".to_string(),
            "93" => "degrees-Fahrenheit-per-hour".to_string(),
            "94" => "degrees-Fahrenheit-per-minute".to_string(),
            "137" => "kilowatt-hours-per-square-meter".to_string(),
            "138" => "kilowatt-hours-per-square-foot".to_string(),
            "139" => "megajoules-per-square-meter".to_string(),
            "140" => "megajoules-per-square-foot".to_string(),
            "95" => "no-units".to_string(),
            "96" => "parts-per-million".to_string(),
            "97" => "parts-per-billion".to_string(),
            "98" => "percent".to_string(),
            "143" => "percent-obscuration-per-foot".to_string(),
            "144" => "percent-obscuration-per-meter".to_string(),
            "99" => "percent-per-second".to_string(),
            "100" => "per-minute".to_string(),
            "101" => "per-second".to_string(),
            "102" => "psi-per-degree-Fahrenheit".to_string(),
            "103" => "radians".to_string(),
            "104" => "revolutions-per-minute".to_string(),
            "141" => "watts-per-square-meter-degree-Kelvin".to_string(),
            
            // Default case - return a more user-friendly string
            _ => "unknown-units".to_string(),
        }
    }

    // Handle hex response starting with 0x
    if response.starts_with("0x") {
        let hex_str = &response[2..];
        if let Ok(bytes) = decode_hex(hex_str) {
            // Use universal decoder - units will be returned as enumerated values
            if let Ok(value) = decode_bacnet_value(&bytes) {
                return Ok(unit_id_to_name(&value));
            }
        }
    } else if response.chars().all(|c| c.is_digit(10)) {
        // Handle plain numeric values
        return Ok(unit_id_to_name(response));
    }
    
    Ok(response.to_string())
}

fn is_io_object(obj_type: ObjectType) -> bool {
    matches!(obj_type,
        ObjectType::AnalogInput | ObjectType::AnalogOutput | ObjectType::AnalogValue |
        ObjectType::BinaryInput | ObjectType::BinaryOutput | ObjectType::BinaryValue |
        ObjectType::MultiStateInput | ObjectType::MultiStateOutput | ObjectType::MultiStateValue
    )
}