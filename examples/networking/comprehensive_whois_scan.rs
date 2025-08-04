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
};
use std::{
    net::{SocketAddr, UdpSocket},
    time::{Duration, Instant},
    collections::HashMap,
    sync::atomic::{AtomicU8, Ordering},
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
        println!("      Reading object details using ReadPropertyMultiple...");
        let objects_to_read = device.objects.len(); // Read all objects
        for i in 0..objects_to_read {
            // Use only ReadPropertyMultiple
            if let Ok(all_props) = read_all_object_properties(socket, device, &device.objects[i]) {
                // Debug for specific object - commented out
                // if device.objects[i].object_type == ObjectType::AnalogInput && device.objects[i].instance == 18 {
                //     println!("        AI 18 properties: {:?}", all_props);
                // }
                
                // Extract object name
                if let Some(name) = all_props.get(&(PropertyIdentifier::ObjectName as u32)) {
                    if let Ok(parsed_name) = parse_string_from_response(name) {
                        // Clean up object names - remove null bytes and control characters
                        let cleaned_name = parsed_name.chars()
                            .filter(|&c| c != '\0' && !c.is_control())
                            .collect::<String>()
                            .trim()
                            .to_string();
                            
                        // Validate the name - if it looks like binary garbage, skip it
                        let printable_ratio = cleaned_name.chars()
                            .filter(|c| c.is_ascii_graphic() || c == &' ')
                            .count() as f32 / cleaned_name.len().max(1) as f32;
                            
                        if printable_ratio > 0.7 && cleaned_name.len() > 0 {
                            device.objects[i].name = Some(cleaned_name);
                        } else if cleaned_name.len() > 0 && cleaned_name.chars().all(|c| c.is_ascii_graphic() || c == ' ') {
                            // Accept names that are all printable ASCII even if they don't meet the ratio test
                            device.objects[i].name = Some(cleaned_name);
                        }
                    }
                } else {
                    // Try to read the object name directly using ReadProperty
                    if let Ok(name_response) = read_object_property(socket, device, &device.objects[i], PropertyIdentifier::ObjectName as u32) {
                        if let Ok(parsed_name) = parse_string_from_response(&name_response) {
                            // Clean up object names - remove null bytes and control characters
                            let cleaned_name = parsed_name.chars()
                                .filter(|&c| c != '\0' && !c.is_control())
                                .collect::<String>()
                                .trim()
                                .to_string();
                                
                            if !cleaned_name.is_empty() {
                                device.objects[i].name = Some(cleaned_name);
                            }
                        }
                    }
                }
                
                // Extract present value
                if let Some(value) = all_props.get(&(PropertyIdentifier::PresentValue as u32)) {
                    device.objects[i].present_value = Some(value.clone());
                } else {
                    // Try to read the present value directly using ReadProperty for I/O objects
                    if matches!(device.objects[i].object_type,
                        ObjectType::AnalogInput | ObjectType::AnalogOutput | ObjectType::AnalogValue |
                        ObjectType::BinaryInput | ObjectType::BinaryOutput | ObjectType::BinaryValue |
                        ObjectType::MultiStateInput | ObjectType::MultiStateOutput | ObjectType::MultiStateValue) {
                        if let Ok(value_response) = read_object_property(socket, device, &device.objects[i], PropertyIdentifier::PresentValue as u32) {
                            device.objects[i].present_value = Some(value_response);
                        }
                    }
                }
            }
            
            // Fallback added for reading present values directly
            std::thread::sleep(Duration::from_millis(50)); // Small delay between reads
        }
    }
    
    // Old fallback code - commented out as we're using the new approach
    // else {
    //     // Try alternative methods to read at least some objects
    //     println!("      Attempting to read individual objects...");
    //
    //     // Try to read just the first few objects as a sample
    //     let objects_to_read = std::cmp::min(device.objects.len(), 10);
    //     for i in 0..objects_to_read {
    //         // Read object name
    //         if let Ok(name) = read_object_property(socket, device, &device.objects[i], PropertyIdentifier::ObjectName as u32) {
    //             device.objects[i].name = Some(name);
    //         }
    //
    //         // Read present value for I/O objects
    //         if is_io_object(device.objects[i].object_type) {
    //             if let Ok(value) = read_object_property(socket, device, &device.objects[i], PropertyIdentifier::PresentValue as u32) {
    //                 device.objects[i].present_value = Some(value);
    //             }
    //         }
    //
    //         std::thread::sleep(Duration::from_millis(50));
    //     }
    // }
    
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

fn read_all_object_properties(socket: &UdpSocket, device: &BACnetDevice, object: &BACnetObject) -> Result<HashMap<u32, String>, Box<dyn std::error::Error>> {
    static INVOKE_ID: AtomicU8 = AtomicU8::new(250);
    let invoke_id = INVOKE_ID.fetch_add(1, Ordering::SeqCst);
    let invoke_id = if invoke_id == 0 { 1 } else { invoke_id };
    
    // Debug output - commented out
    // if object.object_type == ObjectType::AnalogInput && (object.instance == 61 || object.instance == 18) {
    //     println!("        Reading properties for {} {}", object_type_name(object.object_type), object.instance);
    // }
    
    // Create ReadPropertyMultiple request for ALL properties
    let mut apdu = Vec::new();
    apdu.push(0x02); // Confirmed-Request (with segmentation bit)
    apdu.push(0x75); // Segmentation accepted, max APDU 1476
    apdu.push(invoke_id);
    apdu.push(0x0E); // ReadPropertyMultiple service (14)
    
    // Object ID
    let obj_id = ((object.object_type as u32) << 22) | (object.instance & 0x3FFFFF);
    apdu.push(0x0C); // Context tag 0, length 4
    apdu.extend_from_slice(&obj_id.to_be_bytes());
    
    // Property list - request specific properties
    apdu.push(0x1E); // Opening tag 1
    
    // Property 1: ObjectName (77)
    apdu.push(0x09); // Context tag 0, length 1
    apdu.push(77);   // Property ID 77 = Object_Name
    
    // Property 2: PresentValue (85) - only for I/O objects
    if matches!(object.object_type,
        ObjectType::AnalogInput | ObjectType::AnalogOutput | ObjectType::AnalogValue |
        ObjectType::BinaryInput | ObjectType::BinaryOutput | ObjectType::BinaryValue |
        ObjectType::MultiStateInput | ObjectType::MultiStateOutput | ObjectType::MultiStateValue) {
        apdu.push(0x09); // Context tag 0, length 1
        apdu.push(85);   // Property ID 85 = Present_Value
    }
    
    apdu.push(0x1F); // Closing tag 1
    
    match send_request_and_get_response(socket, device, &apdu, invoke_id) {
        Ok(response) => {
            // Debug - commented out
            // if object.object_type == ObjectType::AnalogInput && (object.instance == 61 || object.instance == 18) {
            //     println!("          Response length: {} bytes", response.len());
            //     // Show hex response
            //     if response.starts_with("0x") {
            //         println!("          Response hex: {}", &response[2..]);
            //     } else {
            //         println!("          Response: {}", response);
            //     }
            // }
            
            // if response.len() < 50 {
            //     // Check if it's an error or abort response
            //     if response.starts_with("0x") && response.len() > 2 {
            //         let hex_str = &response[2..];
            //         if let Ok(bytes) = decode_hex(hex_str) {
            //             if bytes.len() > 1 {
            //                 let pdu_type = (bytes[0] & 0xF0) >> 4;
            //                 if pdu_type == 5 {
            //                     println!("        {} {} returned ERROR response",
            //                         object_type_name(object.object_type), object.instance);
            //                 } else if pdu_type == 7 {
            //                     println!("        {} {} returned ABORT response",
            //                         object_type_name(object.object_type), object.instance);
            //                 } else {
            //                     println!("        {} {} returned short response: {} bytes",
            //                         object_type_name(object.object_type), object.instance, response.len());
            //                 }
            //             }
            //         }
            //     }
            // }
            
            // Parse the response to extract all properties
            let props = parse_all_properties_response(&response);
            // No debug output needed
            props
        }
        Err(e) => {
            // println!("        Error reading properties: {}", e);
            // No fallback - return error
            Err(e)
        }
    }
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
                                            // Debug for Device 5047
                                            if device.device_id == 5047 && apdu_data.len() >= 140 && apdu_data.len() <= 150 {
                                                println!("        Device 5047 RPM response {} bytes, first 30: {:02X?}",
                                                         apdu_data.len(), &apdu_data[0..30]);
                                            }
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
                                    
                                    // Try to parse as raw property data
                                    return parse_raw_response(apdu_data);
                                } else if pdu_type == 0x5 { // Error
                                    return Err("Device returned error".into());
                                } else if pdu_type == 0x7 { // Abort
                                    // Device aborted the request - this is common for unsupported properties
                                    return Err("Property not supported (abort)".into());
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
                
                // Show present value for I/O objects
                if let Some(value) = &obj.present_value {
                    println!("      {:2}. {} {} - {} = {}", i + 1, type_name, obj.instance, obj_name, value);
                } else {
                    println!("      {:2}. {} {} - {}", i + 1, type_name, obj.instance, obj_name);
                }
            }
        } else {
            println!("   OBJECTS: Unable to read object list");
        }
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
                            Ok(s) => Ok(s.to_string()),
                            Err(_) => Ok(format!("(invalid UTF-8: 0x{})", hex::encode(string_data)))
                        }
                    },
                    _ => {
                        // For other character sets, try UTF-8 anyway as a fallback
                        match std::str::from_utf8(string_data) {
                            Ok(s) => Ok(s.to_string()),
                            Err(_) => Ok(format!("(charset {}: 0x{})", charset, hex::encode(string_data)))
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

fn parse_all_properties_response(data: &str) -> Result<HashMap<u32, String>, Box<dyn std::error::Error>> {
    let mut properties = HashMap::new();
    
    // Handle hex-encoded response
    if data.starts_with("0x") {
        let hex_str = &data[2..];
        if let Ok(bytes) = decode_hex(hex_str) {
            // println!("        Parsing ReadPropertyMultiple response, {} bytes", bytes.len());
            
            // Skip Complex-ACK PDU header and service choice
            let mut i = 0;
            
            // Skip Complex-ACK PDU header and look for service choice 0x0E
            let mut service_choice_pos = None;
            for j in 0..std::cmp::min(10, bytes.len()) {
                if bytes[j] == 0x0E {
                    service_choice_pos = Some(j);
                    break;
                }
            }
            
            if let Some(pos) = service_choice_pos {
                i = pos + 1; // Start after service choice
            } else if bytes.len() > 20 {
                // No service choice found
                if bytes[0] == 0x50 || bytes[0] == 0x70 {
                    return Ok(properties); // Error or abort response
                }
                return Ok(properties); // Can't parse without service choice
            }
            
            // Debug removed - parsing works correctly
            
            // In ReadPropertyMultiple response after service choice, we have:
            // 0E (opening tag for object 0)
            // 0C (object identifier)
            // 1E (opening tag for property list)
            // ...
            // 1F (closing tag for property list)
            // 0F (closing tag for object 0)
            
            // Look for opening tag 0E (context tag for list of read access results)
            if i < bytes.len() && bytes[i] == 0x0E {
                i += 1; // Skip opening tag
                
                // Now look for object identifier (0x0C)
                if i + 4 < bytes.len() && bytes[i] == 0x0C {
                    i += 5; // Skip object identifier (tag + 4 bytes)
                    
                    // Now we should be at the property list opening tag (0x1E)
                    if i < bytes.len() && bytes[i] == 0x1E {
                        i += 1;
                        
                        // Parse properties until closing tag (0x1F)
                        let mut _prop_count = 0;
                        while i < bytes.len() && bytes[i] != 0x1F {
                            // Look for property identifier context tags (0x29)
                            if bytes[i] == 0x29 && i + 1 < bytes.len() {
                                _prop_count += 1;
                                let prop_id = bytes[i + 1] as u32;
                                i += 2;
                                
                                // Skip opening tag 4E if present (property value opening tag)
                                if i < bytes.len() && bytes[i] == 0x4E {
                                    i += 1;
                                }
                                
                                // Now parse the value
                                if i < bytes.len() {
                                    // Debug for property 77 (Object_Name) - commented out
                                    // if prop_id == 77 && i + 10 < bytes.len() {
                                    //     println!("        Found Object_Name at position {}, next 10 bytes: {:02X} {:02X} {:02X} {:02X} {:02X} {:02X} {:02X} {:02X} {:02X} {:02X}",
                                    //         i, bytes[i], bytes[i+1], bytes[i+2], bytes[i+3], bytes[i+4],
                                    //         bytes[i+5], bytes[i+6], bytes[i+7], bytes[i+8], bytes[i+9]);
                                    // }
                                    
                                    // Try to determine the length of the value
                                    let value_result = parse_bacnet_application_tag(&bytes[i..]);
                                    match value_result {
                                        Ok(value) => {
                                            properties.insert(prop_id, value);
                                            // Skip past the value (estimate based on tag type)
                                            if i < bytes.len() {
                                                let tag = bytes[i];
                                                let tag_number = (tag >> 4) & 0x0F;
                                                let length_value = tag & 0x07;
                                                
                                                // Calculate skip length more accurately
                                                let skip_len = if tag_number == 7 && length_value == 5 {
                                                    // Character string with extended length
                                                    if i + 1 < bytes.len() {
                                                        let str_len = bytes[i + 1] as usize;
                                                        2 + str_len // tag + length byte + string data
                                                    } else {
                                                        2
                                                    }
                                                } else if length_value <= 4 {
                                                    1 + length_value as usize
                                                } else if length_value == 5 && i + 1 < bytes.len() {
                                                    2 + bytes[i + 1] as usize
                                                } else {
                                                    1
                                                };
                                                i += skip_len;
                                            } else {
                                                i += 1;
                                            }
                                        }
                                        Err(_e) => {
                                            // Debug error - commented out
                                            // println!("        Failed to parse value for property {}: {}", prop_id, e);
                                            i += 1;
                                        }
                                    }
                                    
                                    // Skip closing tag 4F if present
                                    if i < bytes.len() && bytes[i] == 0x4F {
                                        i += 1;
                                    }
                                } else {
                                    i += 1;
                                }
                            } else if bytes[i] == 0x59 && i + 1 < bytes.len() {
                                // Context tag 5 (property identifier) with 2-byte encoding
                                let prop_id = ((bytes[i + 1] as u32) << 8) | (bytes[i + 2] as u32);
                                i += 3;
                                
                                // Skip opening tag 4E if present
                                if i < bytes.len() && bytes[i] == 0x4E {
                                    i += 1;
                                }
                                
                                // Parse value
                                if i < bytes.len() {
                                    if let Ok(value) = parse_bacnet_application_tag(&bytes[i..]) {
                                        properties.insert(prop_id, value);
                                        // Skip the parsed value
                                        let tag = bytes[i];
                                        let length_value = tag & 0x07;
                                        let skip_len = if length_value <= 4 {
                                            1 + length_value as usize
                                        } else if length_value == 5 && i + 1 < bytes.len() {
                                            2 + bytes[i + 1] as usize
                                        } else {
                                            1
                                        };
                                        i += skip_len;
                                    } else {
                                        i += 1;
                                    }
                                }
                                
                                if i < bytes.len() && bytes[i] == 0x4F {
                                    i += 1;
                                }
                            } else {
                                i += 1;
                            }
                        }
                    }
                }
            }
        }
    }
    
    // Debug - commented out
    // if data.starts_with("0x") && properties.is_empty() {
    //     let hex_str = &data[2..];
    //     if let Ok(bytes) = decode_hex(hex_str) {
    //         if bytes.len() > 60 {
    //             println!("        WARNING: {} byte response but no properties parsed!", bytes.len());
    //             // Show first few bytes to debug
    //             if bytes.len() > 20 {
    //                 print!("        First 20 bytes: ");
    //                 for j in 0..20 {
    //                     print!("{:02X} ", bytes[j]);
    //                 }
    //                 println!();
    //             }
    //         }
    //     }
    // }
    // println!("        Parsed {} properties from response", properties.len());
    Ok(properties)
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
    
    let length = (tag & 0x07) as usize;
    if start + 1 + length + 1 > data.len() {
        return Err("Insufficient data for string".into());
    }
    
    let charset = data[start + 1];
    let string_data = &data[start + 2..start + 1 + length + 1];
    
    match charset {
        0 => { // UTF-8
            match std::str::from_utf8(string_data) {
                Ok(s) => Ok(s.to_string()),
                Err(_) => Ok(format!("(invalid UTF-8: 0x{})", hex::encode(string_data)))
            }
        },
        _ => Ok(format!("(charset {}: 0x{})", charset, hex::encode(string_data)))
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
        _ => "Unknown",
    }
}

fn parse_units_from_response(response: &str) -> Result<String, Box<dyn std::error::Error>> {
    // Handle hex response starting with 0x
    if response.starts_with("0x") {
        let hex_str = &response[2..];
        if let Ok(bytes) = decode_hex(hex_str) {
            // Use universal decoder - units will be returned as enumerated values
            if let Ok(value) = decode_bacnet_value(&bytes) {
                // Convert common unit enumerations to readable names
                match value.as_str() {
                    "95" => return Ok("degrees-celsius".to_string()),
                    "96" => return Ok("degrees-fahrenheit".to_string()),
                    "98" => return Ok("percent".to_string()),
                    "99" => return Ok("percent-relative-humidity".to_string()),
                    _ => return Ok(value),
                }
            }
        }
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