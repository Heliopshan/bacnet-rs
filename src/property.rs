//! BACnet Property Value Decoders
//!
//! This module provides utilities for decoding BACnet property values
//! from their encoded representations into typed Rust values.

#[cfg(not(feature = "std"))]
use alloc::{string::String, vec::Vec};

use crate::object::ObjectType;

/// Decoded BACnet property value
#[derive(Debug, Clone, PartialEq)]
pub enum PropertyValue {
    /// Real (float) value
    Real(f32),
    /// Boolean value
    Boolean(bool),
    /// Unsigned integer value
    Unsigned(u32),
    /// Signed integer value
    Signed(i32),
    /// Character string value
    CharacterString(String),
    /// Enumerated value
    Enumerated(u32),
    /// Bit string value
    BitString(Vec<bool>),
    /// Date value (year, month, day, weekday)
    Date(u16, u8, u8, u8),
    /// Time value (hour, minute, second, hundredths)
    Time(u8, u8, u8, u8),
    /// Object identifier value
    ObjectIdentifier(u16, u32), // (object_type, instance)
    /// Null value
    Null,
    /// Unknown/unsupported value type
    Unknown(Vec<u8>),
}

impl PropertyValue {
    /// Get the value as a display string
    pub fn as_display_string(&self) -> String {
        match self {
            PropertyValue::Real(f) => format!("{:.2}", f),
            PropertyValue::Boolean(b) => {
                if *b {
                    "True".to_string()
                } else {
                    "False".to_string()
                }
            }
            PropertyValue::Unsigned(u) => u.to_string(),
            PropertyValue::Signed(i) => i.to_string(),
            PropertyValue::CharacterString(s) => s.clone(),
            PropertyValue::Enumerated(e) => format!("Enum({})", e),
            PropertyValue::BitString(bits) => {
                let bit_str: String = bits.iter().map(|b| if *b { '1' } else { '0' }).collect();
                format!("Bits({})", bit_str)
            }
            PropertyValue::Date(y, m, d, w) => format!("{:04}-{:02}-{:02} (DoW:{})", y, m, d, w),
            PropertyValue::Time(h, m, s, hs) => format!("{:02}:{:02}:{:02}.{:02}", h, m, s, hs),
            PropertyValue::ObjectIdentifier(t, i) => format!("Object({}, {})", t, i),
            PropertyValue::Null => "Null".to_string(),
            PropertyValue::Unknown(_) => "Unknown".to_string(),
        }
    }

    /// Check if this is a numeric value
    pub fn is_numeric(&self) -> bool {
        matches!(
            self,
            PropertyValue::Real(_) | PropertyValue::Unsigned(_) | PropertyValue::Signed(_)
        )
    }

    /// Get numeric value as f64 if possible
    pub fn as_numeric(&self) -> Option<f64> {
        match self {
            PropertyValue::Real(f) => Some(*f as f64),
            PropertyValue::Unsigned(u) => Some(*u as f64),
            PropertyValue::Signed(i) => Some(*i as f64),
            _ => None,
        }
    }
}

/// Extract character string from BACnet encoded data
pub fn decode_character_string(data: &[u8]) -> Option<(PropertyValue, usize)> {
    if data.len() < 2 {
        return None;
    }

    // Check for character string application tag (0x75) or context tag
    let (_tag, mut pos) = if data[0] == 0x75 {
        // Application tag with length in next byte
        (0x75, 1)
    } else if (data[0] & 0xF0) == 0x70 {
        // Context tag for character string
        (data[0], 1)
    } else {
        return None;
    };

    if pos >= data.len() {
        return None;
    }

    let length = data[pos] as usize;
    pos += 1;

    if data.len() < pos + length || length == 0 {
        return None;
    }

    // Skip encoding byte (typically 0 for ANSI X3.4)
    if pos >= data.len() {
        return None;
    }

    let _encoding = data[pos];
    pos += 1;

    if data.len() < pos + length - 1 {
        return None;
    }

    let string_data = &data[pos..pos + length - 1];
    let string = String::from_utf8_lossy(string_data).to_string();

    Some((PropertyValue::CharacterString(string), pos + length - 1))
}

/// Extract real (float) value from BACnet encoded data
pub fn decode_real(data: &[u8]) -> Option<(PropertyValue, usize)> {
    if data.len() < 5 {
        return None;
    }

    // Check for real application tag (0x44)
    if data[0] != 0x44 {
        return None;
    }

    let bytes = [data[1], data[2], data[3], data[4]];
    let value = f32::from_be_bytes(bytes);

    Some((PropertyValue::Real(value), 5))
}

/// Extract boolean value from BACnet encoded data
pub fn decode_boolean(data: &[u8]) -> Option<(PropertyValue, usize)> {
    if data.len() < 2 {
        return None;
    }

    // Check for boolean application tag (0x11)
    if data[0] != 0x11 {
        return None;
    }

    let value = data[1] != 0;
    Some((PropertyValue::Boolean(value), 2))
}

/// Extract unsigned integer from BACnet encoded data
pub fn decode_unsigned(data: &[u8]) -> Option<(PropertyValue, usize)> {
    if data.len() < 2 {
        return None;
    }

    // Check for unsigned application tag (0x21, 0x22, 0x23, or 0x24)
    let (_tag, length) = match data[0] {
        0x21 => (0x21, 1), // 1 byte
        0x22 => (0x22, 2), // 2 bytes
        0x23 => (0x23, 3), // 3 bytes
        0x24 => (0x24, 4), // 4 bytes
        _ => return None,
    };

    if data.len() < 1 + length {
        return None;
    }

    let mut value = 0u32;
    for i in 0..length {
        value = (value << 8) | (data[1 + i] as u32);
    }

    Some((PropertyValue::Unsigned(value), 1 + length))
}

/// Extract signed integer from BACnet encoded data  
pub fn decode_signed(data: &[u8]) -> Option<(PropertyValue, usize)> {
    if data.len() < 2 {
        return None;
    }

    // Check for signed application tag (0x31, 0x32, 0x33, or 0x34)
    let (_tag, length) = match data[0] {
        0x31 => (0x31, 1), // 1 byte
        0x32 => (0x32, 2), // 2 bytes
        0x33 => (0x33, 3), // 3 bytes
        0x34 => (0x34, 4), // 4 bytes
        _ => return None,
    };

    if data.len() < 1 + length {
        return None;
    }

    let mut value = if (data[1] & 0x80) != 0 {
        0xFFFFFFFFu32
    } else {
        0
    }; // Sign extend
    for i in 0..length {
        value = (value << 8) | (data[1 + i] as u32);
    }

    Some((PropertyValue::Signed(value as i32), 1 + length))
}

/// Extract enumerated value from BACnet encoded data
pub fn decode_enumerated(data: &[u8]) -> Option<(PropertyValue, usize)> {
    if data.len() < 2 {
        return None;
    }

    // Check for enumerated application tag (0x91, 0x92, 0x93, or 0x94)
    let (_tag, length) = match data[0] {
        0x91 => (0x91, 1), // 1 byte
        0x92 => (0x92, 2), // 2 bytes
        0x93 => (0x93, 3), // 3 bytes
        0x94 => (0x94, 4), // 4 bytes
        _ => return None,
    };

    if data.len() < 1 + length {
        return None;
    }

    let mut value = 0u32;
    for i in 0..length {
        value = (value << 8) | (data[1 + i] as u32);
    }

    Some((PropertyValue::Enumerated(value), 1 + length))
}

/// Extract object identifier from BACnet encoded data
pub fn decode_object_identifier(data: &[u8]) -> Option<(PropertyValue, usize)> {
    if data.len() < 5 {
        return None;
    }

    // Check for object identifier application tag (0xC4)
    if data[0] != 0xC4 {
        return None;
    }

    let obj_id_bytes = [data[1], data[2], data[3], data[4]];
    let obj_id = u32::from_be_bytes(obj_id_bytes);
    let object_type = ((obj_id >> 22) & 0x3FF) as u16;
    let instance = obj_id & 0x3FFFFF;

    Some((PropertyValue::ObjectIdentifier(object_type, instance), 5))
}

/// Extract present value based on object type
pub fn decode_present_value(
    data: &[u8],
    object_type: ObjectType,
) -> Option<(PropertyValue, usize)> {
    if data.is_empty() {
        return None;
    }

    match object_type {
        ObjectType::AnalogInput | ObjectType::AnalogOutput | ObjectType::AnalogValue => {
            decode_real(data)
        }
        ObjectType::BinaryInput | ObjectType::BinaryOutput | ObjectType::BinaryValue => {
            decode_boolean(data)
        }
        ObjectType::MultiStateInput
        | ObjectType::MultiStateOutput
        | ObjectType::MultiStateValue => decode_unsigned(data),
        _ => None,
    }
}

/// Decode engineering units enumeration
pub fn decode_units(data: &[u8]) -> Option<(String, usize)> {
    if let Some((PropertyValue::Enumerated(units_id), consumed)) = decode_enumerated(data) {
        let units_name = match units_id {
            // Basic units
            0 => "no-units",
            1 => "percent",
            2 => "parts-per-million",
            3 => "parts-per-billion",
            4 => "microsiemens",
            5 => "millisiemens",
            6 => "siemens",
            7 => "mole-percent",

            // Area units
            8 => "square-meters",
            9 => "square-centimeters",
            10 => "square-feet",
            11 => "square-inches",

            // Currency units
            12 => "currency1",
            13 => "currency2",
            14 => "currency3",
            15 => "currency4",
            16 => "currency5",
            17 => "currency6",
            18 => "currency7",
            19 => "currency8",
            20 => "currency9",
            21 => "currency10",

            // Electrical units
            22 => "milliamperes",
            23 => "amperes",
            24 => "ampere-seconds",
            25 => "ampere-square-meters",
            26 => "amperes-per-meter",
            27 => "amperes-per-square-meter",
            28 => "ampere-square-meters-per-joule-second",
            29 => "farads",
            30 => "henrys",
            31 => "ohms",
            32 => "ohm-meters",
            33 => "milliohms",
            34 => "kilohms",
            35 => "megohms",
            36 => "siemens-per-meter",
            37 => "teslas",
            38 => "volts",
            39 => "millivolts",
            40 => "kilovolts",
            41 => "megavolts",
            42 => "volt-amperes",
            43 => "kilovolt-amperes",
            44 => "megavolt-amperes",
            45 => "volt-amperes-reactive",
            46 => "kilovolt-amperes-reactive",
            47 => "megavolt-amperes-reactive",
            48 => "volts-per-degree-kelvin",
            49 => "volts-per-meter",
            50 => "webers",

            // Energy units
            51 => "btus",
            52 => "kilo-btus",
            53 => "mega-btus",
            54 => "kilojoules",
            55 => "megajoules",
            56 => "gigajoules",
            57 => "calories",
            58 => "kilocalories",
            59 => "megacalories",
            60 => "gigacalories",
            61 => "joules",

            // Temperature units
            62 => "degrees-celsius",
            63 => "degrees-fahrenheit",
            64 => "degrees-kelvin",
            65 => "degrees-rankine",
            66 => "delta-degrees-fahrenheit",

            // Pressure units
            67 => "pascals",
            68 => "kilopascals",
            69 => "megapascals",
            70 => "millibars",
            71 => "bars",
            72 => "pounds-per-square-inch",
            73 => "centimeters-of-water",
            74 => "inches-of-water",
            75 => "millimeters-of-mercury",
            76 => "centimeters-of-mercury",
            77 => "inches-of-mercury",

            // Time units
            78 => "years",
            79 => "months",
            80 => "weeks",
            81 => "days",
            82 => "hours",
            83 => "minutes",
            84 => "seconds",
            85 => "hundredths-seconds",
            86 => "milliseconds",

            // Volume units
            87 => "cubic-feet",
            88 => "cubic-meters",
            89 => "imperial-gallons",
            90 => "milliliters",
            91 => "liters",
            92 => "us-gallons",

            // Volumetric Flow units
            93 => "cubic-feet-per-second",
            94 => "cubic-feet-per-minute",
            95 => "million-standard-cubic-feet-per-minute",
            96 => "cubic-feet-per-hour",
            97 => "cubic-feet-per-day",
            98 => "standard-cubic-feet-per-day",
            99 => "million-standard-cubic-feet-per-day",
            100 => "thousand-cubic-feet-per-day",
            101 => "thousand-standard-cubic-feet-per-day",
            102 => "pounds-mass-per-day",
            103 => "cubic-meters-per-second",
            104 => "cubic-meters-per-minute",
            105 => "cubic-meters-per-hour",
            106 => "cubic-meters-per-day",
            107 => "imperial-gallons-per-minute",
            108 => "milliliters-per-second",
            109 => "liters-per-second",
            110 => "liters-per-minute",
            111 => "liters-per-hour",
            112 => "us-gallons-per-minute",
            113 => "us-gallons-per-hour",

            // Power units
            114 => "watts",
            115 => "kilowatts",
            116 => "megawatts",
            117 => "btus-per-hour",
            118 => "kilo-btus-per-hour",
            119 => "horsepower",
            120 => "tons-refrigeration",

            // Mass units
            121 => "grams",
            122 => "kilograms",
            123 => "pounds-mass",
            124 => "tons",

            // Mass Flow units
            125 => "grams-per-second",
            126 => "grams-per-minute",
            127 => "kilograms-per-second",
            128 => "kilograms-per-minute",
            129 => "kilograms-per-hour",
            130 => "pounds-mass-per-minute",
            131 => "pounds-mass-per-hour",
            132 => "pounds-mass-per-second",
            133 => "tons-per-hour",

            // Length units
            134 => "millimeters",
            135 => "centimeters",
            136 => "meters",
            137 => "inches",
            138 => "feet",

            // Light units
            139 => "candelas",
            140 => "candelas-per-square-meter",
            141 => "watts-per-square-foot",
            142 => "watts-per-square-meter",
            143 => "lumens",
            144 => "luxes",
            145 => "foot-candles",

            // Velocity units
            146 => "meters-per-second",
            147 => "kilometers-per-hour",
            148 => "feet-per-second",
            149 => "feet-per-minute",
            150 => "miles-per-hour",

            // Acceleration units
            151 => "meters-per-second-per-second",

            // Force units
            152 => "newtons",

            // Frequency units
            153 => "cycles-per-hour",
            154 => "cycles-per-minute",
            155 => "hertz",
            156 => "kilohertz",
            157 => "megahertz",
            158 => "per-hour",

            // Humidity units
            159 => "grams-of-water-per-kilogram-dry-air",
            160 => "percent-relative-humidity",

            // Enthalpy units
            161 => "btus-per-pound",
            162 => "btus-per-pound-dry-air",
            163 => "joules-per-kilogram",
            164 => "joules-per-kilogram-dry-air",
            165 => "kilojoules-per-kilogram",
            166 => "kilojoules-per-kilogram-dry-air",
            167 => "megajoules-per-kilogram-dry-air",

            // Entropy units
            168 => "joules-per-degree-kelvin",
            169 => "joules-per-kilogram-degree-kelvin",
            170 => "kilojoules-per-degree-kelvin",
            171 => "megajoules-per-degree-kelvin",

            // Specific Heat units
            172 => "joules-per-kilogram-degree-kelvin",

            // Specific Volume units
            173 => "cubic-meters-per-kilogram",
            174 => "cubic-feet-per-pound",

            // Thermal Conductivity units
            175 => "watts-per-meter-degree-kelvin",

            // Thermal Resistance units
            176 => "square-meter-degree-kelvin-per-watt",

            // Thermal Capacity units
            177 => "joules-per-degree-kelvin",

            // Energy Density units
            178 => "joules-per-cubic-meter",
            179 => "watt-hours-per-cubic-meter",
            180 => "btus-per-cubic-foot",

            // Power Density units
            181 => "watts-per-cubic-meter",

            // Additional common HVAC units
            182 => "cfm-per-square-foot",
            183 => "liters-per-second-per-square-meter",
            184 => "cubic-feet-per-minute-per-square-foot",
            185 => "watts-per-square-meter-degree-kelvin",
            186 => "square-feet",
            187 => "square-meters",
            188 => "btus-per-hour-square-foot",
            189 => "btus-per-hour-square-foot-degree-fahrenheit",
            190 => "degrees-fahrenheit-hour-square-feet-per-btu",

            _ => "unknown-units",
        };
        Some((units_name.to_string(), consumed))
    } else {
        None
    }
}

/// Get the numeric unit ID from a unit name string
pub fn get_unit_id(unit_name: &str) -> Option<u32> {
    match unit_name {
        "no-units" => Some(0),
        "percent" => Some(1),
        "parts-per-million" => Some(2),
        "parts-per-billion" => Some(3),
        "microsiemens" => Some(4),
        "millisiemens" => Some(5),
        "siemens" => Some(6),
        "mole-percent" => Some(7),
        "square-meters" => Some(8),
        "square-centimeters" => Some(9),
        "square-feet" => Some(10),
        "square-inches" => Some(11),
        "currency1" => Some(12),
        "currency2" => Some(13),
        "currency3" => Some(14),
        "currency4" => Some(15),
        "currency5" => Some(16),
        "currency6" => Some(17),
        "currency7" => Some(18),
        "currency8" => Some(19),
        "currency9" => Some(20),
        "currency10" => Some(21),
        "milliamperes" => Some(22),
        "amperes" => Some(23),
        "ampere-seconds" => Some(24),
        "ampere-square-meters" => Some(25),
        "amperes-per-meter" => Some(26),
        "amperes-per-square-meter" => Some(27),
        "ampere-square-meters-per-joule-second" => Some(28),
        "farads" => Some(29),
        "henrys" => Some(30),
        "ohms" => Some(31),
        "ohm-meters" => Some(32),
        "milliohms" => Some(33),
        "kilohms" => Some(34),
        "megohms" => Some(35),
        "siemens-per-meter" => Some(36),
        "teslas" => Some(37),
        "volts" => Some(38),
        "millivolts" => Some(39),
        "kilovolts" => Some(40),
        "megavolts" => Some(41),
        "volt-amperes" => Some(42),
        "kilovolt-amperes" => Some(43),
        "megavolt-amperes" => Some(44),
        "volt-amperes-reactive" => Some(45),
        "kilovolt-amperes-reactive" => Some(46),
        "megavolt-amperes-reactive" => Some(47),
        "volts-per-degree-kelvin" => Some(48),
        "volts-per-meter" => Some(49),
        "webers" => Some(50),
        "btus" => Some(51),
        "kilo-btus" => Some(52),
        "mega-btus" => Some(53),
        "kilojoules" => Some(54),
        "megajoules" => Some(55),
        "gigajoules" => Some(56),
        "calories" => Some(57),
        "kilocalories" => Some(58),
        "megacalories" => Some(59),
        "gigacalories" => Some(60),
        "joules" => Some(61),
        "degrees-celsius" => Some(62),
        "degrees-fahrenheit" => Some(63),
        "degrees-kelvin" => Some(64),
        "degrees-rankine" => Some(65),
        "delta-degrees-fahrenheit" => Some(66),
        "pascals" => Some(67),
        "kilopascals" => Some(68),
        "megapascals" => Some(69),
        "millibars" => Some(70),
        "bars" => Some(71),
        "pounds-per-square-inch" => Some(72),
        "centimeters-of-water" => Some(73),
        "inches-of-water" => Some(74),
        "millimeters-of-mercury" => Some(75),
        "centimeters-of-mercury" => Some(76),
        "inches-of-mercury" => Some(77),
        "years" => Some(78),
        "months" => Some(79),
        "weeks" => Some(80),
        "days" => Some(81),
        "hours" => Some(82),
        "minutes" => Some(83),
        "seconds" => Some(84),
        "hundredths-seconds" => Some(85),
        "milliseconds" => Some(86),
        "cubic-feet" => Some(87),
        "cubic-meters" => Some(88),
        "imperial-gallons" => Some(89),
        "milliliters" => Some(90),
        "liters" => Some(91),
        "us-gallons" => Some(92),
        "cubic-feet-per-second" => Some(93),
        "cubic-feet-per-minute" => Some(94),
        "million-standard-cubic-feet-per-minute" => Some(95),
        "cubic-feet-per-hour" => Some(96),
        "cubic-feet-per-day" => Some(97),
        "standard-cubic-feet-per-day" => Some(98),
        "million-standard-cubic-feet-per-day" => Some(99),
        "thousand-cubic-feet-per-day" => Some(100),
        "thousand-standard-cubic-feet-per-day" => Some(101),
        "pounds-mass-per-day" => Some(102),
        "cubic-meters-per-second" => Some(103),
        "cubic-meters-per-minute" => Some(104),
        "cubic-meters-per-hour" => Some(105),
        "cubic-meters-per-day" => Some(106),
        "imperial-gallons-per-minute" => Some(107),
        "milliliters-per-second" => Some(108),
        "liters-per-second" => Some(109),
        "liters-per-minute" => Some(110),
        "liters-per-hour" => Some(111),
        "us-gallons-per-minute" => Some(112),
        "us-gallons-per-hour" => Some(113),
        "watts" => Some(114),
        "kilowatts" => Some(115),
        "megawatts" => Some(116),
        "btus-per-hour" => Some(117),
        "kilo-btus-per-hour" => Some(118),
        "horsepower" => Some(119),
        "tons-refrigeration" => Some(120),
        "grams" => Some(121),
        "kilograms" => Some(122),
        "pounds-mass" => Some(123),
        "tons" => Some(124),
        "grams-per-second" => Some(125),
        "grams-per-minute" => Some(126),
        "kilograms-per-second" => Some(127),
        "kilograms-per-minute" => Some(128),
        "kilograms-per-hour" => Some(129),
        "pounds-mass-per-minute" => Some(130),
        "pounds-mass-per-hour" => Some(131),
        "pounds-mass-per-second" => Some(132),
        "tons-per-hour" => Some(133),
        "millimeters" => Some(134),
        "centimeters" => Some(135),
        "meters" => Some(136),
        "inches" => Some(137),
        "feet" => Some(138),
        "candelas" => Some(139),
        "candelas-per-square-meter" => Some(140),
        "watts-per-square-foot" => Some(141),
        "watts-per-square-meter" => Some(142),
        "lumens" => Some(143),
        "luxes" => Some(144),
        "foot-candles" => Some(145),
        "meters-per-second" => Some(146),
        "kilometers-per-hour" => Some(147),
        "feet-per-second" => Some(148),
        "feet-per-minute" => Some(149),
        "miles-per-hour" => Some(150),
        "meters-per-second-per-second" => Some(151),
        "newtons" => Some(152),
        "cycles-per-hour" => Some(153),
        "cycles-per-minute" => Some(154),
        "hertz" => Some(155),
        "kilohertz" => Some(156),
        "megahertz" => Some(157),
        "per-hour" => Some(158),
        "grams-of-water-per-kilogram-dry-air" => Some(159),
        "percent-relative-humidity" => Some(160),
        "btus-per-pound" => Some(161),
        "btus-per-pound-dry-air" => Some(162),
        "joules-per-kilogram" => Some(163),
        "joules-per-kilogram-dry-air" => Some(164),
        "kilojoules-per-kilogram" => Some(165),
        "kilojoules-per-kilogram-dry-air" => Some(166),
        "megajoules-per-kilogram-dry-air" => Some(167),
        "joules-per-degree-kelvin" => Some(168),
        "joules-per-kilogram-degree-kelvin" => Some(169),
        "kilojoules-per-degree-kelvin" => Some(170),
        "megajoules-per-degree-kelvin" => Some(171),
        "cubic-meters-per-kilogram" => Some(173),
        "cubic-feet-per-pound" => Some(174),
        "watts-per-meter-degree-kelvin" => Some(175),
        "square-meter-degree-kelvin-per-watt" => Some(176),
        "joules-per-cubic-meter" => Some(178),
        "watt-hours-per-cubic-meter" => Some(179),
        "btus-per-cubic-foot" => Some(180),
        "watts-per-cubic-meter" => Some(181),
        "cfm-per-square-foot" => Some(182),
        "liters-per-second-per-square-meter" => Some(183),
        "cubic-feet-per-minute-per-square-foot" => Some(184),
        "watts-per-square-meter-degree-kelvin" => Some(185),
        "btus-per-hour-square-foot" => Some(188),
        "btus-per-hour-square-foot-degree-fahrenheit" => Some(189),
        "degrees-fahrenheit-hour-square-feet-per-btu" => Some(190),
        _ => None,
    }
}

/// Extract bit string (status flags) from BACnet encoded data
pub fn decode_bit_string(data: &[u8]) -> Option<(PropertyValue, usize)> {
    if data.len() < 3 {
        return None;
    }

    // Check for bit string application tag (0x82)
    if data[0] != 0x82 {
        return None;
    }

    let length = data[1] as usize;
    if data.len() < 2 + length {
        return None;
    }

    let unused_bits = data[2];
    let mut bits = Vec::new();

    for byte in data.iter().take(2 + length).skip(3) {
        for bit_pos in (0..8).rev() {
            bits.push((byte & (1 << bit_pos)) != 0);
        }
    }

    // Remove unused bits from the end
    if unused_bits > 0 && unused_bits < 8 {
        let total_bits = bits.len();
        bits.truncate(total_bits - unused_bits as usize);
    }

    Some((PropertyValue::BitString(bits), 2 + length))
}

/// Decode status flags specifically
pub fn decode_status_flags(data: &[u8]) -> Option<(Vec<bool>, usize)> {
    if let Some((PropertyValue::BitString(bits), consumed)) = decode_bit_string(data) {
        // Status flags are typically 4 bits: in-alarm, fault, overridden, out-of-service
        Some((bits, consumed))
    } else {
        None
    }
}

/// Generic property value decoder - tries multiple decoders
pub fn decode_property_value(data: &[u8]) -> Option<(PropertyValue, usize)> {
    if data.is_empty() {
        return None;
    }

    // Try different decoders based on the tag
    match data[0] {
        0x00 => Some((PropertyValue::Null, 1)),
        0x11 => decode_boolean(data),
        0x21..=0x24 => decode_unsigned(data),
        0x31..=0x34 => decode_signed(data),
        0x44 => decode_real(data),
        0x75 => decode_character_string(data),
        0x82 => decode_bit_string(data),
        0x91..=0x94 => decode_enumerated(data),
        0xC4 => decode_object_identifier(data),
        _ => {
            // Unknown tag - return raw data
            Some((PropertyValue::Unknown(data.to_vec()), data.len()))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_decode_real() {
        // Test encoding of 23.5
        let data = [0x44, 0x41, 0xBC, 0x00, 0x00];
        let (value, consumed) = decode_real(&data).unwrap();
        assert_eq!(consumed, 5);
        if let PropertyValue::Real(f) = value {
            assert!((f - 23.5).abs() < 0.01);
        } else {
            panic!("Expected Real value");
        }
    }

    #[test]
    fn test_decode_boolean() {
        // Test true
        let data = [0x11, 0x01];
        let (value, consumed) = decode_boolean(&data).unwrap();
        assert_eq!(consumed, 2);
        assert_eq!(value, PropertyValue::Boolean(true));

        // Test false
        let data = [0x11, 0x00];
        let (value, consumed) = decode_boolean(&data).unwrap();
        assert_eq!(consumed, 2);
        assert_eq!(value, PropertyValue::Boolean(false));
    }

    #[test]
    fn test_decode_unsigned() {
        // Test 1-byte unsigned
        let data = [0x21, 0x7B]; // 123
        let (value, consumed) = decode_unsigned(&data).unwrap();
        assert_eq!(consumed, 2);
        assert_eq!(value, PropertyValue::Unsigned(123));

        // Test 2-byte unsigned
        let data = [0x22, 0x01, 0x2C]; // 300
        let (value, consumed) = decode_unsigned(&data).unwrap();
        assert_eq!(consumed, 3);
        assert_eq!(value, PropertyValue::Unsigned(300));
    }

    #[test]
    fn test_decode_character_string() {
        // Test simple string "Hello"
        let data = [0x75, 0x06, 0x00, b'H', b'e', b'l', b'l', b'o'];
        let (value, consumed) = decode_character_string(&data).unwrap();
        assert_eq!(consumed, 8);
        if let PropertyValue::CharacterString(s) = value {
            assert_eq!(s, "Hello");
        } else {
            panic!("Expected CharacterString value");
        }
    }

    #[test]
    fn test_decode_enumerated() {
        // Test enumerated value 42
        let data = [0x91, 0x2A];
        let (value, consumed) = decode_enumerated(&data).unwrap();
        assert_eq!(consumed, 2);
        assert_eq!(value, PropertyValue::Enumerated(42));
    }

    #[test]
    fn test_decode_object_identifier() {
        // Test device object with instance 123
        let data = [0xC4, 0x02, 0x00, 0x00, 0x7B];
        let (value, consumed) = decode_object_identifier(&data).unwrap();
        assert_eq!(consumed, 5);
        if let PropertyValue::ObjectIdentifier(obj_type, instance) = value {
            assert_eq!(obj_type, 8); // Device object type
            assert_eq!(instance, 123);
        } else {
            panic!("Expected ObjectIdentifier value");
        }
    }

    #[test]
    fn test_property_value_display() {
        assert_eq!(PropertyValue::Real(23.45).as_display_string(), "23.45");
        assert_eq!(PropertyValue::Boolean(true).as_display_string(), "True");
        assert_eq!(PropertyValue::Unsigned(42).as_display_string(), "42");
        assert_eq!(
            PropertyValue::CharacterString("Test".to_string()).as_display_string(),
            "Test"
        );
    }

    #[test]
    fn test_decode_units() {
        // Test degrees Celsius
        let data = [0x91, 62];
        let (units, consumed) = decode_units(&data).unwrap();
        assert_eq!(consumed, 2);
        assert_eq!(units, "degrees-celsius");

        // Test kilowatts
        let data = [0x91, 115];
        let (units, consumed) = decode_units(&data).unwrap();
        assert_eq!(consumed, 2);
        assert_eq!(units, "kilowatts");

        // Test amperes
        let data = [0x91, 23];
        let (units, consumed) = decode_units(&data).unwrap();
        assert_eq!(consumed, 2);
        assert_eq!(units, "amperes");

        // Test cubic-feet-per-minute
        let data = [0x91, 94];
        let (units, consumed) = decode_units(&data).unwrap();
        assert_eq!(consumed, 2);
        assert_eq!(units, "cubic-feet-per-minute");
    }

    #[test]
    fn test_get_unit_id() {
        assert_eq!(get_unit_id("degrees-celsius"), Some(62));
        assert_eq!(get_unit_id("kilowatts"), Some(115));
        assert_eq!(get_unit_id("amperes"), Some(23));
        assert_eq!(get_unit_id("cubic-feet-per-minute"), Some(94));
        assert_eq!(get_unit_id("percent"), Some(1));
        assert_eq!(get_unit_id("nonexistent-unit"), None);
    }
}

