use std::io::Cursor;
use dlc_messages::{WireMessage, Message};
use dlc_messages::message_handler::MessageHandler;
use dlc_messages::segmentation::{SegmentChunk, SegmentStart}
use lightning::ln::wire::CustomMessageReader;
use lightning::util::ser::{Readable, Writeable, Writer};
use secp256k1_zkp::SECP256K1;
use dlc_messages::OfferDlc;
use dlc_messages::AcceptDlc;
use dlc_messages::SignDlc;


// use super::*;

fn main() {
    // Pseudo hex representation of your `DlcAccept` message
    let hex_value = "a71e00000001c1c79e1e9e2fa2840b2514902ea244f39eb3001a4037a52ea43c797d4f8412690300c706fe7ed70197a77397fb7ce8445fcf1d0b239b4ab41ebdad4f76e0a671d7830470f4fef96d0838e8f3cec33176a6a427d777b57d256f8545b570cd702972910192f8ad4eb341ac2867d203360516028b967b46ef0e5d1603b59a7d8ebc81d655dd11673febcf098006eba74b3604d0a1da818208ea2833079505a3dee7392255f0682e5b357a7382aae6e5bdcc728b94c9d0a52fb6f49ac5cbe32804fcfb71b10125e92381be588737f6ac5c28325c843c6551995880f830d926abd35ee3f8ed9fdfc47a5fd277d0df2a1f1d0bafba8efad7b127e2a232a4846ed90810c81e65750039dba803adb78100f20ca12b09b68a92b996b07a5ee47806379cedfa217848644f48d96ed6443ea7143adf1ce19a4386d0841b5071e31f5d3e4c479eab6a856b426c80d091da3de3959b29e4c2e3ae47ddba2758c2ca1c6a064dfee4671ba5010098f2595778a1596054ffcafb599f8f4a65c4215de757548c142d50b12eb67d4c1407690b808e33eba95fe818223886fd8e9ce4c758b4662636af663e0055376300a915ee71914ee8ae2c18d55b397649c0057a01f0a85c6ecf1b0eb26f7485f21b24c89013e1cb15a4bf40256e52a66751f33de46032db0801975933be2977a1e37d5d5f2d43f48481cc68783dbfeb21a35c62c1ca2eb6ee2ccfc12b74e9fd7a08fbf56fbb4bbcb01d1be3169dfda6f465020ee89c1e368d4a91e36d0d4cc44e6123db348c223988dfe147d611ae9351d6e78cfb902e3d01beed0c909e52a3aae901020047304402203812d7d194d44ec68f244cc3fd68507c563ec8c729fdfa3f4a79395b98abe84f0220704ab3f3ffd9c50c2488e59f90a90465fccc2d924d67a1e98a133676bf52f37201002102dde41aa1f21671a2e28ad92155d2d66e0b5428de15d18db4cbcf216bf00de919";

    // Convert hex_value into bytes
    let bytes = hex::decode(hex_value).unwrap();

    let handler = MessageHandler::new();
    let mut reader = Cursor::new(&mut bytes);
    let message_type =
        <u16 as Readable>::read(&mut reader).expect("to be able to read the type prefix.");
    let result = MessageHandler::read(message_type, &mut reader)
        .expect("to be able to read the message")
        .expect("to have a message");
}

// use std::io::Cursor;
// use dlc_messages::{WireMessage, Message, message_handler};
// use dlc_messages::message_handler::MessageHandler;
// use lightning::ln::wire::CustomMessageReader;
// use lightning::util::ser::{Readable, Writeable, Writer};

// fn main() {
//     // Pseudo hex representation of your `DlcAccept` message
//     let hex_value = "a71e00000001c1c79e1e9e2fa2840b2514902ea244f39eb3001a4037a52ea43c797d4f8412690300c706fe7ed70197a77397fb7ce8445fcf1d0b239b4ab41ebdad4f76e0a671d7830470f4fef96d0838e8f3cec33176a6a427d777b57d256f8545b570cd702972910192f8ad4eb341ac2867d203360516028b967b46ef0e5d1603b59a7d8ebc81d655dd11673febcf098006eba74b3604d0a1da818208ea2833079505a3dee7392255f0682e5b357a7382aae6e5bdcc728b94c9d0a52fb6f49ac5cbe32804fcfb71b10125e92381be588737f6ac5c28325c843c6551995880f830d926abd35ee3f8ed9fdfc47a5fd277d0df2a1f1d0bafba8efad7b127e2a232a4846ed90810c81e65750039dba803adb78100f20ca12b09b68a92b996b07a5ee47806379cedfa217848644f48d96ed6443ea7143adf1ce19a4386d0841b5071e31f5d3e4c479eab6a856b426c80d091da3de3959b29e4c2e3ae47ddba2758c2ca1c6a064dfee4671ba5010098f2595778a1596054ffcafb599f8f4a65c4215de757548c142d50b12eb67d4c1407690b808e33eba95fe818223886fd8e9ce4c758b4662636af663e0055376300a915ee71914ee8ae2c18d55b397649c0057a01f0a85c6ecf1b0eb26f7485f21b24c89013e1cb15a4bf40256e52a66751f33de46032db0801975933be2977a1e37d5d5f2d43f48481cc68783dbfeb21a35c62c1ca2eb6ee2ccfc12b74e9fd7a08fbf56fbb4bbcb01d1be3169dfda6f465020ee89c1e368d4a91e36d0d4cc44e6123db348c223988dfe147d611ae9351d6e78cfb902e3d01beed0c909e52a3aae901020047304402203812d7d194d44ec68f244cc3fd68507c563ec8c729fdfa3f4a79395b98abe84f0220704ab3f3ffd9c50c2488e59f90a90465fccc2d924d67a1e98a133676bf52f37201002102dde41aa1f21671a2e28ad92155d2d66e0b5428de15d18db4cbcf216bf00de919";

//     // Convert hex_value into bytes
//     let bytes = hex::decode(hex_value).expect("Decoding failed");

//     // Create instance of `MessageHandler`
//     let message_handler = MessageHandler::new();

//     // Prepare buffer
//     let mut cursor = Cursor::new(bytes);

//     // Define `msg_type` for `DlcAccept`. You would replace this value with the actual number
//     // associated with `DlcAccept`
//     let msg_type = <u16 as Readable>::read(&mut cursor).unwrap();

//     // Deserialization using the CustomMessageReader impl
//     match message_handler.read(msg_type, &mut cursor) {
//         Ok(Some(decoded_msg)) => {
//             match decoded_msg {
//                 WireMessage::Message(msg) => match msg {
//                     Message::Accept(decoded_message) => {
//                         // Handle the decoded DLCAccept message here.
//                         // This is where it will end up if the decoding is successful.
//                         println!("Decoded Message: {:?}", decoded_message);
//                     },
//                     _ => {
//                         println!("Decoded a different kind of message.");
//                     }
//                 },
//                 _ => {
//                     println!("Decoded WireMessage was not a Message variant.");
//                 }
//             }
//         },
//         Err(error) => panic!("Failed to deserialize message: {:?}", error),
//         _ => {},
//     }
// }


// use std::io::Cursor;
// use dlc_messages::message_handler::MessageHandler;
// use lightning::ln::wire::CustomMessageReader;

// fn main() {
//     // Pseudo hex representation of your `DlcAccept` message
//     let hex_value = "a71e00000001c1c79e1e9e2fa2840b2514902ea244f39eb3001a4037a52ea43c797d4f8412690300c706fe7ed70197a77397fb7ce8445fcf1d0b239b4ab41ebdad4f76e0a671d7830470f4fef96d0838e8f3cec33176a6a427d777b57d256f8545b570cd702972910192f8ad4eb341ac2867d203360516028b967b46ef0e5d1603b59a7d8ebc81d655dd11673febcf098006eba74b3604d0a1da818208ea2833079505a3dee7392255f0682e5b357a7382aae6e5bdcc728b94c9d0a52fb6f49ac5cbe32804fcfb71b10125e92381be588737f6ac5c28325c843c6551995880f830d926abd35ee3f8ed9fdfc47a5fd277d0df2a1f1d0bafba8efad7b127e2a232a4846ed90810c81e65750039dba803adb78100f20ca12b09b68a92b996b07a5ee47806379cedfa217848644f48d96ed6443ea7143adf1ce19a4386d0841b5071e31f5d3e4c479eab6a856b426c80d091da3de3959b29e4c2e3ae47ddba2758c2ca1c6a064dfee4671ba5010098f2595778a1596054ffcafb599f8f4a65c4215de757548c142d50b12eb67d4c1407690b808e33eba95fe818223886fd8e9ce4c758b4662636af663e0055376300a915ee71914ee8ae2c18d55b397649c0057a01f0a85c6ecf1b0eb26f7485f21b24c89013e1cb15a4bf40256e52a66751f33de46032db0801975933be2977a1e37d5d5f2d43f48481cc68783dbfeb21a35c62c1ca2eb6ee2ccfc12b74e9fd7a08fbf56fbb4bbcb01d1be3169dfda6f465020ee89c1e368d4a91e36d0d4cc44e6123db348c223988dfe147d611ae9351d6e78cfb902e3d01beed0c909e52a3aae901020047304402203812d7d194d44ec68f244cc3fd68507c563ec8c729fdfa3f4a79395b98abe84f0220704ab3f3ffd9c50c2488e59f90a90465fccc2d924d67a1e98a133676bf52f37201002102dde41aa1f21671a2e28ad92155d2d66e0b5428de15d18db4cbcf216bf00de919";

//     // Convert hex_value into bytes
//     let bytes = hex::decode(hex_value).expect("Decoding failed");

//     // Create instance of `MessageHandler`
//     let message_handler = MessageHandler::new();

//     // Prepare buffer
//     let mut buffer = Cursor::new(bytes);

//     // Define `msg_type` for `DlcAccept`
//     let message_type = <u16 as Readable>::read(&mut cursor).unwrap();

//     // Call the `read` function
//     match CustomMessageReader::read(&message_handler, message_type, &mut buffer) {
//         Ok(Some(msg)) => println!("{:?}", msg),
//         Ok(None) => println!("No message returned"),
//         Err(e) => println!("Error: {:?}", e),
//     }
// }

// use std::any::Any;

// // use lightning::ln::peer_handler::CustomMessageHandler;
// use lightning::{
//     ln::wire::CustomMessageReader,
//     util::ser::Readable,
// };

// Import wire message from dlc_messages
// use dlc_messages::wire::WireMessage;

// use dlc_messages::message_handler::MessageHandler;
// use dlc_messages::Message::Offer;

// use dlc_messages::WireMessage;

// use dlc_messages::OFFER_TYPE;

// use hex::decode;
// use std::io::{Cursor};

// use secp256k1_zkp::PublicKey;
// use secp256k1_zkp::SECP256K1;

// use crate::{
//     segmentation::{get_segments, segment_reader::SegmentReader},
//     Message, WireMessage,
// };

// Get offer_bytes from this 

// Decode serialized offer message

// fn some_pk() -> PublicKey {
//     PublicKey::from_secret_key(SECP256K1, &secp256k1_zkp::ONE_KEY)
// }

// extern crate dlc_messages;

// use dlc_messages::Message; // For accessing `Message` struct.

// use hex::decode;
// use std::io::Cursor;
// // use lightning::util::ser::Readable;
// use lightning::ln::wire::CustomMessageReader;
// // use dlc_messages::message_handler::MessageHandler;
// use dlc_messages::*;
// use lightning::util::ser::{Readable, Writeable, Writer};

// // use std::io::Cursor;
// // use your_crate::MessageHandler; // Replace "your_crate" with your actual crate's name where the MessageHandler struct is defined
// // use lightning::ln::wire::CustomMessageReader;
// use secp256k1_zkp::PublicKey;

// use lightning::ln::peer_handler::{
//     ErroringMessageHandler, IgnoringMessageHandler, MessageHandler, PeerManager as LdkPeerManager,
// };

// fn main() {
//     // from rust-dlc
//     // let hex_string = "a71a000000010006226e46111a0b59caaf126043eb5bbf28c34f3a5e332a1fc7b2b73cf188910f3f62c0b0d2e58985b50312d79f567c1e24e73c9020e39bb55e35b2a78cbc891600000000000bebc20000040161000000000bebc200016200000000000000000163000000000bebc2000164000000000000000001000303fdd8249d40dd8917551273b0995586415ea0d1cd563fe09ee7c23ef71e7f3d597e08b9d5563a626b5edcfa7ba3d5b169bf3b9b5b430c17fa92d9e1cf573a5fb72b6e1adab97e84e1988de11297b4f2088a723a8904e8bde65bbb06fdb8852254c8cc2c4ffdd822390001381efae1b4b83eb060d0468c018d685f6c915f2c48e37114a90f9541964ed2af60bf0bb0fdd8060a000401610162016301640454657374fdd8249d5bbc6f506e27cb14cc1dcd633da10e9c946bb872fbc483c9287dafd693c3a2ddf9b6a5b399facb899e96949658e8e733ff5b6b678cf6624869d7fb77182b509def68ed382aad934c786739302d131ac3cc7257004b32c9fe361fe01ed404d639fdd82239000108298599cb25d5efa5924024a7c35801cc1ac5d284f8ecfb99d3db67262c1a3360bf0bb0fdd8060a000401610162016301640454657374fdd8249db61e9ad9ab7205bb37740ec2f75db8f48a66ed29fc7e9a08a33e6e9a12f8a1f63e2edadad892293b7efb5d9691f73e1fbcbf134e1dc60ff57536f765c9a5ba4a7ef162d300c7454fd86403b9c73e79b84839653c2c6a144c794df289fd66303dfdd8223900016b0962ff4e444806f0fbc588ba6250514bf26b6323cdc16a8b8d5f0b0b4e630d60bf0bb0fdd8060a0004016101620163016404546573740002abea992869cb905be0f6fde98ce2448741504b3d2a2ae8933064f7371ea0267e00160014d34ff7f9a8fc804ff05e20e7a29a4eeada9e51e52b17b951477be17e0000000005f5e10001eade4da8f142f09aa8020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff03520101ffffffff0200f2052a01000000160014cc6a78085a467c442acb8140ff33d1fbd61ba9bc0000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf9012000000000000000000000000000000000000000000000000000000000000000000000000000000000ffffffff006b000000160014f8140840d6ef2a7d63e749e9c0d8fc35a59ce8c3119bbbd9b7c874e7fa211bc7ecf46cef000000000000000260bf0bb060c84630";
//     // from node-dlc new
//     // let hex_string = "a71a000000010006226e46111a0b59caaf126043eb5bbf28c34f3a5e332a1fc7b2b73cf188910fab94f511edde339db1415569da160639b3053a923a282147f37cc14e5f6105dc00000000000501bd000100150300000000000000000000000004ff2cc00000000200000000000000000000000004ff2cc0000000000000000f3e580000000004ff2cc0000000000000000f3e580000000004ff2cc00000000200000000000f3e580000000004ff2cc0000000000000000f4628000000000501bd00000000000000000f4628000000000501bd000000000200000000000f4628000000000501bd00000000000000001fffff000000000501bd00000000000000001fffff000000000501bd000000010000000000000000000000000001482000fdd824fd032ee73d38cb95eaf6d60c9f75c0c65b39e031632e4ccc42dcfb70a822a3fb3118048dc9717f5fc350a89fcd9c73f216717a5212a90ced86d52c54421b372016f14cbb4317df926c040caa0b29aa6a2bb2730d50529809b95936a74e47127ce3ad46fdd822fd02c80015e73d38cb95eaf6d60c9f75c0c65b39e031632e4ccc42dcfb70a822a3fb311804182a97e21d7b59a86e7c35f7d04ea41df89eea5b87a2ec1b7c53e5272141ff342a0a92d09c5ad6297bf057cf0ec6598fcc78a1f98815b4493828e39614910a17acd73151cd9d9e4cd4ba0f314e0cea7258ec19619fda13c2b74555ff2f2952f7bac9a7a92fa53618553bdd674b21695dfa96f8ae87af36337eb986344dc67c62c4e824524eb93768edef4ed4e58d5a1ff30c5648d1ca13941fc6bb1e583897d059075ed31615df121e8b179e2b406a10203ffd9c6b8cf5c648d0f359f149bac2ddfb555c819470d71810ec968477e7be553b55e03e7c1f9d3974f956e39c2eeab0acaebe72da4482c7e0738f8f68a3231e45233473f4b00e5f1f59124f71b03b332753fbb409c7fe9c2aead962e4e2fbc9d37785c4ede8a88397170069062aed632330018c82f8e3e783e090ee18c4e9b08d6db3bd803478f98837ea929466134cf853a5f79f9f67d552729e712751392b698a226e6a01d84e3a05b537c8850f2f5871a73716f2516859de1867492f4d2ee24416d62e3d2ae36602d1e6c67177c172abf2f7b8d60ddcdae24025b22af2d936ba8202453a7d58bd937299a84c81573b9beb005615e90f254638fab266dfdb3bc590b71f9e13ac4d188a0de2b4b9ac3f86159c49cf1a9e2e73f6a8a3e826d4e846edba40315eb8078336d48d6f2021f8d3504db6f03708b43dc5907f7a178f93906760d2fb8b00466a635a6a38620127f4c86271c625f67e8968b9a7bcc2a46788046adde8ac1df171d0c792adfeaa70acc23f79c9f82dbdd1d7d7fc0e7f2d62b28c52fbb94e00263b221077ba11bd684317883f4a68eee5dc1214bc0f1448f1275475958dba18f69c7f97e761df3d31e1dcccb04a74446e612950ca19f3a84737eac02f533019d606cf2a19f4de6064108cfdd80a0e00020004626974730000000000150f73747261746567794f7574636f6d6503e37856b7499f1ea4d46a3ebb2e348512b2b451b5a5ad1e388415eea66f142cbb0016001483fe9b838804e60f012ef140b216b1de14695765000000000002046b00000000050074e0010000000000000932de02000000000101998651d13fa164890d0c0b05187086eb8840970742e9562fd70aaf8677dd850b0000000000fdffffff0265aaeb020000000016001463003404adcbc5b60d86389c16ae3784b31daf3c00c2eb0b000000001600148f7e2621ddbf78d2bb31e4460aaa795a172522b90247304402201e83eb9d5ecb8ef53ebac3525d9ed900e73572324c18bccffbacaf99873943570220432c8370fb9eafdd713669ffcc69135f9e37e97af5f25a63ee0351b94867ed5a012102103e08e2b5822e228f0586292db7165328e81958648fd64102f3d843f9c2b1d09f02000000000001ffffffff006c0000001600145c638c7b6eca05e5c97dace19130e4332a345f78000000000024b824000000000043efb8000000000000000a6064108c6064108d";
//     // from node-dlc old
//     // let hex_string = "a71a0006226e46111a0b59caaf126043eb5bbf28c34f3a5e332a1fc7b2b73cf188910ffdd82efd03dc000000000501bd00fda720960015fda72684000300fe04ff2cc00000fda72816000200fe04ff2cc00000fe000f3e58fe04ff2cc00000fe000f3e58fe04ff2cc00000fda7281a0002fe000f3e58fe04ff2cc00000fe000f4628fe0501bd000000fe000f4628fe0501bd000000fda7281a0002fe000f4628fe0501bd000000fe001ffffffe0501bd000000fe001ffffffe0501bd000000fda72408000100fe00014820fda712fd0334fdd824fd032ee73d38cb95eaf6d60c9f75c0c65b39e031632e4ccc42dcfb70a822a3fb3118048dc9717f5fc350a89fcd9c73f216717a5212a90ced86d52c54421b372016f14cbb4317df926c040caa0b29aa6a2bb2730d50529809b95936a74e47127ce3ad46fdd822fd02c80015e73d38cb95eaf6d60c9f75c0c65b39e031632e4ccc42dcfb70a822a3fb311804182a97e21d7b59a86e7c35f7d04ea41df89eea5b87a2ec1b7c53e5272141ff342a0a92d09c5ad6297bf057cf0ec6598fcc78a1f98815b4493828e39614910a17acd73151cd9d9e4cd4ba0f314e0cea7258ec19619fda13c2b74555ff2f2952f7bac9a7a92fa53618553bdd674b21695dfa96f8ae87af36337eb986344dc67c62c4e824524eb93768edef4ed4e58d5a1ff30c5648d1ca13941fc6bb1e583897d059075ed31615df121e8b179e2b406a10203ffd9c6b8cf5c648d0f359f149bac2ddfb555c819470d71810ec968477e7be553b55e03e7c1f9d3974f956e39c2eeab0acaebe72da4482c7e0738f8f68a3231e45233473f4b00e5f1f59124f71b03b332753fbb409c7fe9c2aead962e4e2fbc9d37785c4ede8a88397170069062aed632330018c82f8e3e783e090ee18c4e9b08d6db3bd803478f98837ea929466134cf853a5f79f9f67d552729e712751392b698a226e6a01d84e3a05b537c8850f2f5871a73716f2516859de1867492f4d2ee24416d62e3d2ae36602d1e6c67177c172abf2f7b8d60ddcdae24025b22af2d936ba8202453a7d58bd937299a84c81573b9beb005615e90f254638fab266dfdb3bc590b71f9e13ac4d188a0de2b4b9ac3f86159c49cf1a9e2e73f6a8a3e826d4e846edba40315eb8078336d48d6f2021f8d3504db6f03708b43dc5907f7a178f93906760d2fb8b00466a635a6a38620127f4c86271c625f67e8968b9a7bcc2a46788046adde8ac1df171d0c792adfeaa70acc23f79c9f82dbdd1d7d7fc0e7f2d62b28c52fbb94e00263b221077ba11bd684317883f4a68eee5dc1214bc0f1448f1275475958dba18f69c7f97e761df3d31e1dcccb04a74446e612950ca19f3a84737eac02f533019d606cf2a19f4de6064108cfdd80a0e00020004626974730000000000150f73747261746567794f7574636f6d6503e37856b7499f1ea4d46a3ebb2e348512b2b451b5a5ad1e388415eea66f142cbb0016001483fe9b838804e60f012ef140b216b1de14695765000000000002046b00000000050074e00001fda714f4000000000000093200de02000000000101998651d13fa164890d0c0b05187086eb8840970742e9562fd70aaf8677dd850b0000000000fdffffff0265aaeb020000000016001463003404adcbc5b60d86389c16ae3784b31daf3c00c2eb0b000000001600148f7e2621ddbf78d2bb31e4460aaa795a172522b90247304402201e83eb9d5ecb8ef53ebac3525d9ed900e73572324c18bccffbacaf99873943570220432c8370fb9eafdd713669ffcc69135f9e37e97af5f25a63ee0351b94867ed5a012102103e08e2b5822e228f0586292db7165328e81958648fd64102f3d843f9c2b1d09f02000000000001ffffffff006c0000001600145c638c7b6eca05e5c97dace19130e4332a345f78000000000024b824000000000043efb8000000000000000a6064108c6064108d";
//     // from node-dlc new accept
//     let hex_string = "a71e00000001c1c79e1e9e2fa2840b2514902ea244f39eb3001a4037a52ea43c797d4f8412690300c706fe7ed70197a77397fb7ce8445fcf1d0b239b4ab41ebdad4f76e0a671d7830470f4fef96d0838e8f3cec33176a6a427d777b57d256f8545b570cd702972910192f8ad4eb341ac2867d203360516028b967b46ef0e5d1603b59a7d8ebc81d655dd11673febcf098006eba74b3604d0a1da818208ea2833079505a3dee7392255f0682e5b357a7382aae6e5bdcc728b94c9d0a52fb6f49ac5cbe32804fcfb71b10125e92381be588737f6ac5c28325c843c6551995880f830d926abd35ee3f8ed9fdfc47a5fd277d0df2a1f1d0bafba8efad7b127e2a232a4846ed90810c81e65750039dba803adb78100f20ca12b09b68a92b996b07a5ee47806379cedfa217848644f48d96ed6443ea7143adf1ce19a4386d0841b5071e31f5d3e4c479eab6a856b426c80d091da3de3959b29e4c2e3ae47ddba2758c2ca1c6a064dfee4671ba5010098f2595778a1596054ffcafb599f8f4a65c4215de757548c142d50b12eb67d4c1407690b808e33eba95fe818223886fd8e9ce4c758b4662636af663e0055376300a915ee71914ee8ae2c18d55b397649c0057a01f0a85c6ecf1b0eb26f7485f21b24c89013e1cb15a4bf40256e52a66751f33de46032db0801975933be2977a1e37d5d5f2d43f48481cc68783dbfeb21a35c62c1ca2eb6ee2ccfc12b74e9fd7a08fbf56fbb4bbcb01d1be3169dfda6f465020ee89c1e368d4a91e36d0d4cc44e6123db348c223988dfe147d611ae9351d6e78cfb902e3d01beed0c909e52a3aae901020047304402203812d7d194d44ec68f244cc3fd68507c563ec8c729fdfa3f4a79395b98abe84f0220704ab3f3ffd9c50c2488e59f90a90465fccc2d924d67a1e98a133676bf52f37201002102dde41aa1f21671a2e28ad92155d2d66e0b5428de15d18db4cbcf216bf00de919";
//     // from suredbits wallet new offer
//     // let hex_string = "a71a006fe28c0ab6f1b372c1a6a246ae63f74f931e8365e15a089c68d6190000000000fdd82efd030e000000000000c350fda720220012fda72616000100000000fda728020000fe0003fffffdc3500000fda724020000fda712fd02dafdd824fd02d463ff2cce9484666899ab54b6340d3104173018c6440c210018335ac552876866706d8118d6924d55c2384d9ae073c24bb0279f61036df4750ebe9f3c27f341fe04ba9838623f02c940d20d7b185d410178cff7990c7fcf19186c7f58c7c4b8defdd822fd026e001233f062b532effcc1e53f3ba1a5a7b83608c88d43f1c1554b2115df1960c712253b8ffb9794b93c43423ce88554f7d71686d4c5b1635d61db353aadff6d86f648427b20abcbbaf90847e38e5082c3b57662243c8ec8730920e7f747448f18f0984512b270ea3519dd2d2d9c1c57a2962045ae8ba2293a3265b3a20879c6e8241e5e192149d77c2115aa3e102e812021acfc9efbe99c0649a82a0d762cc3a5b5a45efab3a8b304d917dbdeb8b000f65cc8f40a1e24083837e53099d32202bdf99462b32f8fced9f31b1449f55c1f8a1b80f987e626c8fe6f5bdca0dcc1f99968c264ea1a13e243677cb136ab94a76b30d42a0d9f8e5a9b4f75db69a0cb80827aa969ca4de7e43d068643476ae1b2cc895852e6302dd74ca4d04b116bff3dab07f07680d78373c5897e6e0661fb6cce6aae2a7f3901501aa3871352bddb5581a4ce85c70a000dfd4c8738759b6e27d6b3b8c4691243d94b8fb3767f0b3e5ecdaa5b89f928b0d55dbb821892bd87ec71074a69d7fd8e9fde933cd7b19cf62feefa30900e47bf250c4d7239d92b10bc603d1cadad55dfa10ae75b46181cf16d2d4666b78a9466d4a2c2952c0861108f335c184acf25654fae79fcf0d1c652c16c0b55c89c4aa341d275c0323d198aef8c9e975eb66630dde9425d8760b91438b1067dd3a3cd52b7deba4db8c7c88bb4554534a26653c72ccd7fb4eb5bd3fd8b3aadf3e361a0d187f299c621e7a22f758916e8a484abbb5b79d36efb9522905848cbc8f83e95b5dc974bef9d7f6bbbbc5945d8a8f1f635d0aa895c1699a2cda1dbc5ba63d77900fdd80a100002000642544355534400000000001213446572696269742d4254432d33304a414e32330343dbb6e13376739420bad92e9167d3ab2ef5baa27e415bea6f62c3ae567c3fb4001600144cc008760b7f05750fc8245440c7f6719b247309eaf117111b7a939e00000000000061a80001fda714f4fd3e82d4c323481300de020000000001010e834bc161b454bae7a6b7ee87ddcb2c078bc18d573a2c9d93a721e9325b4e5d0000000000feffffff0250b74600000000001600140cbc4e458417ca2bbbf3cfa18a67793eb840831850c3000000000000160014faf39ec48162bfe8ad1c5919bd709ab12f54d6960247304402205a0ed4c3e1011c78c56b4481638aba9a7e258582f0d5e363801fe9de5a428ca80220712719e1168a1fd5028e31656a9a18928a4891b049bd8ec53e899439090cc290012103b524991f65f449d5e76cd0690b9f98f7790ef85b752d7cc1fd2c2aee412cc6a18dd00b0000000001fffffffd006b0000001600147548fe1e7d1aa5722f8270d50867310e3fab94fe08885f4ca906806f9a4b5f9d6a55b1b20000000000000001000bd08e63e0b380";
//     let bytes = decode(hex_string).unwrap();

//     let message_handler = IgnoringMessageHandler::new();

//     let mut cursor = std::io::Cursor::new(bytes);

//     let message_type = <u16 as Readable>::read(&mut cursor).unwrap();

//     match CustomMessageReader::read(&message_handler, message_type, &mut cursor) {
//         Ok(Some(msg)) => println!("{:?}", msg),
//         Ok(None) => println!("No message returned"),
//         Err(e) => println!("Error: {:?}", e),
//     }



//     // let deser = Readable::read(&mut reader).unwrap();

//     // if let Ok(msg) = <OfferDlc as Readable>::read(&mut reader) {
//     //     println!("Received a valid OfferDlc message: {:?}", msg);
//     // } else {
//     //     println!("Failed to decode hex string into an OfferDlc message");
//     // }

//     // let handler = MessageHandler::new();
//     // let message_type = <u16 as Readable>::read(&mut reader).unwrap();  // Obtain the message type
//     // let message =  handler.read(message_type, &mut reader);  // Call read() on MessageHandler

//     // print message_type
//     // println!("message_type {:?}", message_type);

//     // Create DlcMessageHandler and read buffer
//     // let dlc_message_handler = MessageHandler::new();

//     println!("test2");

//     // let value = dlc_message_handler.read(message_type, &mut reader);

//     println!("test1");

//     // print out value
//     // println!("value {:?}", value);

//     // // get type of value
//     // println!("{:?}", value.type_id());

//     // let new_value = value.unwrap();
//     // println!("new_value {:?}", new_value);


//     // let newest_value = new_value.unwrap();
//     // println!("newest_value {:?}", newest_value);

//     // let msg = dlc_message_handler.get_and_clear_received_messages();
//     // println!("msg {:?}", msg);

//     // if let WireMessage::Message(Offer(offer_dlc)) = newest_value {
//     //     println!("OfferDlc protocol version: {}", offer_dlc.protocol_version);
//     // }

//     println!("Hello, world!");
// }
