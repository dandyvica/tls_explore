#![allow(dead_code)]
use std::io::BufReader;
use std::io::Cursor;
use std::net::TcpStream;
use std::{io::prelude::*, net::TcpListener};

mod structurizer;
//use structurizer::length::Length;
use structurizer::{from_network::TlsFromNetworkBytes, to_network::TlsToNetworkBytes};
//use tls_derive::TlsLength;

mod alert;
mod macros;

mod handshake;
use handshake::{
    common::ContentType,
    constants::*,
    handshake::Handshake,
    record_layer::{RecordHeader, RecordLayer},
};

use crate::alert::alert::{Alert, AlertRecord};

fn main() -> std::result::Result<(), Box<dyn std::error::Error>> {
    // define new handshake
    let mut record_layer = RecordLayer {
        header: RecordHeader {
            content_type: ContentType::handshake,
            version: [3, 1],
            length: 0,
        },
        data: Handshake::new(&vec![TLS_DHE_RSA_WITH_AES_256_CBC_SHA]),
    };
    record_layer.set_length();
    println!("{:#?}", record_layer);

    // send client_hello
    let mut stream = TcpStream::connect("www.google.fr:443").unwrap();

    // let x = [
    //     0x16, 0x03, 0x01, 0x00, 0xa5, 0x01, 0x00, 0x00, 0xa1, 0x03, 0x03, 0x00, 0x01, 0x02, 0x03,
    //     0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12,
    //     0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x00, 0x00,
    //     0x20, 0xcc, 0xa8, 0xcc, 0xa9, 0xc0, 0x2f, 0xc0, 0x30, 0xc0, 0x2b, 0xc0, 0x2c, 0xc0, 0x13,
    //     0xc0, 0x09, 0xc0, 0x14, 0xc0, 0x0a, 0x00, 0x9c, 0x00, 0x9d, 0x00, 0x2f, 0x00, 0x35, 0xc0,
    //     0x12, 0x00, 0x0a, 0x01, 0x00, 0x00, 0x58, 0x00, 0x00, 0x00, 0x18, 0x00, 0x16, 0x00, 0x00,
    //     0x13, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x2e, 0x75, 0x6c, 0x66, 0x68, 0x65, 0x69,
    //     0x6d, 0x2e, 0x6e, 0x65, 0x74, 0x00, 0x05, 0x00, 0x05, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
    //     0x0a, 0x00, 0x0a, 0x00, 0x08, 0x00, 0x1d, 0x00, 0x17, 0x00, 0x18, 0x00, 0x19, 0x00, 0x0b,
    //     0x00, 0x02, 0x01, 0x00, 0x00, 0x0d, 0x00, 0x12, 0x00, 0x10, 0x04, 0x01, 0x04, 0x03, 0x05,
    //     0x01, 0x05, 0x03, 0x06, 0x01, 0x06, 0x03, 0x02, 0x01, 0x02, 0x03, 0xff, 0x01, 0x00, 0x01,
    //     0x00, 0x00, 0x12, 0x00, 0x00,
    // ];

    let mut v = Vec::new();
    let _ = record_layer.to_network_bytes(&mut v)?;
    println!("{:0X?}", v);

    stream.write(&v).unwrap();

    /*/
    let mut response = [0; 1024];
    stream.read(&mut response).unwrap();
    println!("response={:?}", response);
    */

    // convert to network bytes
    //println!("{:#?}", handshake);
    //println!("{:x?}", handshake.to_network_bytes());

    // receive from server
    let response = read_data(&stream).unwrap();

    // has the handshake started ?
    match ContentType::try_from(response[0]) {
        Ok(ContentType::change_cipher_spec) => println!("change_cipher_spec"),
        Ok(ContentType::alert) => {
            let mut alert = RecordLayer::<Alert>::default();
            let _ = alert.from_network_bytes(&mut Cursor::new(response));
            println!("{:#?}", alert);
        }
        Ok(ContentType::handshake) => println!("handshake"),
        Ok(ContentType::application_data) => println!("application_data"),
        Ok(ContentType::fake) => println!("error"),
        Err(e) => println!("error {}", e),
    };

    Ok(())
}

fn read_data(stream: &TcpStream) -> Option<Vec<u8>> {
    let mut buffer: Vec<u8> = vec![0; 1024];
    let mut reader = BufReader::new(stream);

    let result = reader.read(&mut buffer);

    match result {
        Ok(read) => {
            println!("READ {}", buffer.len()); //Returing zero, even sending raw data on the body.
            if read == 0 {
                return None; //Stop the loop
            } else {
                return Some(buffer);
            }
        }
        Err(e) => panic!("Error: {}", e),
    }
}
