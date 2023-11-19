use std::{ptr, ffi::c_void};

use windows::{Win32::{Storage::FileSystem::{CreateFileA, FILE_SHARE_NONE, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL}, Foundation::{HANDLE, CloseHandle}, System::{Diagnostics::Debug::{ImageEnumerateCertificates, ImageRemoveCertificate, ImageGetCertificateData, ImageGetCertificateHeader, ImageAddCertificate}, Memory::{HeapAlloc, GetProcessHeap, HEAP_ZERO_MEMORY, HeapFree}}, Security::WinTrust::WIN_CERTIFICATE}, core::PCSTR};

use clap::Parser;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None, arg_required_else_help = true)]
struct Args {
    #[arg(short, long, help = "Signed source file to copy certificate from")]
    source: String,

    #[arg(short, long, help = "Destination file to add certificate to")]
    dest: String
}

fn main() {
    let args = Args::parse();

    const FILE_READ_DATA: u32 = 1;
    const FILE_WRITE_DATA: u32 = 2;

    let mut source_file: String = args.source;
    let mut dest_file: String = args.dest;
    
    unsafe {
            
        let h_file: HANDLE = CreateFileA(
            PCSTR::from_raw(source_file.as_mut_ptr()),
            FILE_READ_DATA,
            FILE_SHARE_NONE,
            Some(ptr::null_mut()),
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            HANDLE::default()
        ).unwrap();

        const CERT_SECTION_TYPE_ANY: u16 = 255;
        let mut cert_count: u32 = 0;
        let mut indices: Vec<u32> = Vec::new();

        println!("[+] Enumerating certificates");
        ImageEnumerateCertificates(h_file, CERT_SECTION_TYPE_ANY, &mut cert_count, Some(&mut indices)).unwrap();

        println!("[+] Found {} certificate(s)", cert_count);
        if cert_count == 0 {
            println!("[!] Input file is not signed!");
            CloseHandle(h_file).unwrap();
            return;
        }

        println!("[+] Opening handle to binary to copy certificate to");
        let h_new_file: HANDLE = CreateFileA(
            PCSTR::from_raw(dest_file.as_mut_ptr()),
            FILE_READ_DATA | FILE_WRITE_DATA,
            FILE_SHARE_NONE,
            Some(ptr::null_mut()),
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            HANDLE::default()
        ).unwrap();

        println!("[+] Enumerating old certificates");
        let mut old_cert_count: u32 = 0;
        let mut old_indices: Vec<u32> = Vec::new();

        ImageEnumerateCertificates(h_new_file, CERT_SECTION_TYPE_ANY, &mut old_cert_count, Some(&mut old_indices)).unwrap();
        println!("[+] Existing certificates: {}", old_cert_count);

        if old_cert_count > 0 {
            println!("[+] Removing old certificates");
            while old_cert_count > 0 {
                ImageRemoveCertificate(h_new_file, (old_cert_count - 1) as u32).unwrap();
                println!("[+] Removed cert index: {} OK", old_cert_count);
                old_cert_count -= 1;
            }
        }

        let mut def_cert: WIN_CERTIFICATE = WIN_CERTIFICATE::default();

        println!("[+] Getting certificate data");
        ImageGetCertificateHeader(h_file, 0, &mut def_cert).unwrap();

        println!("[+] Size of cert: {}", def_cert.dwLength);
        let mut cert_len: u32 = def_cert.dwLength;

        let cert_mem: *mut c_void = HeapAlloc(GetProcessHeap().unwrap(), HEAP_ZERO_MEMORY, def_cert.dwLength as usize);
        let win_cert: *mut WIN_CERTIFICATE = cert_mem as *mut WIN_CERTIFICATE;

        ImageGetCertificateData(h_file, 0, win_cert, &mut cert_len).unwrap();

        println!("[+] Adding certificate to binary");

        let mut cert_index: u32 = 0;
        ImageAddCertificate(h_new_file, win_cert, &mut cert_index).unwrap();

        println!("[+] Successfully added certificate! Index: {}", cert_index);

        CloseHandle(h_file).unwrap();
        CloseHandle(h_new_file).unwrap();
        HeapFree(GetProcessHeap().unwrap(), HEAP_ZERO_MEMORY, Some(win_cert as *mut c_void)).unwrap();
    }
}
