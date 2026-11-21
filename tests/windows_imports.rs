//! rts.exe must start on any Windows, including one without Hyper-V, so it
//! can say why it cannot run a sandbox there. computecore.dll (the HCS API)
//! exists only where Hyper-V is installed, so it must never be a load-time
//! import: rts loads it at run time (src/backend/hyperv/hcs.rs). This reads
//! the import table of the built rts.exe and checks.

#![cfg(windows)]

fn u16_at(d: &[u8], o: usize) -> usize {
    u16::from_le_bytes([d[o], d[o + 1]]) as usize
}

fn u32_at(d: &[u8], o: usize) -> usize {
    u32::from_le_bytes([d[o], d[o + 1], d[o + 2], d[o + 3]]) as usize
}

/// The DLL names in a PE32+ file's import directory.
fn imported_dlls(d: &[u8]) -> Vec<String> {
    let pe = u32_at(d, 0x3c);
    assert_eq!(&d[pe..pe + 4], b"PE\0\0", "not a PE file");
    let sections = u16_at(d, pe + 6);
    let opt = pe + 24;
    assert_eq!(u16_at(d, opt), 0x20b, "not PE32+");
    let opt_size = u16_at(d, pe + 20);
    let import_rva = u32_at(d, opt + 112 + 8);
    let table: Vec<(usize, usize, usize)> = (0..sections)
        .map(|i| {
            let s = opt + opt_size + i * 40;
            (u32_at(d, s + 12), u32_at(d, s + 8).max(u32_at(d, s + 16)), u32_at(d, s + 20))
        })
        .collect();
    let at = |rva: usize| {
        table
            .iter()
            .find(|(va, size, _)| (*va..va + size).contains(&rva))
            .map(|(va, _, raw)| rva - va + raw)
            .expect("RVA outside every section")
    };
    let mut names = vec![];
    let mut entry = at(import_rva);
    while u32_at(d, entry + 12) != 0 {
        let name = at(u32_at(d, entry + 12));
        let end = d[name..].iter().position(|&b| b == 0).unwrap();
        names.push(String::from_utf8_lossy(&d[name..name + end]).to_ascii_lowercase());
        entry += 20;
    }
    names
}

#[test]
fn computecore_dll_is_not_a_load_time_import_of_rts_exe() {
    let exe = std::fs::read(env!("CARGO_BIN_EXE_rts")).unwrap();
    let dlls = imported_dlls(&exe);
    assert!(dlls.iter().any(|d| d == "kernel32.dll"), "the parser found no kernel32.dll: {dlls:?}");
    assert!(!dlls.iter().any(|d| d == "computecore.dll"), "rts.exe imports computecore.dll: {dlls:?}");
}
