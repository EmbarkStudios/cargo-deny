// use divan::black_box;

// fn main() {
//     divan::main();
// }

// #[divan::bench]
// fn cache(b: divan::Bencher<'_, '_>) {
//     // We do this outside the benchmark since the cache included in the binary
//     let cache = std::sync::Arc::new(std::fs::read("./resources/spdx_cache.bin.zstd").unwrap());

//     b.with_inputs(|| cache.clone()).bench_local_values(|cache| {
//         black_box(askalono::Store::from_cache(std::io::Cursor::new(cache.as_slice())).unwrap());
//     });
// }

// #[divan::bench]
// fn no_cache(b: divan::Bencher<'_, '_>) {
//     b.bench_local(|| {
//         let mut boop = std::collections::BTreeMap::<&str, (askalono::TextData, Vec<&str>)>::new();
//         for lic in spdx::text::LICENSE_TEXTS {
//             let td = askalono::TextData::new(lic.1);

//             if let Some(v) = boop.values_mut().find(|(etd, _)| etd.eq_data(&td)) {
//                 v.1.push(lic.0);
//             } else {
//                 boop.insert(lic.0, (td, Vec::new()));
//             }
//         }

//         let mut s = askalono::Store::new();
//         for (k, v) in boop {
//             s.add_license(k.into(), v.0);

//             if !v.1.is_empty() {
//                 s.set_aliases(k, v.1.into_iter().map(String::from).collect())
//                     .unwrap();
//             }
//         }
//     });
// }
