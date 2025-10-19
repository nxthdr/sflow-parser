use criterion::{black_box, criterion_group, criterion_main, Criterion, Throughput};
use sflow_parser::parse_datagram;

/// Benchmark parsing a real sFlow datagram from test data
fn bench_parse_real_datagram(c: &mut Criterion) {
    // Load real sFlow data from integration test
    let data = std::fs::read("tests/data/sflow.bin")
        .expect("Failed to read sflow.bin - run integration tests first");

    let mut group = c.benchmark_group("parse_datagram");
    group.throughput(Throughput::Bytes(data.len() as u64));

    group.bench_function("real_sflow_data", |b| {
        b.iter(|| {
            let result = parse_datagram(black_box(&data));
            black_box(result)
        });
    });

    group.finish();
}

/// Benchmark parsing multiple datagrams
fn bench_parse_multiple_datagrams(c: &mut Criterion) {
    let data = std::fs::read("tests/data/sflow.bin")
        .expect("Failed to read sflow.bin - run integration tests first");

    let mut group = c.benchmark_group("parse_multiple");

    // Parse the same datagram 10 times to simulate batch processing
    group.bench_function("10x_datagrams", |b| {
        b.iter(|| {
            for _ in 0..10 {
                let result = parse_datagram(black_box(&data));
                let _ = black_box(result);
            }
        });
    });

    group.finish();
}

/// Benchmark memory allocation patterns
fn bench_memory_allocation(c: &mut Criterion) {
    let data = std::fs::read("tests/data/sflow.bin")
        .expect("Failed to read sflow.bin - run integration tests first");

    let mut group = c.benchmark_group("memory");

    // Measure parsing with result consumption (forces allocation)
    group.bench_function("parse_and_consume", |b| {
        b.iter(|| {
            let datagram = parse_datagram(black_box(&data)).unwrap();
            // Access fields to ensure they're not optimized away
            let _agent = &datagram.agent_address;
            let _samples = &datagram.samples;
            black_box(datagram)
        });
    });

    // Measure just parsing (may allow some optimizations)
    group.bench_function("parse_only", |b| {
        b.iter(|| parse_datagram(black_box(&data)));
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_parse_real_datagram,
    bench_parse_multiple_datagrams,
    bench_memory_allocation
);
criterion_main!(benches);
