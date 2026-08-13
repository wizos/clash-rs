use clash_lib::app::router::benchmark::RuleBenchmark;
use criterion::{BatchSize, Criterion, Throughput, criterion_group, criterion_main};
use std::{
    alloc::{GlobalAlloc, Layout, System},
    hint::black_box,
    sync::atomic::{AtomicUsize, Ordering},
    time::Instant,
};

struct CountingAllocator;
static ALLOCATIONS: AtomicUsize = AtomicUsize::new(0);

unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        ALLOCATIONS.fetch_add(1, Ordering::Relaxed);
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { System.dealloc(ptr, layout) }
    }
}

#[global_allocator]
static ALLOCATOR: CountingAllocator = CountingAllocator;

fn report(
    runtime: &tokio::runtime::Runtime,
    case: &RuleBenchmark,
    dns_enrichment: bool,
) {
    let mut samples = Vec::with_capacity(100);
    for _ in 0..100 {
        let start = Instant::now();
        black_box(runtime.block_on(case.run()));
        samples.push(start.elapsed().as_nanos());
    }
    samples.sort_unstable();
    ALLOCATIONS.store(0, Ordering::Relaxed);
    for _ in 0..100 {
        black_box(runtime.block_on(case.run()));
    }
    let allocations = ALLOCATIONS.load(Ordering::Relaxed) / 100;
    let p50 = samples[49];
    let p95 = samples[94];
    println!(
        "RULE_BENCH rules={} dns_enrichment={} p50_ns={} p95_ns={} routes_per_sec={} allocations_per_route={}",
        case.rule_count(),
        dns_enrichment,
        p50,
        p95,
        1_000_000_000_u128 / p50.max(1),
        allocations,
    );
}

fn rule_matching(criterion: &mut Criterion) {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    for size in [30, 500, 10_000] {
        for dns_enrichment in [false, true] {
            let case = runtime.block_on(RuleBenchmark::new(size, dns_enrichment));
            report(&runtime, &case, dns_enrichment);
            let mut group = criterion.benchmark_group(format!("rules/{size}"));
            group.throughput(Throughput::Elements(1));
            group.bench_function(
                if dns_enrichment {
                    "with_dns"
                } else {
                    "without_dns"
                },
                |bencher| {
                    bencher.to_async(&runtime).iter_batched(
                        || (),
                        |_| case.run(),
                        BatchSize::SmallInput,
                    );
                },
            );
            group.finish();
        }
    }
}

criterion_group!(benches, rule_matching);
criterion_main!(benches);
