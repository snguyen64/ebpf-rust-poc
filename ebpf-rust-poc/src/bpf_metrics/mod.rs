// declares the metrics module
pub mod collector;
pub mod exporter;

// Public API for the `metrics` module
pub fn init_metrics() {
    println!("Initializing metrics...");
}