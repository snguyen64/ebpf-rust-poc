use opentelemetry::metrics::{Counter, Meter, MeterProvider};
use opentelemetry::global;

// Struct to hold references to metrics
pub struct MetricsRegistry {
    malloc_calls: Counter<u64>,
    malloc_returns: Counter<u64>,
    free_calls: Counter<u64>,
    default_labels: Vec<opentelemetry::KeyValue>,
}

impl MetricsRegistry {
    // Initialize the registry with OpenTelemetry counters
    pub fn initialize() -> Self {
        let meter = global::meter("bpf_metrics");

        let default_labels = vec![
            opentelemetry::KeyValue::new("node_name", std::env::var("NODE_NAME").unwrap_or_else(|_| "unknown".to_string())),
            opentelemetry::KeyValue::new("pod_name", std::env::var("POD_NAME").unwrap_or_else(|_| "unknown".to_string())),
            opentelemetry::KeyValue::new("pod_namespace", std::env::var("POD_NAMESPACE").unwrap_or_else(|_| "unknown".to_string())),
            // opentelemetry::KeyValue::new("pod_ip", std::env::var("POD_IP").unwrap_or_else(|_| "unknown".to_string())),
        ];

        let malloc_calls = meter.u64_counter("malloc_calls")
            .with_description("Counts the number of malloc calls")
            .build();
        let malloc_returns = meter.u64_counter("malloc_returns")
            .with_description("Counts the number of malloc returns")
            .build();
        let free_calls = meter.u64_counter("free_calls")
            .with_description("Counts the number of free calls")
            .build();

        MetricsRegistry {
            malloc_calls,
            malloc_returns,
            free_calls,
            default_labels,
        }
    }

    // Increment the "packets_processed" metric
    // pub fn increment_packets_processed(&self, value: u64) {
    //     self.packets_processed.add(value, &[]);
    // }

    pub fn increment_malloc_calls(&self, value: u64) {
        // let additional_labels = vec![];
        let mut labels = self.default_labels.clone();
        // labels.extend(additional_labels);
        self.malloc_calls.add(value, &labels);
    }

    pub fn increment_malloc_returns(&self, value: u64) {
        // let additional_labels = vec![];
        let mut labels = self.default_labels.clone();
        // labels.extend(additional_labels);
        self.malloc_returns.add(value, &labels);
    }

    pub fn increment_free_calls(&self, value: u64) {
        // let additional_labels = vec![];
        let mut labels = self.default_labels.clone();
        // labels.extend(additional_labels);
        self.free_calls.add(value, &labels);
    }
}