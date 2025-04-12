use opentelemetry::global;

// Struct to hold references to metrics
pub struct MetricsRegistry {
    alloc_info: opentelemetry::metrics::Gauge<u64>,
    default_labels: Vec<opentelemetry::KeyValue>,
}

impl MetricsRegistry {
    // Initialize the registry with OpenTelemetry counters
    pub fn initialize() -> Self {
        let meter = global::meter("ebpf-rust-poc");

        let default_labels = vec![
            // node name is actually from the environment variable. 
            opentelemetry::KeyValue::new("node_name", std::env::var("NODE_NAME").unwrap_or_else(|_| "unknown".to_string())),
        ];

        let alloc_info = meter.u64_gauge("alloc_info")
            .with_description("Tracks the allocation information")
            .build();

        MetricsRegistry {
            alloc_info,
            default_labels,
        }
    }

    pub fn update_alloc_info(&self, container_id: &str, pod_namespace: &str, pod_name: &str, value: u64) {
        // Create labels from the provided pod cache data
        let mut labels = self.default_labels.clone();
        labels.push(opentelemetry::KeyValue::new("container_id", container_id.to_string()));
        labels.push(opentelemetry::KeyValue::new("pod_namespace", pod_namespace.to_string()));
        labels.push(opentelemetry::KeyValue::new("pod_name", pod_name.to_string()));

        // Update the alloc_info metric with the value and labels
        println!("Updating [Metric] alloc_info with value: {} and labels: {:?}", value, labels);
        self.alloc_info.record(value as u64, &labels);
    }
}