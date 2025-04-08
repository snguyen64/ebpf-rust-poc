use opentelemetry::global;
use opentelemetry::metrics::Meter;
use opentelemetry::KeyValue;
use opentelemetry_otlp::Protocol;
use opentelemetry_otlp::WithExportConfig;
use opentelemetry_sdk;

// handles metrics exporting
// OTLP exporter can export directly to tools such as Prometheus,
// Jaeger, or Zipkin
pub fn export() {
    println!("Exporting metrics...");

    let meter_provider = init_meter_provider();
 
    // Get a meter
    let meter = global::meter("mylibraryname");

    // Create a metric
    let counter = meter.u64_counter("my_counter").build();
    counter.add(
        10,
        &[
            KeyValue::new("mykey1", "myvalue1"),
            KeyValue::new("mykey2", "myvalue2"),
        ],
    );

    // Metrics are exported by default every 30 seconds when using stdout
    // exporter, however shutting down the MeterProvider here instantly flushes
    // the metrics, instead of waiting for the 30 sec interval. Shutdown returns
    // a result, which is bubbled up to the caller The commented code below
    // demonstrates handling the shutdown result, instead of bubbling up the
    // error.
    // Shutdown the meter provider. This will trigger an export of all metrics.
    meter_provider.shutdown()?;

    // Ok(())
}

fn init_meter_provider() -> opentelemetry_sdk::metrics::SdkMeterProvider {
   // Initialize OTLP exporter using HTTP binary protocol
    let exporter = opentelemetry_otlp::MetricExporterBuilder::builder()
        .with_http()
        .with_protocol(Protocol::HttpBinary)
        .with_endpoint("http://localhost:9090/api/v1/otlp/v1/metrics")
        .build()?;

        // Create a meter provider with the OTLP Metric exporter
    let meter_provider = opentelemetry_sdk::metrics::SdkMeterProvider::builder()
        .with_periodic_exporter(exporter)
        .with_resource(
            Resource::builder()
                .with_service_name("metrics-basic-example")
                .build(),
        )
        .build();
    global::set_meter_provider(meter_provider.clone());
    meter_provider
}