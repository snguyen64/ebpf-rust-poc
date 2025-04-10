// use opentelemetry::global;
// use opentelemetry::metrics::Meter;
// use opentelemetry::KeyValue;
// use opentelemetry_otlp::Protocol;
// use opentelemetry_otlp::WithExportConfig;
// use opentelemetry_sdk;

// // handles metrics exporting
// // OTLP exporter can export directly to tools such as Prometheus,
// // Jaeger, or Zipkin
// pub fn export() {
//     println!("Exporting metrics...");
//     let meter_provider = init_meter_provider();

//     meter_provider.shutdown()?;
// }


// pub fn init_meter_provider() -> opentelemetry_sdk::metrics::SdkMeterProvider {
//     let exporter = opentelemetry_stdout::MetricExporterBuilder::default()
//         // Build exporter using Delta Temporality (Defaults to Temporality::Cumulative)
//         // .with_temporality(opentelemetry_sdk::metrics::Temporality::Delta)
//         .build();
//     let provider = SdkMeterProvider::builder()
//         .with_periodic_exporter(exporter)
//         .with_resource(
//             Resource::builder()
//                 .with_service_name("ebpf-rust-poc")
//                 .build(),
//         )
//         .build();
//     global::set_meter_provider(provider.clone());
//     provider
// }