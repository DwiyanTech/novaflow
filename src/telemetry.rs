//! Optional OpenTelemetry exporter (OTLP/HTTP traces + metrics).
//!
//! Initialized once at startup from the `otel:` config section. All
//! instrumentation call sites go through the record_* helpers in this module,
//! which are cheap no-ops when telemetry is disabled (the instruments are
//! never registered and the OnceLock stays empty).

use std::{sync::OnceLock, time::Duration};

use anyhow::{Context, Result};
use opentelemetry::{
    metrics::{Counter, Histogram, MeterProvider},
    trace::TracerProvider as _,
    KeyValue,
};
use opentelemetry_otlp::WithExportConfig;
use opentelemetry_sdk::{
    metrics::{periodic_reader_with_async_runtime::PeriodicReader, SdkMeterProvider},
    propagation::TraceContextPropagator,
    resource::Resource,
    runtime,
    trace::{
        span_processor_with_async_runtime::BatchSpanProcessor, Sampler, SdkTracerProvider, Tracer,
    },
};

use crate::config::OtelConfig;

/// Holds the tracer/meter providers so they stay alive for the whole process
/// and are flushed/shut down on drop.
pub struct TelemetryGuard {
    tracer_provider: SdkTracerProvider,
    meter_provider: SdkMeterProvider,
}

impl Drop for TelemetryGuard {
    fn drop(&mut self) {
        if let Err(err) = self.tracer_provider.shutdown() {
            tracing::warn!(error = ?err, "otel tracer shutdown failed");
        }
        if let Err(err) = self.meter_provider.shutdown() {
            tracing::warn!(error = ?err, "otel meter shutdown failed");
        }
    }
}

struct Instruments {
    http_req_duration: Histogram<f64>,
    http_req_count: Counter<u64>,
    waf_duration: Histogram<f64>,
    upstream_duration: Histogram<f64>,
    upstream_count: Counter<u64>,
}

static INSTRUMENTS: OnceLock<Instruments> = OnceLock::new();

/// Initialize the OTLP tracer and meter from `otel:` config.
///
/// Returns `None` (and registers nothing) when telemetry is disabled.
pub fn init_telemetry(cfg: &OtelConfig) -> Result<Option<(TelemetryGuard, Tracer)>> {
    if !cfg.enabled {
        return Ok(None);
    }

    let endpoint = cfg.endpoint.trim_end_matches('/');
    let traces_endpoint = format!("{endpoint}/v1/traces");
    let metrics_endpoint = format!("{endpoint}/v1/metrics");

    let span_exporter = opentelemetry_otlp::SpanExporter::builder()
        .with_http()
        .with_endpoint(traces_endpoint)
        .build()
        .context("failed to build otel span exporter")?;
    let tracer_provider = SdkTracerProvider::builder()
        .with_resource(resource(&cfg.service_name))
        .with_sampler(Sampler::ParentBased(Box::new(Sampler::TraceIdRatioBased(
            cfg.sample_ratio.clamp(0.0, 1.0),
        ))))
        .with_span_processor(BatchSpanProcessor::builder(span_exporter, runtime::Tokio).build())
        .build();
    let tracer = tracer_provider.tracer("novaflow");

    let metrics_exporter = opentelemetry_otlp::MetricExporter::builder()
        .with_http()
        .with_endpoint(metrics_endpoint)
        .build()
        .context("failed to build otel metric exporter")?;
    let meter_provider = SdkMeterProvider::builder()
        .with_resource(resource(&cfg.service_name))
        .with_reader(PeriodicReader::builder(metrics_exporter, runtime::Tokio).build())
        .build();
    let meter = meter_provider.meter("novaflow");

    let instruments = Instruments {
        http_req_duration: meter
            .f64_histogram("novaflow.http.request.duration")
            .with_unit("ms")
            .with_description("End-to-end duration of proxied requests")
            .build(),
        http_req_count: meter
            .u64_counter("novaflow.http.request.count")
            .with_unit("{request}")
            .with_description("Number of proxied requests")
            .build(),
        waf_duration: meter
            .f64_histogram("novaflow.waf.inspection.duration")
            .with_unit("ms")
            .with_description("Time spent evaluating WAF block rules")
            .build(),
        upstream_duration: meter
            .f64_histogram("novaflow.upstream.request.duration")
            .with_unit("ms")
            .with_description("Time to send a request to an upstream and receive its response")
            .build(),
        upstream_count: meter
            .u64_counter("novaflow.upstream.request.count")
            .with_unit("{request}")
            .with_description("Number of upstream requests")
            .build(),
    };
    let _ = INSTRUMENTS.set(instruments);

    // W3C trace context so downstream collectors can correlate.
    opentelemetry::global::set_text_map_propagator(TraceContextPropagator::new());

    Ok(Some((
        TelemetryGuard {
            tracer_provider,
            meter_provider,
        },
        tracer,
    )))
}

fn resource(service_name: &str) -> Resource {
    Resource::builder()
        .with_service_name(service_name.to_string())
        .build()
}

fn instruments() -> Option<&'static Instruments> {
    INSTRUMENTS.get()
}

/// Record one proxied request: duration + count with method/status/action.
pub fn record_http_request(elapsed: Duration, method: &str, status: u16, action: &str) {
    if let Some(i) = instruments() {
        let attrs = [
            KeyValue::new("method", method.to_string()),
            KeyValue::new("status", i64::from(status)),
            KeyValue::new("action", action.to_string()),
        ];
        i.http_req_duration
            .record(elapsed.as_secs_f64() * 1000.0, &attrs);
        i.http_req_count.add(1, &attrs);
    }
}

/// Record WAF block-rule evaluation time.
pub fn record_waf_inspection(elapsed: Duration, blocked: bool) {
    if let Some(i) = instruments() {
        i.waf_duration.record(
            elapsed.as_secs_f64() * 1000.0,
            &[KeyValue::new("blocked", blocked)],
        );
    }
}

/// Record one upstream request: duration + count with success/status.
/// `status` is `None` when the request to the upstream failed entirely
/// (connection error, timeout -> the client gets a 502).
pub fn record_upstream(elapsed: Duration, upstream: &str, status: Option<u16>) {
    if let Some(i) = instruments() {
        let status_code = status.unwrap_or(0);
        let attrs = [
            KeyValue::new("upstream", upstream.to_string()),
            KeyValue::new("status", i64::from(status_code)),
            KeyValue::new("success", status.is_some()),
        ];
        i.upstream_duration
            .record(elapsed.as_secs_f64() * 1000.0, &attrs);
        i.upstream_count.add(1, &attrs);
    }
}
