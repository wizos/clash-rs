use crate::def::LogLevel;
use anyhow::anyhow;
#[cfg(feature = "telemetry")]
use opentelemetry::trace::TracerProvider;
#[cfg(feature = "telemetry")]
use opentelemetry_otlp::{Protocol, WithExportConfig};
#[cfg(feature = "telemetry")]
use opentelemetry_semantic_conventions::{
    SCHEMA_URL,
    attribute::{DEPLOYMENT_ENVIRONMENT_NAME, SERVICE_VERSION},
};
use serde::Serialize;
use std::{
    io::IsTerminal,
    sync::{LazyLock, Once, OnceLock},
};
use tokio::sync::broadcast::{self, Receiver, Sender};
use tracing::level_filters::LevelFilter;
use tracing_log::LogTracer;
#[cfg(feature = "telemetry")]
use tracing_opentelemetry::OpenTelemetryLayer;
#[cfg(target_os = "ios")]
use tracing_oslog::OsLogger;
use tracing_subscriber::{
    EnvFilter, Layer, Registry, filter::filter_fn, fmt::time::LocalTime, prelude::*,
    reload,
};

impl From<LogLevel> for LevelFilter {
    fn from(level: LogLevel) -> Self {
        match level {
            LogLevel::Error => LevelFilter::ERROR,
            LogLevel::Warning => LevelFilter::WARN,
            LogLevel::Info => LevelFilter::INFO,
            LogLevel::Debug => LevelFilter::DEBUG,
            LogLevel::Trace => LevelFilter::TRACE,
            LogLevel::Silent => LevelFilter::OFF,
        }
    }
}

#[derive(Clone, Serialize)]
pub struct LogEvent {
    #[serde(rename = "type")]
    pub level: LogLevel,
    #[serde(rename = "payload")]
    pub msg: String,
}

static LOG_EVENTS: LazyLock<Sender<LogEvent>> =
    LazyLock::new(|| broadcast::channel(512).0);

pub fn subscribe() -> Receiver<LogEvent> {
    LOG_EVENTS.subscribe()
}

pub struct EventCollector(Vec<Sender<LogEvent>>);

impl EventCollector {
    pub fn new(receivers: Vec<Sender<LogEvent>>) -> Self {
        Self(receivers)
    }
}

impl<S> Layer<S> for EventCollector
where
    S: tracing::Subscriber,
{
    fn on_event(
        &self,
        event: &tracing::Event<'_>,
        _ctx: tracing_subscriber::layer::Context<'_, S>,
    ) {
        let mut strs = vec![];
        event.record(&mut EventVisitor(&mut strs));

        let event = LogEvent {
            level: match *event.metadata().level() {
                tracing::Level::ERROR => LogLevel::Error,
                tracing::Level::WARN => LogLevel::Warning,
                tracing::Level::INFO => LogLevel::Info,
                tracing::Level::DEBUG => LogLevel::Debug,
                tracing::Level::TRACE => LogLevel::Trace,
            },
            msg: strs.join(" "),
        };
        let _ = LOG_EVENTS.send(event.clone());
        crate::app::events::emit_app("log", &event);
        for tx in &self.0 {
            _ = tx.send(event.clone());
        }
    }
}

struct LoggingGuard {
    _file_appender: Option<tracing_appender::non_blocking::WorkerGuard>,
    #[cfg(feature = "telemetry")]
    _tracing_chrome: Option<tracing_chrome::FlushGuard>,
    #[cfg(feature = "telemetry")]
    _tracer_provider: Option<opentelemetry_sdk::trace::SdkTracerProvider>,
}

static SETUP_LOGGING: Once = Once::new();
static mut LOGGING_GUARD: Option<LoggingGuard> = None;
static LOG_FILTER_RELOAD: OnceLock<reload::Handle<EnvFilter, Registry>> =
    OnceLock::new();

fn log_filter(level: LogLevel) -> EnvFilter {
    EnvFilter::new(match level {
        LogLevel::Trace => "warn,clash=trace,viaport=trace",
        LogLevel::Debug => "warn,clash=debug,viaport=debug",
        LogLevel::Info => "warn,clash=info,viaport=info",
        LogLevel::Warning => "warn",
        LogLevel::Error => "error",
        LogLevel::Silent => "off",
    })
}

pub fn set_log_level(level: LogLevel) -> anyhow::Result<()> {
    LOG_FILTER_RELOAD
        .get()
        .ok_or_else(|| anyhow!("logging is not initialized"))?
        .reload(log_filter(level))
        .map_err(|error| anyhow!("failed to reload log level: {error}"))
}

pub fn setup_logging(
    level: LogLevel,
    collector: EventCollector,
    cwd: &str,
    log_file: Option<String>,
) {
    unsafe {
        SETUP_LOGGING.call_once(|| {
            LogTracer::init().unwrap_or_else(|e| {
                eprintln!(
                    "Failed to init tracing-log: {e}, another env_logger might \
                     have been initialized"
                );
            });
            LOGGING_GUARD = setup_logging_inner(level, collector, cwd, log_file)
                .unwrap_or_else(|e| {
                    eprintln!("Failed to setup logging: {e}");
                    None
                });
        });
    }
    if let Err(error) = set_log_level(level) {
        eprintln!("Failed to apply log level: {error}");
    }
}

fn setup_logging_inner(
    level: LogLevel,
    collector: EventCollector,
    cwd: &str,
    log_file: Option<String>,
) -> anyhow::Result<Option<LoggingGuard>> {
    let (filter, reload_handle) = reload::Layer::new(log_filter(level));

    let (appender, guard) = if let Some(log_file) = log_file {
        let path_buf = std::path::PathBuf::from(&log_file);
        let log_path = if path_buf.is_absolute() {
            log_file
        } else {
            format!("{cwd}/{log_file}")
        };
        let writer = std::fs::File::options().append(true).open(log_path)?;
        let (non_blocking, guard) =
            tracing_appender::non_blocking::NonBlockingBuilder::default()
                .buffered_lines_limit(16_000)
                .lossy(true)
                .thread_name("clash-logger-appender")
                .finish(writer);
        (Some(non_blocking), Some(guard))
    } else {
        (None, None)
    };

    #[cfg(feature = "telemetry")]
    let (tracing_chrome, tracing_chrome_g) = if cfg!(feature = "telemetry") {
        let builder = tracing_chrome::ChromeLayerBuilder::new();
        let (layer, guard) = builder.build();
        (Some(layer), Some(guard))
    } else {
        (None, None)
    };

    #[cfg(feature = "telemetry")]
    let exporter = opentelemetry_otlp::SpanExporter::builder()
        .with_http()
        .with_protocol(Protocol::HttpBinary)
        .build()
        .unwrap();

    #[cfg(feature = "telemetry")]
    let tracer_provider = opentelemetry_sdk::trace::SdkTracerProvider::builder()
        // Customize sampling strategy
        .with_sampler(opentelemetry_sdk::trace::Sampler::ParentBased(Box::new(opentelemetry_sdk::trace::Sampler::TraceIdRatioBased(
            if cfg!(debug_assertions) {
                1.0 // 100% sampling in development
            } else {
                0.1 // 10% sampling in production
            },
        ))))
        .with_id_generator(opentelemetry_sdk::trace::RandomIdGenerator::default())
        .with_resource(opentelemetry_sdk::Resource::builder()
            .with_service_name(env!("CARGO_PKG_NAME"))
            .with_schema_url(
                [
                    opentelemetry::KeyValue::new(SERVICE_VERSION, env!("CARGO_PKG_VERSION")),
                    opentelemetry::KeyValue::new(DEPLOYMENT_ENVIRONMENT_NAME,  if cfg!(debug_assertions) {
                        "development"
                    } else {
                        "production"
                    }),
            ],
            SCHEMA_URL,
        )
        .build())
        .with_batch_exporter(exporter)
        .build();
    #[cfg(feature = "telemetry")]
    let tracer = tracer_provider.tracer("tracing-otel-subscriber");

    let subscriber = tracing_subscriber::registry();

    let exclude = filter_fn(|metadata| {
        !metadata.target().contains("tokio")
            && !metadata.target().contains("runtime")
    });

    let timer = LocalTime::new(time::macros::format_description!(
        "[year repr:last_two]-[month]-[day] [hour]:[minute]:[second]:[subsecond]"
    ));

    let log_to_file_layer = appender.map(|x| {
        tracing_subscriber::fmt::Layer::new()
            .with_timer(timer.clone())
            .with_ansi(false)
            .compact()
            .with_file(true)
            .with_line_number(true)
            .with_level(true)
            .with_writer(x)
            .with_filter(exclude.clone())
    });
    let log_stdout_layer = tracing_subscriber::fmt::Layer::new()
        .with_timer(timer)
        .with_ansi(std::io::stdout().is_terminal())
        .compact()
        .with_target(cfg!(debug_assertions))
        .with_file(true)
        .with_line_number(true)
        .with_level(true)
        .with_thread_ids(cfg!(debug_assertions))
        .with_writer(std::io::stdout)
        .with_filter(exclude.clone());

    let subscriber = {
        #[cfg(feature = "telemetry")]
        {
            subscriber
        .with(filter) // Global filter
        .with(tracing_chrome)
        .with(OpenTelemetryLayer::new(tracer))
        .with(collector.with_filter(exclude.clone()))
        .with(log_to_file_layer)
        .with(log_stdout_layer)
        }
        #[cfg(not(feature = "telemetry"))]
        {
            subscriber.with(filter) // Global filter
        .with(collector.with_filter(exclude.clone()))
        .with(log_to_file_layer)
        .with(log_stdout_layer)
        }
    };

    #[cfg(target_os = "ios")]
    let subscriber =
        subscriber.with(Some(OsLogger::new("com.watfaq.clash", "default")));

    #[cfg(target_os = "android")]
    let subscriber = subscriber.with(android_log::AndroidLogLayer);

    tracing::subscriber::set_global_default(subscriber)
        .map_err(|x| anyhow!("setup logging error: {}", x))?;
    LOG_FILTER_RELOAD
        .set(reload_handle)
        .map_err(|_| anyhow!("log filter reload handle is already initialized"))?;

    Ok(Some(LoggingGuard {
        _file_appender: guard,
        #[cfg(feature = "telemetry")]
        _tracing_chrome: tracing_chrome_g,
        #[cfg(feature = "telemetry")]
        _tracer_provider: Some(tracer_provider),
    }))
}

struct EventVisitor<'a>(&'a mut Vec<String>);

impl EventVisitor<'_> {
    fn push_display(
        &mut self,
        field: &tracing::field::Field,
        value: impl std::fmt::Display,
    ) {
        if field.name() != "message" {
            self.0.push(format!("{}={}", field.name(), value));
        }
    }

    fn push_debug(
        &mut self,
        field: &tracing::field::Field,
        value: &dyn std::fmt::Debug,
    ) {
        if field.name() == "message" {
            self.0.push(format!("{value:?}"));
        } else {
            self.0.push(format!("{}={value:?}", field.name()));
        }
    }
}

impl tracing::field::Visit for EventVisitor<'_> {
    fn record_f64(&mut self, field: &tracing::field::Field, value: f64) {
        self.push_display(field, value);
    }

    fn record_i64(&mut self, field: &tracing::field::Field, value: i64) {
        self.push_display(field, value);
    }

    fn record_u64(&mut self, field: &tracing::field::Field, value: u64) {
        self.push_display(field, value);
    }

    fn record_i128(&mut self, field: &tracing::field::Field, value: i128) {
        self.push_display(field, value);
    }

    fn record_u128(&mut self, field: &tracing::field::Field, value: u128) {
        self.push_display(field, value);
    }

    fn record_bool(&mut self, field: &tracing::field::Field, value: bool) {
        self.push_display(field, value);
    }

    fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
        self.push_display(field, value);
    }

    fn record_error(
        &mut self,
        field: &tracing::field::Field,
        value: &(dyn std::error::Error + 'static),
    ) {
        self.push_display(field, value);
    }

    fn record_debug(
        &mut self,
        field: &tracing::field::Field,
        value: &dyn std::fmt::Debug,
    ) {
        self.push_debug(field, value);
    }
}

#[cfg(target_os = "android")]
mod android_log {
    use super::EventVisitor;
    use std::ffi::CString;
    use tracing_subscriber::{Layer, layer::Context};

    unsafe extern "C" {
        fn __android_log_write(prio: i32, tag: *const u8, text: *const u8) -> i32;
    }

    const LOG_VERBOSE: i32 = 2;
    const LOG_DEBUG: i32 = 3;
    const LOG_INFO: i32 = 4;
    const LOG_WARN: i32 = 5;
    const LOG_ERROR: i32 = 6;

    pub(super) struct AndroidLogLayer;

    impl<S: tracing::Subscriber> Layer<S> for AndroidLogLayer {
        fn on_event(&self, event: &tracing::Event<'_>, _ctx: Context<'_, S>) {
            let mut strs = vec![];
            event.record(&mut EventVisitor(&mut strs));
            let msg = strs.join(" ");
            let prio = match *event.metadata().level() {
                tracing::Level::ERROR => LOG_ERROR,
                tracing::Level::WARN => LOG_WARN,
                tracing::Level::INFO => LOG_INFO,
                tracing::Level::DEBUG => LOG_DEBUG,
                tracing::Level::TRACE => LOG_VERBOSE,
            };
            let tag = CString::new("clash-rs").unwrap();
            if let Ok(cmsg) = CString::new(msg) {
                unsafe {
                    __android_log_write(prio, tag.as_ptr(), cmsg.as_ptr());
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{EventCollector, LogLevel, log_filter};
    use tokio::sync::broadcast;
    use tracing_subscriber::{layer::SubscriberExt, registry, reload};

    #[test]
    fn collector_keeps_message_and_fields_inline() {
        let (tx, mut rx) = broadcast::channel(1);
        let collector = EventCollector::new(vec![tx]);
        let subscriber = registry().with(collector);

        tracing::subscriber::with_default(subscriber, || {
            tracing::info!(answer = 42u64, kind = "demo", success = true, "hello");
        });

        let event = rx.try_recv().expect("expected collected log event");

        assert!(matches!(event.level, LogLevel::Info));
        assert!(event.msg.contains("hello"));
        assert!(event.msg.contains("answer=42"));
        assert!(event.msg.contains("kind=demo"));
        assert!(event.msg.contains("success=true"));
    }

    #[test]
    fn reloads_log_level_without_restarting_the_subscriber() {
        let (filter, handle) = reload::Layer::new(log_filter(LogLevel::Info));
        let subscriber = registry().with(filter);

        tracing::subscriber::with_default(subscriber, || {
            assert!(
                !tracing::enabled!(target: "clash::test", tracing::Level::DEBUG)
            );
            assert!(tracing::enabled!(target: "clash::test", tracing::Level::INFO));

            handle.reload(log_filter(LogLevel::Debug)).unwrap();
            assert!(tracing::enabled!(target: "clash::test", tracing::Level::DEBUG));

            handle.reload(log_filter(LogLevel::Silent)).unwrap();
            assert!(
                !tracing::enabled!(target: "clash::test", tracing::Level::ERROR)
            );
        });
    }
}
