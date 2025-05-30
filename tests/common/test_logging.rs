/// Initializes logging for tests.
pub fn init_logging() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::new(
            "debug,reqwest=off,hyper=off",
        ))
        .try_init();
}