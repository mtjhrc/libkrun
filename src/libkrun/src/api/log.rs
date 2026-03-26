use env_logger::Env;

use super::error::ErrorCode;

pub struct KrunLog;

fn log_level_to_filter_str(level: u32) -> &'static str {
    match level {
        0 => "off",
        1 => "error",
        2 => "warn",
        3 => "info",
        4 => "debug",
        _ => "trace",
    }
}

#[ffier::exportable(prefix = "krun")]
impl KrunLog {
    pub fn init(level: u32) -> Result<(), ErrorCode> {
        let filter = log_level_to_filter_str(level);
        env_logger::Builder::from_env(Env::default().default_filter_or(filter))
            .format_timestamp_micros()
            .try_init()
            .map_err(|_| ErrorCode::Internal)?;
        Ok(())
    }
}
