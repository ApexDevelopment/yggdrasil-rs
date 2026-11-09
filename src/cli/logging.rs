//! A logger for the `log` crate that writes like yggdrasil-go's: to stdout,
//! a file, or syslog, with Go's `2006/01/02 15:04:05` timestamps.

use std::fs::OpenOptions;
use std::io::Write;
use std::sync::Mutex;

use log::{LevelFilter, Log, Metadata, Record};

enum Output {
	Stdout,
	File(std::fs::File),
	#[cfg(unix)]
	Syslog(syslog::Logger<syslog::LoggerBackend, syslog::Formatter3164>),
}

struct Logger {
	output: Mutex<Output>,
	level: LevelFilter,
}

/// The local time as `YYYY/MM/DD HH:MM:SS`.
fn timestamp() -> String {
	let now = std::time::SystemTime::now()
		.duration_since(std::time::UNIX_EPOCH)
		.map(|since| since.as_secs() as i64)
		.unwrap_or_default();
	#[cfg(unix)]
	{
		// Inferred from localtime_r, as musl deprecates naming time_t
		let time = now as _;
		let mut tm: libc::tm = unsafe { std::mem::zeroed() };
		// Safe: both pointers are valid for the duration of the call
		if !unsafe { libc::localtime_r(&time, &mut tm) }.is_null() {
			return format!(
				"{:04}/{:02}/{:02} {:02}:{:02}:{:02}",
				tm.tm_year + 1900,
				tm.tm_mon + 1,
				tm.tm_mday,
				tm.tm_hour,
				tm.tm_min,
				tm.tm_sec
			);
		}
	}
	utc_timestamp(now)
}

fn utc_timestamp(seconds: i64) -> String {
	let days = seconds.div_euclid(86400);
	let secs = seconds.rem_euclid(86400);
	// Civil-from-days, by Howard Hinnant
	let z = days + 719468;
	let era = z.div_euclid(146097);
	let doe = z - era * 146097;
	let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
	let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
	let mp = (5 * doy + 2) / 153;
	let day = doy - (153 * mp + 2) / 5 + 1;
	let month = if mp < 10 { mp + 3 } else { mp - 9 };
	let year = yoe + era * 400 + i64::from(month <= 2);
	format!(
		"{year:04}/{month:02}/{day:02} {:02}:{:02}:{:02}",
		secs / 3600,
		secs / 60 % 60,
		secs % 60
	)
}

impl Log for Logger {
	fn enabled(&self, metadata: &Metadata<'_>) -> bool {
		metadata.level() <= self.level && metadata.target().starts_with("yggdrasil")
	}

	fn log(&self, record: &Record<'_>) {
		if !self.enabled(record.metadata()) {
			return;
		}
		let mut output = self
			.output
			.lock()
			.unwrap_or_else(|poisoned| poisoned.into_inner());
		match &mut *output {
			Output::Stdout => {
				println!("{} {}", timestamp(), record.args());
			}
			Output::File(file) => {
				let _ = writeln!(file, "{} {}", timestamp(), record.args());
			}
			#[cfg(unix)]
			Output::Syslog(logger) => {
				let _ = logger.notice(record.args().to_string());
			}
		}
	}

	fn flush(&self) {
		let _ = std::io::stdout().flush();
	}
}

/// Parses a yggdrasil-go log level name. Unknown names give `None`.
pub fn parse_level(name: &str) -> Option<LevelFilter> {
	Some(match name.to_lowercase().as_str() {
		"error" => LevelFilter::Error,
		"warn" => LevelFilter::Warn,
		"info" => LevelFilter::Info,
		"debug" => LevelFilter::Debug,
		"trace" => LevelFilter::Trace,
		_ => return None,
	})
}

/// Installs the logger. `target` is `stdout`, `syslog`, or a file path.
pub fn init(target: &str, level: LevelFilter) {
	let mut fallback = false;
	let output = match target {
		"stdout" => Output::Stdout,
		#[cfg(unix)]
		"syslog" => {
			let formatter = syslog::Formatter3164 {
				facility: syslog::Facility::LOG_DAEMON,
				hostname: None,
				process: crate::version::build_name().into(),
				pid: std::process::id(),
			};
			match syslog::unix(formatter) {
				Ok(logger) => Output::Syslog(logger),
				Err(_) => {
					fallback = true;
					Output::Stdout
				}
			}
		}
		path => match OpenOptions::new().append(true).create(true).open(path) {
			Ok(file) => Output::File(file),
			Err(_) => {
				fallback = true;
				Output::Stdout
			}
		},
	};
	let logger = Logger {
		output: Mutex::new(output),
		level,
	};
	if log::set_boxed_logger(Box::new(logger)).is_ok() {
		log::set_max_level(level);
	}
	if fallback {
		log::warn!("Logging defaulting to stdout");
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn formats_utc_timestamps() {
		assert_eq!(utc_timestamp(0), "1970/01/01 00:00:00");
		assert_eq!(utc_timestamp(1_000_000_000), "2001/09/09 01:46:40");
		assert_eq!(utc_timestamp(951_782_400), "2000/02/29 00:00:00");
	}
}
