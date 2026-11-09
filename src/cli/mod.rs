//! Helpers shared by the command-line programs.

pub mod flags;
pub mod logging;
pub mod table;

use std::time::Duration;

/// Formats a duration like Go's `time.Duration.String`, e.g. `1h2m3.5s` or `1.5ms`.
pub fn go_duration(duration: Duration) -> String {
	/// The last `precision` digits of `value` as a fraction without trailing zeros, and the rest.
	fn fraction(value: u64, precision: u32) -> (String, u64) {
		let mut digits = String::new();
		let mut rest = value;
		for _ in 0..precision {
			let digit = rest % 10;
			if !digits.is_empty() || digit != 0 {
				digits.insert(0, char::from(b'0' + digit as u8));
			}
			rest /= 10;
		}
		let digits = if digits.is_empty() {
			digits
		} else {
			format!(".{digits}")
		};
		(digits, rest)
	}
	let nanos = duration.as_nanos().min(u64::MAX as u128) as u64;
	if nanos == 0 {
		return "0s".into();
	}
	if nanos < 1_000_000_000 {
		let (unit, precision) = match nanos {
			n if n < 1_000 => ("ns", 0),
			n if n < 1_000_000 => ("µs", 3),
			_ => ("ms", 6),
		};
		let (fraction, whole) = fraction(nanos, precision);
		return format!("{whole}{fraction}{unit}");
	}
	let (fraction, whole_seconds) = fraction(nanos, 9);
	let (hours, minutes, seconds) = (
		whole_seconds / 3600,
		whole_seconds / 60 % 60,
		whole_seconds % 60,
	);
	match (hours, minutes) {
		(0, 0) => format!("{seconds}{fraction}s"),
		(0, _) => format!("{minutes}m{seconds}{fraction}s"),
		_ => format!("{hours}h{minutes}m{seconds}{fraction}s"),
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn formats_durations_like_go() {
		for (duration, expected) in [
			(Duration::ZERO, "0s"),
			(Duration::from_nanos(15), "15ns"),
			(Duration::from_nanos(1_500), "1.5µs"),
			(Duration::from_micros(1_234_567), "1.234567s"),
			(Duration::from_millis(1_500), "1.5s"),
			(Duration::from_secs(3600), "1h0m0s"),
			(Duration::from_secs(65), "1m5s"),
			(Duration::from_nanos(2_000_100), "2.0001ms"),
		] {
			assert_eq!(go_duration(duration), expected);
		}
	}
}
