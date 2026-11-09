//! Text tables in the style yggdrasilctl prints them.

#[derive(Default)]
pub struct Table {
	header: Option<Vec<String>>,
	rows: Vec<Vec<String>>,
	borders: bool,
}

fn width(text: &str) -> usize {
	text.chars().count()
}

fn pad_left(text: &str, width_: usize) -> String {
	format!("{text}{}", " ".repeat(width_ - width(text)))
}

fn center(text: &str, width_: usize) -> String {
	let space = width_ - width(text);
	format!(
		"{}{text}{}",
		" ".repeat(space / 2),
		" ".repeat(space - space / 2)
	)
}

impl Table {
	pub fn new(borders: bool) -> Self {
		Table {
			borders,
			..Default::default()
		}
	}

	pub fn header(&mut self, cells: &[&str]) {
		self.header = Some(cells.iter().map(|cell| cell.to_string()).collect());
	}

	pub fn row(&mut self, cells: Vec<String>) {
		self.rows.push(cells);
	}

	fn widths(&self) -> Vec<usize> {
		let mut widths = Vec::new();
		for row in self.header.iter().chain(&self.rows) {
			for (i, cell) in row.iter().enumerate() {
				if widths.len() <= i {
					widths.push(0);
				}
				widths[i] = widths[i].max(width(cell));
			}
		}
		widths
	}

	fn line(&self, widths: &[usize], left: char, middle: char, right: char) -> String {
		let segments: Vec<String> = widths.iter().map(|w| "─".repeat(w + 2)).collect();
		format!("{left}{}{right}\n", segments.join(&middle.to_string()))
	}

	fn cells(
		&self,
		widths: &[usize],
		cells: &[String],
		align: fn(&str, usize) -> String,
	) -> String {
		let padded: Vec<String> = widths
			.iter()
			.enumerate()
			.map(|(i, w)| format!(" {} ", align(cells.get(i).map_or("", String::as_str), *w)))
			.collect();
		if self.borders {
			format!("│{}│\n", padded.join("│"))
		} else {
			format!("{}\n", padded.concat())
		}
	}

	pub fn render(&self) -> String {
		let widths = self.widths();
		if widths.is_empty() {
			return String::new();
		}
		let mut out = String::new();
		if self.borders {
			out.push_str(&self.line(&widths, '┌', '┬', '┐'));
		}
		if let Some(header) = &self.header {
			out.push_str(&self.cells(&widths, header, center));
			if self.borders && !self.rows.is_empty() {
				out.push_str(&self.line(&widths, '├', '┼', '┤'));
			}
		}
		for row in &self.rows {
			out.push_str(&self.cells(&widths, row, pad_left));
		}
		if self.borders {
			out.push_str(&self.line(&widths, '└', '┴', '┘'));
		}
		out
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn renders_like_yggdrasilctl() {
		let mut table = Table::new(true);
		table.header(&["Command", "Arguments"]);
		table.row(vec!["addpeer".into(), "uri=...".into()]);
		assert_eq!(
			table.render(),
			"┌─────────┬───────────┐\n│ Command │ Arguments │\n├─────────┼───────────┤\n│ addpeer │ uri=...   │\n└─────────┴───────────┘\n"
		);
		let mut table = Table::new(false);
		table.row(vec!["Name:".into(), "x".into()]);
		table.row(vec!["Longer:".into(), "y".into()]);
		assert_eq!(table.render(), " Name:    x \n Longer:  y \n");
	}
}
