use std::io::{self, IsTerminal, Write};

#[derive(Debug, Clone, Copy)]
pub enum StatusStream {
    Stdout,
    Stderr,
}

pub struct StatusLine {
    stream: StatusStream,
    enabled: bool,
    frame: usize,
    last_message: Option<String>,
}

impl StatusLine {
    pub fn stdout() -> Self {
        Self::new(StatusStream::Stdout)
    }

    pub fn stderr() -> Self {
        Self::new(StatusStream::Stderr)
    }

    fn new(stream: StatusStream) -> Self {
        let enabled = match stream {
            StatusStream::Stdout => io::stdout().is_terminal(),
            StatusStream::Stderr => io::stderr().is_terminal(),
        };
        Self {
            stream,
            enabled,
            frame: 0,
            last_message: None,
        }
    }

    pub fn update(&mut self, prefix: &str, message: &str) -> io::Result<()> {
        if self.enabled {
            let frames = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];
            let frame = frames[self.frame % frames.len()];
            self.frame = self.frame.wrapping_add(1);
            self.write_raw(&format!("\r\x1b[2K{prefix} [{frame}] {message}"))?;
            return self.flush();
        }

        if self.last_message.as_deref() != Some(message) {
            self.write_raw(&format!("{prefix} {message}\n"))?;
            self.flush()?;
            self.last_message = Some(message.to_string());
        }

        Ok(())
    }

    pub fn clear(&mut self) -> io::Result<()> {
        if self.enabled {
            self.write_raw("\r\x1b[2K")?;
            self.flush()?;
        }
        Ok(())
    }

    fn write_raw(&mut self, value: &str) -> io::Result<()> {
        match self.stream {
            StatusStream::Stdout => {
                let mut handle = io::stdout().lock();
                handle.write_all(value.as_bytes())
            },
            StatusStream::Stderr => {
                let mut handle = io::stderr().lock();
                handle.write_all(value.as_bytes())
            },
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match self.stream {
            StatusStream::Stdout => io::stdout().lock().flush(),
            StatusStream::Stderr => io::stderr().lock().flush(),
        }
    }
}
