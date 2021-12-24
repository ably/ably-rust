pub use ::log::{debug, error, info, trace, warn};

use atty::Stream;
use simplelog::{ColorChoice, Config, LevelFilter, SimpleLogger, TermLogger, TerminalMode};

use crate::Result;

pub fn init() -> Result<()> {
    let res = if atty::is(Stream::Stdout) {
        TermLogger::init(
            LevelFilter::Warn,
            Config::default(),
            TerminalMode::Mixed,
            ColorChoice::Auto,
        )
    } else {
        SimpleLogger::init(LevelFilter::Warn, Config::default())
    };
    res.map_err(Into::into)
}
