use super::error::{Error, ErrorKind, Result};

#[derive(Debug, PartialEq)]
pub enum CurveKind {
    Nistp256,
    Nistp384,
    Nistp521,
}

#[derive(Debug, PartialEq)]
pub struct Curve {
    pub kind: CurveKind,
    pub identifier: &'static str,
}

impl Curve {
    pub fn from_identifier(id: &str) -> Result<Curve> {
        let curve = match id {
            "nistp256" => Curve { kind: CurveKind::Nistp256, identifier: "nistp256" },
            "nistp384" => Curve { kind: CurveKind::Nistp384, identifier: "nistp384" },
            "nistp521" => Curve { kind: CurveKind::Nistp521, identifier: "nistp521" },
            _ => return Err(Error::with_kind(ErrorKind::UnknownCurve(id.to_string()))),
        };

        Ok(curve)
    }
}
