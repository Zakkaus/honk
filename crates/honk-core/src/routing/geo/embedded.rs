use super::{GeoRequirements, GeoSource, GeoSourceSet, capture_file};

impl GeoSourceSet {
    /// Reads `geosite.dat` and `geoip.dat` from `root` only. Unlike the
    /// daemon's search, which warns and empties the matcher, a required asset
    /// that is missing, does not parse or lacks a category the rules use is an
    /// error, as for a native-api replacement: an empty matcher would widen
    /// every negated rule that uses it.
    pub(crate) fn load_from_root(
        requirements: &GeoRequirements,
        root: &std::path::Path,
    ) -> std::io::Result<Self> {
        let capture = |required: bool, name: &str| {
            if required {
                let path = root.join(name);
                capture_file(&path).map_err(|error| {
                    std::io::Error::new(error.kind(), format!("{}: {error}", path.display()))
                })
            } else {
                Ok(GeoSource::Unused)
            }
        };
        let sources = Self::from_sources(
            capture(!requirements.geosite_codes.is_empty(), "geosite.dat")?,
            capture(!requirements.geoip_codes.is_empty(), "geoip.dat")?,
        );
        sources.validate(requirements)?;
        sources.contain(requirements)?;
        Ok(sources)
    }
}
