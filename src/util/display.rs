use std::fmt;

/// Write a representation as a human-readable size.
pub struct HumanReadableSize(pub u64);

impl fmt::Display for HumanReadableSize {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        const LN_KIB: f64 = 6.931471805599453; // 1024f64.ln()

        if self.0 == 0 {
            f.write_str("0 B")
        } else {
            let num = self.0 as f64;
            let exp = ((num.ln() / LN_KIB) as i32).clamp(0, 8);

            let val = num / 2f64.powi(exp * 10);

            write!(
                f,
                "{} {}",
                if exp > 0 {
                    (val * 10f64).round() / 10f64
                } else {
                    val.round()
                },
                ["B", "KiB", "MiB", "GiB", "TiB", "PiB", "EiB", "ZiB", "YiB"]
                    [exp.max(0) as usize]
            )
        }
    }
}

/// Replace `"` with `_`
pub struct NoDoubleQuotes<'s>(pub &'s str);

impl<'s> fmt::Display for NoDoubleQuotes<'s> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        for (i, s) in self.0.split('"').enumerate() {
            if i != 0 {
                f.write_str("_")?;
            }
            f.write_str(s)?
        }
        Ok(())
    }
}

/// Replace `&` with `&amp;` and `<` with `&lt;`
pub struct NoHtmlLiteral<'s>(pub &'s str);

impl<'s> fmt::Display for NoHtmlLiteral<'s> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        for mut s in self.0.split_inclusive(&['&', '<']) {
            let last = s.as_bytes().last();
            if matches!(last, Some(b'&' | b'<')) {
                s = &s[..s.len() - 1];
            }
            f.write_str(s)?;
            match last {
                Some(b'&') => f.write_str("&amp;")?,
                Some(b'<') => f.write_str("&lt;")?,
                _ => {}
            }
        }
        Ok(())
    }
}

pub struct CommaList<D: fmt::Display, I: Iterator<Item = D>>(pub I);

impl<D: fmt::Display, I: Iterator<Item = D> + Clone> fmt::Display for CommaList<D, I> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        for (i, item) in self.0.clone().enumerate() {
            if i != 0 {
                f.write_str(", ")?;
            }
            item.fmt(f)?;
        }
        Ok(())
    }
}

pub struct DisplayThree<Df: fmt::Display, Ds: fmt::Display, Dt: fmt::Display>(
    pub Df,
    pub Ds,
    pub Dt,
);

impl<Df: fmt::Display, Ds: fmt::Display, Dt: fmt::Display> fmt::Display
    for DisplayThree<Df, Ds, Dt>
{
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.0.fmt(f)?;
        self.1.fmt(f)?;
        self.2.fmt(f)?;
        Ok(())
    }
}

pub struct Maybe<T: fmt::Display>(pub Option<T>);

impl<T: fmt::Display> fmt::Display for Maybe<T> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        if let Some(dt) = self.0.as_ref() {
            dt.fmt(f)?;
        }
        Ok(())
    }
}
