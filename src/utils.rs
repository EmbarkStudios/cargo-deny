/// A replacement for strum, associates each discriminant with a string and implements parsing and stringization
#[macro_export]
macro_rules! simple_enum {
    ($(#[$outer:meta])* $enum_name:ident, [$($(#[$attr:meta])* $item:ident = $name:literal),+$(,)?]) => {
        $(#[$outer])*
        pub enum $enum_name {
            $(
                $(#[$attr])*
                $item,
            )+
        }

        impl $enum_name {
            pub const VARIANTS: &[Self] = &[
                $(Self::$item,)+
            ];
            pub const NAMES: &[&str] = &[
                $($name,)+
            ];

            #[inline]
            pub fn iter() -> impl Iterator<Item = Self> {
                [$(Self::$item,)+].into_iter()
            }

            pub fn as_str(self) -> &'static str {
                match self {
                    $(
                        Self::$item => $name,
                    )+
                }
            }
        }

        impl std::str::FromStr for $enum_name {
            type Err = ();
            fn from_str(s: &str) -> Result<Self, Self::Err> {
                Ok(match s {
                    $(
                        $name => Self::$item,
                    )+
                    _ => return Err(()),
                })
            }
        }

        impl std::fmt::Display for $enum_name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str((*self).as_str())
            }
        }
    };
}

/// Implements toml_span Deserialize for an enum that was declared via [`simple_enum!`]
#[macro_export]
macro_rules! enum_deser {
    ($enum:ty) => {
        impl<'de> toml_span::Deserialize<'de> for $enum {
            fn deserialize(
                value: &mut toml_span::value::Value<'de>,
            ) -> Result<Self, toml_span::DeserError> {
                let s = value.take_string(Some(stringify!($enum)))?;

                let Some(pos) = <$enum>::NAMES.iter().position(|v| *v == s.as_ref()) else {
                    return Err(toml_span::Error::from((
                        toml_span::ErrorKind::UnexpectedValue {
                            expected: <$enum>::NAMES,
                            value: None,
                        },
                        value.span,
                    ))
                    .into());
                };

                Ok(<$enum>::VARIANTS[pos])
            }
        }
    };
}
