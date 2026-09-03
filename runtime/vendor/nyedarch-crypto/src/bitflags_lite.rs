//! Tiny internal bitflags to avoid pulling a dependency for a single u8 flag
//! set. Not a general-purpose implementation.
#[macro_export]
macro_rules! bitflags_lite {
    ($(#[$m:meta])* pub struct $name:ident: $t:ty { $(const $flag:ident = $val:expr;)* }) => {
        $(#[$m])*
        #[derive(Clone, Copy, Debug, PartialEq, Eq)]
        pub struct $name { bits: $t }
        impl $name {
            $(pub const $flag: $name = $name { bits: $val };)*
            pub const fn empty() -> Self { $name { bits: 0 } }
            pub const fn bits(&self) -> $t { self.bits }
            pub const fn from_bits_truncate(b: $t) -> Self {
                let mut all: $t = 0; $(all |= $val;)* $name { bits: b & all }
            }
            pub const fn contains(&self, other: Self) -> bool {
                (self.bits & other.bits) == other.bits
            }
        }
        impl core::ops::BitOr for $name {
            type Output = $name;
            fn bitor(self, rhs: Self) -> Self { $name { bits: self.bits | rhs.bits } }
        }
    };
}
