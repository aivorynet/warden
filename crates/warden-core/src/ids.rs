//! Identifier newtypes (UUID v7).

use serde::{Deserialize, Serialize};
use std::fmt;
use uuid::Uuid;

macro_rules! id_type {
    ($(#[$m:meta])* $name:ident) => {
        $(#[$m])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
        #[serde(transparent)]
        pub struct $name(pub Uuid);

        impl $name {
            /// Create a new random time-ordered id (UUID v7).
            pub fn new() -> Self {
                Self(Uuid::now_v7())
            }

            /// Return the inner UUID.
            pub fn as_uuid(&self) -> &Uuid {
                &self.0
            }
        }

        impl Default for $name {
            fn default() -> Self {
                Self::new()
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                self.0.fmt(f)
            }
        }

        impl std::str::FromStr for $name {
            type Err = uuid::Error;
            fn from_str(s: &str) -> Result<Self, Self::Err> {
                Uuid::parse_str(s).map(Self)
            }
        }
    };
}

id_type!(
    /// Id of a vault item.
    ItemId
);
id_type!(
    /// Id of a device that holds a copy of the vault.
    DeviceId
);
id_type!(
    /// Id of a vault.
    VaultId
);
id_type!(
    /// Id of a pending inbox entry.
    InboxId
);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let id = ItemId::new();
        let json = serde_json::to_string(&id).unwrap();
        let back: ItemId = serde_json::from_str(&json).unwrap();
        assert_eq!(id, back);
        assert_eq!(id.to_string().parse::<ItemId>().unwrap(), id);
        assert_eq!(id.0.get_version_num(), 7);
    }
}
