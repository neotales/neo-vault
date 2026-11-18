use nvault::{Capabilities, ListedKey, Provider, Result, Secret};

struct LegacyProvider;

impl Provider for LegacyProvider {
    fn name(&self) -> &str {
        "fixture"
    }

    fn kind(&self) -> &'static str {
        "fixture"
    }

    fn capabilities(&self) -> Capabilities {
        Capabilities::READ_WRITE
    }

    fn list(&self, _: &str) -> Result<Vec<ListedKey>> {
        Ok(Vec::new())
    }

    fn get(&self, _: &str) -> Result<Secret> {
        Ok(Secret::new(Vec::new()))
    }
}

#[test]
fn legacy_literals_and_read_only_remain_available() {
    let old = Capabilities {
        read: true,
        write: false,
        list: true,
        ensure: false,
    };
    assert_eq!(old, Capabilities::READ_ONLY);
    assert!(LegacyProvider.can_create());
}
