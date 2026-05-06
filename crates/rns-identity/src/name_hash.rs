use rns_crypto::sha::sha256;

/// 80-bit name hash (`SHA-256(app_name)[:10]`).
///
/// `app_name` is the full dotted app/aspect path, e.g. `"lxmf.delivery"`.
pub fn name_hash(app_name: &str) -> [u8; 10] {
    let full = sha256(app_name.as_bytes());
    let mut out = [0u8; 10];
    out.copy_from_slice(&full[..10]);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_name_hash_basic() {
        let h = name_hash("test.app");
        assert_eq!(h.len(), 10);
    }

    #[test]
    fn test_name_hash_deterministic() {
        assert_eq!(name_hash("lxmf.delivery"), name_hash("lxmf.delivery"));
    }

    #[test]
    fn test_name_hash_different_names() {
        assert_ne!(name_hash("app.one"), name_hash("app.two"));
    }
}
