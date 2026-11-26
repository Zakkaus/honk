use honk_config::Config;

#[test]
fn subscription_ids_must_be_non_nil_and_unique() {
    let id = "6f1c2a4e-7d3b-4c5a-9e8f-0a1b2c3d4e5f";
    for (ids, refused) in [
        ([id, "00000000-0000-0000-0000-000000000001"], None),
        ([id, id], Some("subscriptions[2].id")),
        (
            ["00000000-0000-0000-0000-000000000000", id],
            Some("subscriptions[1].id"),
        ),
    ] {
        let config: Config = serde_json::from_value(serde_json::json!({
            "subscriptions": [
                {"name": "one", "url": "https://example.test/one", "id": ids[0]},
                {"name": "two", "url": "https://example.test/two", "id": ids[1]},
            ],
        }))
        .unwrap();
        for result in [config.validate_detailed(), config.validate_assembled()] {
            match (result, refused) {
                (Ok(()), None) => {}
                (Err(error), Some(setting)) => {
                    assert_eq!(error.diagnostic.code, "invalid-subscription-id");
                    assert_eq!(error.diagnostic.setting.to_string(), setting);
                }
                (result, _) => panic!("{ids:?}: {result:?}"),
            }
        }
    }
}
