pub fn serialize<S: serde::Serializer>(
    value: &users::Group,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    serde::Serialize::serialize(&value.name(), serializer)
}

pub fn deserialize<'de, D>(deserializer: D) -> Result<users::Group, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let group_name = &<String as serde::Deserialize>::deserialize(deserializer)?;
    users::get_group_by_name(group_name)
        .ok_or_else(|| serde::de::Error::custom(format!("group not found: '{}'", group_name)))
}
