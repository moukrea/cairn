//! YAML scenario deserialization matching the conformance test schema.

use serde::Deserialize;

/// A scenario file may contain one or many scenarios.
#[derive(Debug, Deserialize)]
pub struct ScenarioFile {
    pub scenarios: Vec<Scenario>,
}

/// A single conformance test scenario.
#[derive(Debug, Deserialize)]
#[allow(dead_code)]
pub struct Scenario {
    pub scenario: String,
    pub description: String,
    pub tier: u8,
    pub category: String,
    #[serde(default)]
    pub participants: Vec<Participant>,
    #[serde(default)]
    pub actions: Vec<Action>,
    #[serde(default)]
    pub expected: Vec<Expected>,
    #[serde(default)]
    pub timeout_ms: Option<u64>,
    #[serde(default)]
    pub budget_ms: Option<u64>,
}

/// A participant in the scenario.
#[derive(Debug, Deserialize)]
#[allow(dead_code)]
pub struct Participant {
    pub role: String,
    #[serde(default = "default_lang")]
    pub lang: String,
}

fn default_lang() -> String {
    "any".to_string()
}

/// An action to perform in the scenario.
#[derive(Debug, Deserialize)]
#[allow(dead_code)]
pub struct Action {
    #[serde(rename = "type")]
    pub action_type: String,
    #[serde(default)]
    pub actor: Option<String>,
    #[serde(default)]
    pub params: serde_yaml::Value,
}

/// An expected outcome.
#[derive(Debug, Deserialize)]
#[allow(dead_code)]
pub struct Expected {
    #[serde(rename = "type")]
    pub outcome_type: String,
    #[serde(default)]
    pub actor: Option<String>,
    #[serde(default)]
    pub params: serde_yaml::Value,
}

/// Find and load a scenario by name from the test directories.
pub fn find_scenario(scenario_name: &str, base_dir: &str) -> Option<Scenario> {
    let test_dir = format!("{}/tests", base_dir);
    let dirs = std::fs::read_dir(&test_dir).ok()?;

    for entry in dirs.flatten() {
        let path = entry.path();
        if !path.is_dir() {
            continue;
        }

        // Try .yml then .yaml extensions
        for ext in &["yml", "yaml"] {
            let scenario_path = path.join(format!("{}.{}", scenario_name, ext));
            if scenario_path.exists() {
                let content = std::fs::read_to_string(&scenario_path).ok()?;
                let file: ScenarioFile = serde_yaml::from_str(&content).ok()?;
                // Find the specific scenario by name
                return file
                    .scenarios
                    .into_iter()
                    .find(|s| s.scenario == scenario_name);
            }
        }

        // Also check for scenario embedded in a multi-scenario file
        for entry2 in std::fs::read_dir(&path).ok()?.flatten() {
            let fpath = entry2.path();
            if fpath.extension().is_some_and(|e| e == "yml" || e == "yaml") {
                if let Ok(content) = std::fs::read_to_string(&fpath) {
                    if let Ok(file) = serde_yaml::from_str::<ScenarioFile>(&content) {
                        if let Some(s) = file
                            .scenarios
                            .into_iter()
                            .find(|s| s.scenario == scenario_name)
                        {
                            return Some(s);
                        }
                    }
                }
            }
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deserialize_scenario_file() {
        let yaml = r#"
scenarios:
  - scenario: test-basic
    description: A basic test
    tier: 0
    category: wire
    participants:
      - { role: encoder, lang: any }
    actions:
      - type: verify_cbor
        actor: encoder
        params:
          operation: roundtrip
    expected:
      - type: cbor_match
        params:
          description: "test"
    timeout_ms: 2000
"#;
        let file: ScenarioFile = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(file.scenarios.len(), 1);
        assert_eq!(file.scenarios[0].scenario, "test-basic");
        assert_eq!(file.scenarios[0].tier, 0);
        assert_eq!(file.scenarios[0].category, "wire");
        assert_eq!(file.scenarios[0].actions.len(), 1);
        assert_eq!(file.scenarios[0].actions[0].action_type, "verify_cbor");
    }
}
