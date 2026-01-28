//! JSON Schema validation helpers.

use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::sync::{Arc, Mutex};

use jsonschema::Validator;
use serde_json::Value;

use crate::error::GraphqlClientError;

#[derive(Debug, Default)]
pub struct SchemaCache {
    inner: Mutex<std::collections::HashMap<u64, Arc<Validator>>>,
}

impl SchemaCache {
    /// Fetch or compile a schema validator.
    pub fn get_or_compile(&self, schema: &str) -> Result<Arc<Validator>, GraphqlClientError> {
        let mut hasher = DefaultHasher::new();
        schema.hash(&mut hasher);
        let key = hasher.finish();

        if let Some(existing) = self.inner.lock().expect("schema cache lock").get(&key) {
            return Ok(Arc::clone(existing));
        }

        let value: Value = serde_json::from_str(schema)?;
        let validator = Validator::new(&value).map_err(|err| GraphqlClientError::SchemaValidation {
            message: "invalid JSON Schema".to_string(),
            errors: vec![err.to_string()],
        })?;

        let validator = Arc::new(validator);
        self.inner
            .lock()
            .expect("schema cache lock")
            .insert(key, Arc::clone(&validator));

        Ok(validator)
    }

    /// Validate a JSON value against a schema.
    pub fn validate(&self, schema: &str, value: &Value) -> Result<(), GraphqlClientError> {
        let validator = self.get_or_compile(schema)?;
        let mut errors = Vec::new();
        for error in validator.iter_errors(value) {
            errors.push(error.to_string());
        }
        if errors.is_empty() {
            Ok(())
        } else {
            Err(GraphqlClientError::SchemaValidation {
                message: "schema validation failed".to_string(),
                errors,
            })
        }
    }
}
