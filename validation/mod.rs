pub fn validate_request(request: &McpRequest, config: &ValidationConfig) -> Result<()> {
    // 1. Syntax Validation
    syntax::validate_request_syntax(request)
        .map_err(|e| MCPError::ValidationError { 
            stage: "Syntax".to_string(), 
            source: Box::new(e)
        })?;

    // 2. Semantic Validation
    semantics::validate_request_semantics(request)
        .map_err(|e| MCPError::ValidationError { 
            stage: "Semantics".to_string(), 
            source: Box::new(e)
        })?;

    // 3. Security Validation (if applicable)
    if config.enable_security_checks { 
        security::validate_request_security(request)
            .map_err(|e| MCPError::ValidationError { 
                stage: "Security".to_string(), 
                source: Box::new(e)
            })?;
    }

    // TODO: 4. Policy/Consent Validation (likely involves external lookups)

    Ok(())
} 