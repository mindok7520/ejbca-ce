use std::{
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};

use crate::{
    AppState,
    ca::{
        CreateCaRequest, ImportCaRequest, RenewCaRequest, RolloverCaRequest, UpdateCaRequest,
        service as ca_service,
    },
    certs::{
        IssueCertificateRequest, IssueCsrRequest, IssuePkcs12Request, service as cert_service,
    },
    cluster::{self as cluster_service, ClusterHeartbeatRequest},
    cmp::service as cmp_service,
    compat::{self as compat_service, CreateEjbcaFeatureRequest, UpdateEjbcaFeatureRequest},
    config::Command,
    crl::{GenerateCrlRequest, service as crl_service},
    key_provider::{self, CommandSignerConfig},
    maintenance::{
        MaintenanceRequest, UpdateMaintenanceConfigRequest, service as maintenance_service,
    },
    profiles::{
        CreateAccessRoleRequest, CreateCertificateProfileRequest, CreateCmpAliasRequest,
        CreateEndEntityProfileRequest, UpdateAccessRoleRequest, UpdateCertificateProfileRequest,
        UpdateCmpAliasRequest, UpdateEndEntityProfileRequest, service as profile_service,
    },
    ra::{
        self as ra_service, CreateApprovalRequest, CreateEndEntityRequest, DecideApprovalRequest,
        UpdateEndEntityRequest,
    },
    storage::{AuditEventFilter, CertificateFilter},
    util::parse_distinguished_name,
    validators::{CreateValidatorRequest, UpdateValidatorRequest, service as validator_service},
};
use rcgen::{CertificateParams, KeyPair};

pub async fn run(command: Command, state: &AppState) -> Result<()> {
    match command {
        Command::Serve => {}
        Command::ListCas => print_json(ca_service::list_cas(state).await?)?,
        Command::CreateCa {
            name,
            subject_dn,
            validity_days,
        } => {
            let response = ca_service::create_ca(
                state,
                CreateCaRequest {
                    name,
                    subject_dn,
                    validity_days,
                },
                "cli",
            )
            .await?;
            print_json(response)?;
        }
        Command::UpdateCa {
            id,
            name,
            status,
            make_default,
        } => {
            let response = ca_service::update_ca(
                state,
                &id,
                UpdateCaRequest {
                    name,
                    status,
                    make_default: Some(make_default),
                },
                "cli",
            )
            .await?;
            print_json(response)?;
        }
        Command::RenewCa { id, validity_days } => {
            let response =
                ca_service::renew_ca(state, &id, RenewCaRequest { validity_days }, "cli").await?;
            print_json(response)?;
        }
        Command::RolloverCa {
            id,
            name,
            subject_dn,
            validity_days,
            make_default,
            disable_old,
        } => {
            let response = ca_service::rollover_ca(
                state,
                &id,
                RolloverCaRequest {
                    name,
                    subject_dn,
                    validity_days,
                    make_default: make_default.then_some(true),
                    disable_old: disable_old.then_some(true),
                },
                "cli",
            )
            .await?;
            print_json(response)?;
        }
        Command::ImportCa {
            name,
            cert_pem_file,
            key_ref,
        } => {
            let cert_pem = tokio::fs::read_to_string(&cert_pem_file).await?;
            let response = ca_service::import_ca(
                state,
                ImportCaRequest {
                    name,
                    cert_pem,
                    key_ref,
                },
                "cli",
            )
            .await?;
            print_json(response)?;
        }
        Command::BuildCommandKeyRef {
            command,
            args_json,
            timeout_ms,
            max_output_bytes,
        } => {
            let args = match args_json {
                Some(value) => serde_json::from_str::<Vec<String>>(&value)?,
                None => Vec::new(),
            };
            let reference = key_provider::command_key_ref(&CommandSignerConfig {
                command,
                args,
                timeout_ms,
                max_output_bytes,
            })?;
            println!("{reference}");
        }
        Command::BuildEncryptedKeyRef { key_pem_file } => {
            let key_pem = tokio::fs::read_to_string(&key_pem_file).await?;
            let reference = key_provider::encrypted_key_ref_from_pem(&key_pem)?;
            println!("{reference}");
        }
        Command::ListClusterNodes { limit } => {
            print_json(cluster_service::list_nodes(state, list_limit(limit, state)).await?)?;
        }
        Command::ClusterHeartbeat {
            node_id,
            role,
            status,
            metadata_json,
        } => {
            let metadata = match metadata_json {
                Some(value) => serde_json::from_str(&value)?,
                None => serde_json::json!({}),
            };
            let response = cluster_service::heartbeat(
                state,
                ClusterHeartbeatRequest {
                    node_id,
                    role,
                    status,
                    metadata,
                },
                "cli",
            )
            .await?;
            print_json(response)?;
        }
        Command::ListCertificateProfiles => {
            print_json(profile_service::list_certificate_profiles(state).await?)?;
        }
        Command::CreateCertificateProfile {
            name,
            validity_days,
            deny_server_generated_key,
            require_san,
        } => {
            let response = profile_service::create_certificate_profile(
                state,
                CreateCertificateProfileRequest {
                    name,
                    validity_days,
                    key_usages: Vec::new(),
                    extended_key_usages: Vec::new(),
                    allow_server_generated_key: Some(!deny_server_generated_key),
                    require_san: Some(require_san),
                },
                "cli",
            )
            .await?;
            print_json(response)?;
        }
        Command::UpdateCertificateProfile {
            id,
            name,
            validity_days,
            key_usages,
            extended_key_usages,
            allow_server_generated_key,
            require_san,
        } => {
            let response = profile_service::update_certificate_profile(
                state,
                &id,
                UpdateCertificateProfileRequest {
                    name,
                    validity_days,
                    key_usages: non_empty_vec(key_usages),
                    extended_key_usages: non_empty_vec(extended_key_usages),
                    allow_server_generated_key,
                    require_san,
                },
                "cli",
            )
            .await?;
            print_json(response)?;
        }
        Command::DeleteCertificateProfile { id } => {
            profile_service::delete_certificate_profile(state, &id, "cli").await?;
            print_json(serde_json::json!({"deleted": true, "id": id}))?;
        }
        Command::ListEndEntityProfiles => {
            print_json(profile_service::list_end_entity_profiles(state).await?)?;
        }
        Command::CreateEndEntityProfile {
            name,
            subject_regex,
            allowed_dns_domains,
            default_certificate_profile_id,
        } => {
            let response = profile_service::create_end_entity_profile(
                state,
                CreateEndEntityProfileRequest {
                    name,
                    subject_regex,
                    allowed_dns_domains,
                    default_certificate_profile_id,
                },
                "cli",
            )
            .await?;
            print_json(response)?;
        }
        Command::UpdateEndEntityProfile {
            id,
            name,
            subject_regex,
            allowed_dns_domains,
            default_certificate_profile_id,
        } => {
            let response = profile_service::update_end_entity_profile(
                state,
                &id,
                UpdateEndEntityProfileRequest {
                    name,
                    subject_regex,
                    allowed_dns_domains: non_empty_vec(allowed_dns_domains),
                    default_certificate_profile_id,
                },
                "cli",
            )
            .await?;
            print_json(response)?;
        }
        Command::DeleteEndEntityProfile { id } => {
            profile_service::delete_end_entity_profile(state, &id, "cli").await?;
            print_json(serde_json::json!({"deleted": true, "id": id}))?;
        }
        Command::ListEndEntities {
            username,
            status,
            ca_id,
            limit,
        } => {
            print_json(
                ra_service::list_end_entities(
                    state,
                    clean_filter(username),
                    clean_filter(status),
                    clean_filter(ca_id),
                    list_limit(limit, state),
                )
                .await?,
            )?;
        }
        Command::CreateEndEntity {
            username,
            subject_dn,
            dns_names,
            email,
            ca_id,
            certificate_profile_id,
            end_entity_profile_id,
            status,
            password,
            token_type,
        } => {
            let response = ra_service::create_end_entity(
                state,
                CreateEndEntityRequest {
                    username,
                    subject_dn,
                    dns_names,
                    email,
                    ca_id,
                    certificate_profile_id,
                    end_entity_profile_id,
                    status,
                    password,
                    token_type,
                },
                "cli",
            )
            .await?;
            print_json(response)?;
        }
        Command::UpdateEndEntity {
            id,
            username,
            subject_dn,
            dns_names,
            email,
            ca_id,
            certificate_profile_id,
            end_entity_profile_id,
            status,
            password,
            token_type,
        } => {
            let response = ra_service::update_end_entity(
                state,
                &id,
                UpdateEndEntityRequest {
                    username,
                    subject_dn,
                    dns_names: non_empty_vec(dns_names),
                    email,
                    ca_id,
                    certificate_profile_id,
                    end_entity_profile_id,
                    status,
                    password,
                    token_type,
                },
                "cli",
            )
            .await?;
            print_json(response)?;
        }
        Command::DeleteEndEntity { id } => {
            ra_service::delete_end_entity(state, &id, "cli").await?;
            print_json(serde_json::json!({"deleted": true, "id": id}))?;
        }
        Command::ListApprovals {
            action,
            target_id,
            status,
            limit,
        } => {
            print_json(
                ra_service::list_approval_requests(
                    state,
                    clean_filter(action),
                    clean_filter(target_id),
                    clean_filter(status),
                    list_limit(limit, state),
                )
                .await?,
            )?;
        }
        Command::CreateApproval {
            action,
            target_id,
            request_json,
            expires_at,
        } => {
            let response = ra_service::create_approval_request(
                state,
                CreateApprovalRequest {
                    action,
                    target_id,
                    request: serde_json::from_str(&request_json)?,
                    expires_at,
                },
                "cli",
            )
            .await?;
            print_json(response)?;
        }
        Command::DecideApproval {
            id,
            status,
            decision_json,
        } => {
            let response = ra_service::decide_approval_request(
                state,
                &id,
                DecideApprovalRequest {
                    status,
                    decision: serde_json::from_str(&decision_json)?,
                },
                "cli",
            )
            .await?;
            print_json(response)?;
        }
        Command::ListCmpAliases => print_json(profile_service::list_cmp_aliases(state).await?)?,
        Command::CreateCmpAlias {
            alias,
            ca_id,
            certificate_profile_id,
            end_entity_profile_id,
            disabled,
            hmac_secret,
        } => {
            let response = profile_service::create_cmp_alias(
                state,
                CreateCmpAliasRequest {
                    alias,
                    ca_id,
                    certificate_profile_id,
                    end_entity_profile_id,
                    enabled: Some(!disabled),
                    hmac_secret,
                },
                "cli",
            )
            .await?;
            print_json(response)?;
        }
        Command::UpdateCmpAlias {
            id,
            alias,
            ca_id,
            certificate_profile_id,
            end_entity_profile_id,
            enabled,
            hmac_secret,
            clear_hmac_secret,
        } => {
            let response = profile_service::update_cmp_alias(
                state,
                &id,
                UpdateCmpAliasRequest {
                    alias,
                    ca_id,
                    certificate_profile_id,
                    end_entity_profile_id,
                    enabled,
                    hmac_secret,
                    clear_hmac_secret: Some(clear_hmac_secret),
                },
                "cli",
            )
            .await?;
            print_json(response)?;
        }
        Command::DeleteCmpAlias { id } => {
            profile_service::delete_cmp_alias(state, &id, "cli").await?;
            print_json(serde_json::json!({"deleted": true, "id": id}))?;
        }
        Command::CmpP10crSmoke {
            server_url,
            alias,
            subject_dn,
            dns_names,
            hmac_secret,
            request_der_file,
            response_der_file,
        } => {
            let summary = run_cmp_p10cr_smoke(CmpP10crSmokeOptions {
                server_url,
                alias,
                subject_dn,
                dns_names,
                hmac_secret,
                request_der_file,
                response_der_file,
            })
            .await?;
            print_json(summary)?;
        }
        Command::CmpIssueRevokeSmoke {
            server_url,
            alias,
            subject_dn,
            dns_names,
            hmac_secret,
        } => {
            let summary = run_cmp_issue_revoke_smoke(CmpIssueRevokeSmokeOptions {
                server_url,
                alias,
                subject_dn,
                dns_names,
                hmac_secret,
            })
            .await?;
            print_json(summary)?;
        }
        Command::SimulateDevice {
            device_config,
            output_dir,
        } => {
            let summary = run_virtual_device_simulation(state, &device_config, output_dir).await?;
            print_json(summary)?;
        }
        Command::ListAccessRoles => print_json(profile_service::list_access_roles(state).await?)?,
        Command::CreateAccessRole {
            name,
            permissions,
            api_token,
            certificate_issuer_dn,
            certificate_match_key,
            certificate_match_value,
        } => {
            let response = profile_service::create_access_role(
                state,
                CreateAccessRoleRequest {
                    name,
                    permissions,
                    api_token,
                    certificate_issuer_dn,
                    certificate_match_key,
                    certificate_match_value,
                },
                "cli",
            )
            .await?;
            print_json(response)?;
        }
        Command::UpdateAccessRole {
            id,
            name,
            permissions,
            api_token,
            clear_api_token,
            certificate_issuer_dn,
            certificate_match_key,
            certificate_match_value,
            clear_certificate_member,
        } => {
            let response = profile_service::update_access_role(
                state,
                &id,
                UpdateAccessRoleRequest {
                    name,
                    permissions: non_empty_vec(permissions),
                    api_token,
                    clear_api_token: Some(clear_api_token),
                    certificate_issuer_dn,
                    certificate_match_key,
                    certificate_match_value,
                    clear_certificate_member: Some(clear_certificate_member),
                },
                "cli",
            )
            .await?;
            print_json(response)?;
        }
        Command::DeleteAccessRole { id } => {
            profile_service::delete_access_role(state, &id, "cli").await?;
            print_json(serde_json::json!({"deleted": true, "id": id}))?;
        }
        Command::ListEjbcaFeatures {
            feature_type,
            status,
            limit,
        } => {
            print_json(
                compat_service::list_features(
                    state,
                    clean_filter(feature_type),
                    clean_filter(status),
                    list_limit(limit, state),
                )
                .await?,
            )?;
        }
        Command::CreateEjbcaFeature {
            feature_type,
            name,
            status,
            config_json,
        } => {
            let config = serde_json::from_str(&config_json)?;
            let response = compat_service::create_feature(
                state,
                CreateEjbcaFeatureRequest {
                    feature_type,
                    name,
                    status: Some(status),
                    config,
                },
                "cli",
            )
            .await?;
            print_json(response)?;
        }
        Command::UpdateEjbcaFeature {
            id,
            feature_type,
            name,
            status,
            config_json,
        } => {
            let config = match config_json {
                Some(value) => Some(serde_json::from_str(&value)?),
                None => None,
            };
            let response = compat_service::update_feature(
                state,
                &id,
                UpdateEjbcaFeatureRequest {
                    feature_type,
                    name,
                    status,
                    config,
                },
                "cli",
            )
            .await?;
            print_json(response)?;
        }
        Command::DeleteEjbcaFeature { id } => {
            compat_service::delete_feature(state, &id, "cli").await?;
            print_json(serde_json::json!({"deleted": true, "id": id}))?;
        }
        Command::ListCertificates {
            limit,
            ca_id,
            status,
            serial_hex,
            subject,
            expires_before,
            expires_after,
        } => {
            let filter = CertificateFilter {
                ca_id: clean_filter(ca_id),
                status: clean_filter(status).map(|value| value.to_ascii_lowercase()),
                serial_hex: clean_filter(serial_hex).map(|value| value.to_ascii_lowercase()),
                subject_contains: clean_filter(subject),
                expires_before,
                expires_after,
            };
            print_json(
                cert_service::list_certificates(state, filter, list_limit(limit, state)).await?,
            )?;
        }
        Command::GetCertificate { id } => {
            print_json(cert_service::get_certificate(state, &id).await?)?;
        }
        Command::ExportCertificate {
            id,
            format,
            output_file,
        } => {
            let format = format.trim().to_ascii_lowercase();
            match format.as_str() {
                "pem" => {
                    let pem = cert_service::certificate_pem(state, &id).await?;
                    write_or_print(output_file, pem.into_bytes()).await?;
                }
                "der" => {
                    if output_file.is_none() {
                        anyhow::bail!("DER export는 --output-file이 필요합니다");
                    }
                    let der = cert_service::certificate_der(state, &id).await?;
                    write_or_print(output_file, der).await?;
                }
                _ => anyhow::bail!("format은 pem 또는 der이어야 합니다"),
            }
        }
        Command::IssueCertificate {
            end_entity_id,
            approval_id,
            ca_id,
            certificate_profile_id,
            end_entity_profile_id,
            subject_dn,
            dns_names,
            validity_days,
        } => {
            let response = cert_service::issue_generated(
                state,
                IssueCertificateRequest {
                    end_entity_id,
                    approval_id,
                    ca_id,
                    certificate_profile_id,
                    end_entity_profile_id,
                    subject_dn,
                    dns_names,
                    validity_days,
                },
                "cli",
            )
            .await?;
            print_json(response)?;
        }
        Command::IssueBrowserCertificate {
            end_entity_id,
            approval_id,
            ca_id,
            certificate_profile_id,
            end_entity_profile_id,
            subject_dn,
            dns_names,
            validity_days,
            pkcs12_password,
            friendly_name,
            output_file,
        } => {
            let response = cert_service::issue_pkcs12(
                state,
                IssuePkcs12Request {
                    end_entity_id,
                    approval_id,
                    ca_id,
                    certificate_profile_id,
                    end_entity_profile_id,
                    subject_dn,
                    dns_names,
                    validity_days,
                    pkcs12_password,
                    friendly_name,
                },
                "cli",
            )
            .await?;
            tokio::fs::write(&output_file, &response.der).await?;
            print_json(serde_json::json!({
                "certificate_id": response.certificate_id,
                "serial_hex": response.serial_hex,
                "pkcs12_file": output_file,
            }))?;
        }
        Command::LoadTestIssuance {
            total,
            concurrency,
            start_index,
            subject_prefix,
            dns_suffix,
            ca_id,
            certificate_profile_id,
            end_entity_profile_id,
            validity_days,
            sample_failures,
        } => {
            let summary = run_issuance_load_test(
                state,
                LoadTestIssuanceOptions {
                    total,
                    concurrency,
                    start_index,
                    subject_prefix,
                    dns_suffix,
                    ca_id,
                    certificate_profile_id,
                    end_entity_profile_id,
                    validity_days,
                    sample_failures,
                },
            )
            .await?;
            print_json(summary)?;
        }
        Command::SoakTestIssuance {
            duration_seconds,
            concurrency,
            max_total,
            start_index,
            subject_prefix,
            dns_suffix,
            ca_id,
            certificate_profile_id,
            end_entity_profile_id,
            validity_days,
            sample_failures,
        } => {
            let summary = run_issuance_soak_test(
                state,
                SoakTestIssuanceOptions {
                    duration_seconds,
                    concurrency,
                    max_total,
                    start_index,
                    subject_prefix,
                    dns_suffix,
                    ca_id,
                    certificate_profile_id,
                    end_entity_profile_id,
                    validity_days,
                    sample_failures,
                },
            )
            .await?;
            print_json(summary)?;
        }
        Command::IssueCsr {
            end_entity_id,
            approval_id,
            ca_id,
            certificate_profile_id,
            end_entity_profile_id,
            csr_pem_file,
            validity_days,
        } => {
            let csr_pem = tokio::fs::read_to_string(&csr_pem_file).await?;
            let response = cert_service::issue_from_csr(
                state,
                IssueCsrRequest {
                    end_entity_id,
                    approval_id,
                    ca_id,
                    certificate_profile_id,
                    end_entity_profile_id,
                    csr_pem,
                    validity_days,
                },
                "cli",
            )
            .await?;
            print_json(response)?;
        }
        Command::RevokeCertificate {
            id,
            reason,
            approval_id,
        } => {
            let response =
                cert_service::revoke_certificate(state, &id, reason, approval_id, "cli").await?;
            print_json(response)?;
        }
        Command::ListCrls { limit } => {
            print_json(crl_service::list_crls(state, list_limit(limit, state)).await?)?;
        }
        Command::GenerateCrl {
            ca_id,
            validity_days,
            delta,
            partition_index,
            partition_count,
        } => {
            let response = crl_service::generate_crl(
                state,
                GenerateCrlRequest {
                    ca_id,
                    validity_days,
                    is_delta: Some(delta),
                    partition_index,
                    partition_count,
                },
                "cli",
            )
            .await?;
            print_json(response)?;
        }
        Command::ListValidators => print_json(validator_service::list_validators(state).await?)?,
        Command::CreateValidator {
            name,
            kind,
            config_json,
            disabled,
        } => {
            let response = validator_service::create_validator(
                state,
                CreateValidatorRequest {
                    name,
                    kind,
                    config: serde_json::from_str(&config_json)?,
                    enabled: Some(!disabled),
                },
                "cli",
            )
            .await?;
            print_json(response)?;
        }
        Command::UpdateValidator {
            id,
            name,
            kind,
            config_json,
            enabled,
        } => {
            let response = validator_service::update_validator(
                state,
                &id,
                UpdateValidatorRequest {
                    name,
                    kind,
                    config: match config_json {
                        Some(value) => Some(serde_json::from_str(&value)?),
                        None => None,
                    },
                    enabled,
                },
                "cli",
            )
            .await?;
            print_json(response)?;
        }
        Command::DeleteValidator { id } => {
            validator_service::delete_validator(state, &id, "cli").await?;
            print_json(serde_json::json!({"deleted": true, "id": id}))?;
        }
        Command::MaintenanceConfig => {
            print_json(maintenance_service::config_response(state).await?)?;
        }
        Command::SetMaintenanceConfig {
            enabled,
            interval_seconds,
            backup,
            purge_expired_certificates,
            purge_expired_crls,
            purge_metric_events,
            purge_audit_events,
            optimize,
            older_than_days,
            batch_size,
            generate_crls,
            crl_validity_days,
            crl_partition_count,
            metrics_enabled,
            metrics_public,
            metrics_device_limit,
            metrics_event_retention_days,
            audit_event_retention_days,
            log_level,
            log_output,
            log_dir,
            log_retention_days,
            log_retention_files,
            cors_allowed_origins,
        } => {
            let response = maintenance_service::update_config(
                state,
                UpdateMaintenanceConfigRequest {
                    enabled,
                    interval_seconds,
                    backup,
                    purge_expired_certificates,
                    purge_expired_crls,
                    purge_metric_events,
                    purge_audit_events,
                    optimize,
                    older_than_days,
                    batch_size,
                    generate_crls,
                    crl_validity_days,
                    crl_partition_count,
                    metrics_enabled,
                    metrics_public,
                    metrics_device_limit,
                    metrics_event_retention_days,
                    audit_event_retention_days,
                    log_level,
                    log_output,
                    log_dir,
                    log_retention_days,
                    log_retention_files,
                    cors_allowed_origins,
                },
                "cli",
            )
            .await?;
            print_json(response)?;
        }
        Command::RunMaintenance {
            backup,
            purge_expired_certificates,
            purge_expired_crls,
            purge_metric_events,
            purge_audit_events,
            optimize,
            older_than_days,
            batch_size,
            generate_crls,
            crl_validity_days,
            crl_partition_count,
        } => {
            let response = maintenance_service::run_maintenance(
                state,
                MaintenanceRequest {
                    backup: Some(backup),
                    purge_expired_certificates: Some(purge_expired_certificates),
                    purge_expired_crls: Some(purge_expired_crls),
                    purge_metric_events: Some(purge_metric_events),
                    purge_audit_events: Some(purge_audit_events),
                    optimize: Some(optimize),
                    older_than_days,
                    batch_size,
                    generate_crls: Some(generate_crls),
                    crl_validity_days,
                    crl_partition_count,
                },
                "cli",
            )
            .await?;
            print_json(response)?;
        }
        Command::ListAuditEvents {
            limit,
            actor,
            action,
            target,
            status,
            since,
            until,
        } => {
            let filter = AuditEventFilter {
                actor: clean_filter(actor),
                action: clean_filter(action),
                target: clean_filter(target),
                status: clean_filter(status),
                since,
                until,
            };
            print_json(
                state
                    .db
                    .list_audit_events(&filter, list_limit(limit, state))
                    .await?,
            )?;
        }
        Command::VerifyAuditEvents => {
            print_json(state.db.verify_audit_chain().await?)?;
        }
    }
    Ok(())
}

#[derive(Clone)]
struct CmpP10crSmokeOptions {
    server_url: String,
    alias: String,
    subject_dn: String,
    dns_names: Vec<String>,
    hmac_secret: Option<String>,
    request_der_file: Option<String>,
    response_der_file: Option<String>,
}

struct GeneratedCmpP10cr {
    private_key_pem: String,
    csr_pem: String,
    request_der: Vec<u8>,
    request_protected: bool,
}

#[derive(Debug, Serialize)]
struct CmpP10crSmokeSummary {
    url: String,
    request_der_bytes: usize,
    request_protected: bool,
    response_der_bytes: usize,
    response_body_type: String,
    response_body_tag: u64,
    response_protected: bool,
    response_extra_certs: bool,
    issued_serial_hexes: Vec<String>,
    request_der_file: Option<String>,
    response_der_file: Option<String>,
}

#[derive(Clone)]
struct CmpIssueRevokeSmokeOptions {
    server_url: String,
    alias: String,
    subject_dn: String,
    dns_names: Vec<String>,
    hmac_secret: Option<String>,
}

#[derive(Debug, Serialize)]
struct CmpIssueRevokeSmokeSummary {
    url: String,
    issue_request_protected: bool,
    issue_response_body_type: String,
    issued_serial_hex: String,
    revoke_request_protected: bool,
    revoke_response_body_type: String,
    revocation_status_count: usize,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(default)]
struct VirtualDeviceConfig {
    device_id: String,
    server_url: String,
    alias: String,
    subject_dn: String,
    dns_names: Vec<String>,
    hmac_secret: Option<String>,
    output_dir: Option<String>,
    private_key_pem_file: Option<String>,
    csr_pem_file: Option<String>,
    request_der_file: Option<String>,
    response_der_file: Option<String>,
    summary_json_file: Option<String>,
}

impl Default for VirtualDeviceConfig {
    fn default() -> Self {
        Self {
            device_id: "device-001".to_string(),
            server_url: String::new(),
            alias: "iot-ra".to_string(),
            subject_dn: "CN=device-001,O=Example Devices,C=KR".to_string(),
            dns_names: vec!["device-001.example.internal".to_string()],
            hmac_secret: None,
            output_dir: None,
            private_key_pem_file: None,
            csr_pem_file: None,
            request_der_file: None,
            response_der_file: None,
            summary_json_file: None,
        }
    }
}

#[derive(Debug, Serialize)]
struct VirtualDeviceSimulationSummary {
    device_id: String,
    alias: String,
    subject_dn: String,
    dns_names: Vec<String>,
    url: String,
    output_dir: String,
    private_key_pem_file: String,
    csr_pem_file: String,
    request_der_file: String,
    response_der_file: String,
    summary_json_file: String,
    request_der_bytes: usize,
    request_protected: bool,
    response_der_bytes: usize,
    response_body_type: String,
    response_body_tag: u64,
    response_protected: bool,
    response_extra_certs: bool,
    issued_serial_hexes: Vec<String>,
}

async fn run_cmp_p10cr_smoke(options: CmpP10crSmokeOptions) -> Result<CmpP10crSmokeSummary> {
    let generated = build_cmp_p10cr_request(
        &options.subject_dn,
        &options.dns_names,
        options.hmac_secret.as_deref(),
    )?;

    if let Some(path) = &options.request_der_file {
        tokio::fs::write(path, &generated.request_der)
            .await
            .with_context(|| format!("CMP 요청 DER 파일을 쓸 수 없습니다: {path}"))?;
    }

    let url = format!(
        "{}/cmp/{}",
        options.server_url.trim_end_matches('/'),
        options.alias
    );
    let response_bytes = post_cmp_pkixcmp(&url, generated.request_der.clone()).await?;

    let response_summary = cmp_service::summarize_pki_message_der(&response_bytes)?;
    if let Some(path) = &options.response_der_file {
        tokio::fs::write(path, &response_bytes)
            .await
            .with_context(|| format!("CMP 응답 DER 파일을 쓸 수 없습니다: {path}"))?;
    }

    Ok(CmpP10crSmokeSummary {
        url,
        request_der_bytes: generated.request_der.len(),
        request_protected: generated.request_protected,
        response_der_bytes: response_bytes.len(),
        response_body_type: response_summary.body_type,
        response_body_tag: response_summary.body_tag,
        response_protected: response_summary.protected,
        response_extra_certs: response_summary.extra_certs,
        issued_serial_hexes: response_summary.certificate_serial_hexes,
        request_der_file: options.request_der_file,
        response_der_file: options.response_der_file,
    })
}

async fn run_virtual_device_simulation(
    state: &AppState,
    device_config: &str,
    output_dir_override: Option<String>,
) -> Result<VirtualDeviceSimulationSummary> {
    let config = load_virtual_device_config(device_config).await?;
    let hmac_secret = config
        .hmac_secret
        .clone()
        .or_else(|| crate::config::configured_cmp_alias_secret(&config.alias));
    let generated = build_cmp_p10cr_request(
        &config.subject_dn,
        &config.dns_names,
        hmac_secret.as_deref(),
    )?;

    let output_dir = output_dir_override
        .or(config.output_dir.clone())
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            PathBuf::from(&state.settings.data_dir)
                .join("simulated-devices")
                .join(&config.device_id)
        });
    tokio::fs::create_dir_all(&output_dir)
        .await
        .with_context(|| {
            format!(
                "시뮬레이션 출력 디렉터리를 만들 수 없습니다: {}",
                output_dir.display()
            )
        })?;

    let private_key_pem_file = resolve_output_file(
        &output_dir,
        config.private_key_pem_file.as_deref(),
        "device-key.pem",
    );
    let csr_pem_file = resolve_output_file(
        &output_dir,
        config.csr_pem_file.as_deref(),
        "device.csr.pem",
    );
    let request_der_file = resolve_output_file(
        &output_dir,
        config.request_der_file.as_deref(),
        "cmp-request.der",
    );
    let response_der_file = resolve_output_file(
        &output_dir,
        config.response_der_file.as_deref(),
        "cmp-response.der",
    );
    let summary_json_file = resolve_output_file(
        &output_dir,
        config.summary_json_file.as_deref(),
        "summary.json",
    );

    tokio::fs::write(&private_key_pem_file, generated.private_key_pem.as_bytes())
        .await
        .with_context(|| {
            format!(
                "가상 장비 private key 파일을 쓸 수 없습니다: {}",
                private_key_pem_file.display()
            )
        })?;
    tokio::fs::write(&csr_pem_file, generated.csr_pem.as_bytes())
        .await
        .with_context(|| {
            format!(
                "가상 장비 CSR 파일을 쓸 수 없습니다: {}",
                csr_pem_file.display()
            )
        })?;
    tokio::fs::write(&request_der_file, &generated.request_der)
        .await
        .with_context(|| {
            format!(
                "가상 장비 CMP 요청 DER 파일을 쓸 수 없습니다: {}",
                request_der_file.display()
            )
        })?;

    let server_url = if config.server_url.trim().is_empty() {
        state.settings.public_base_url.clone()
    } else {
        config.server_url.clone()
    };
    let url = format!("{}/cmp/{}", server_url.trim_end_matches('/'), config.alias);
    let response_bytes = post_cmp_pkixcmp(&url, generated.request_der.clone()).await?;
    tokio::fs::write(&response_der_file, &response_bytes)
        .await
        .with_context(|| {
            format!(
                "가상 장비 CMP 응답 DER 파일을 쓸 수 없습니다: {}",
                response_der_file.display()
            )
        })?;
    let response_summary = cmp_service::summarize_pki_message_der(&response_bytes)?;

    let summary = VirtualDeviceSimulationSummary {
        device_id: config.device_id,
        alias: config.alias,
        subject_dn: config.subject_dn,
        dns_names: config.dns_names,
        url,
        output_dir: output_dir.display().to_string(),
        private_key_pem_file: private_key_pem_file.display().to_string(),
        csr_pem_file: csr_pem_file.display().to_string(),
        request_der_file: request_der_file.display().to_string(),
        response_der_file: response_der_file.display().to_string(),
        summary_json_file: summary_json_file.display().to_string(),
        request_der_bytes: generated.request_der.len(),
        request_protected: generated.request_protected,
        response_der_bytes: response_bytes.len(),
        response_body_type: response_summary.body_type,
        response_body_tag: response_summary.body_tag,
        response_protected: response_summary.protected,
        response_extra_certs: response_summary.extra_certs,
        issued_serial_hexes: response_summary.certificate_serial_hexes,
    };
    let summary_json = serde_json::to_vec_pretty(&summary)?;
    tokio::fs::write(&summary_json_file, summary_json)
        .await
        .with_context(|| {
            format!(
                "가상 장비 시뮬레이션 요약 파일을 쓸 수 없습니다: {}",
                summary_json_file.display()
            )
        })?;
    Ok(summary)
}

fn build_cmp_p10cr_request(
    subject_dn: &str,
    dns_names: &[String],
    hmac_secret: Option<&str>,
) -> Result<GeneratedCmpP10cr> {
    let key_pair = KeyPair::generate()?;
    let mut params = CertificateParams::new(dns_names.to_vec())?;
    params.distinguished_name = parse_distinguished_name(subject_dn)?;
    let csr = params.serialize_request(&key_pair)?;
    let csr_der = csr.der().as_ref().to_vec();
    let csr_pem = pem::encode(&pem::Pem::new("CERTIFICATE REQUEST", csr_der.clone()));
    let request_der =
        cmp_service::build_p10cr_pki_message_der(&csr_der, hmac_secret.map(str::as_bytes))?;
    let request_summary = cmp_service::summarize_pki_message_der(&request_der)?;
    Ok(GeneratedCmpP10cr {
        private_key_pem: key_pair.serialize_pem(),
        csr_pem,
        request_der,
        request_protected: request_summary.protected,
    })
}

async fn load_virtual_device_config(path: &str) -> Result<VirtualDeviceConfig> {
    let content = tokio::fs::read_to_string(path)
        .await
        .with_context(|| format!("가상 장비 설정 파일을 읽을 수 없습니다: {path}"))?;
    if path.ends_with(".json") {
        Ok(serde_json::from_str(&content)?)
    } else {
        Ok(toml::from_str(&content)?)
    }
}

fn resolve_output_file(
    base: &std::path::Path,
    configured: Option<&str>,
    default_name: &str,
) -> PathBuf {
    let path = PathBuf::from(configured.unwrap_or(default_name));
    if path.is_absolute() {
        path
    } else {
        base.join(path)
    }
}

async fn run_cmp_issue_revoke_smoke(
    options: CmpIssueRevokeSmokeOptions,
) -> Result<CmpIssueRevokeSmokeSummary> {
    let url = format!(
        "{}/cmp/{}",
        options.server_url.trim_end_matches('/'),
        options.alias
    );
    let hmac_secret = options.hmac_secret.as_deref().map(str::as_bytes);

    let key_pair = KeyPair::generate()?;
    let mut params = CertificateParams::new(options.dns_names.clone())?;
    params.distinguished_name = parse_distinguished_name(&options.subject_dn)?;
    let csr = params.serialize_request(&key_pair)?;
    let issue_request = cmp_service::build_p10cr_pki_message_der(csr.der().as_ref(), hmac_secret)?;
    let issue_request_summary = cmp_service::summarize_pki_message_der(&issue_request)?;
    let issue_response = post_cmp_pkixcmp(&url, issue_request).await?;
    let issue_response_summary = cmp_service::summarize_pki_message_der(&issue_response)?;
    let issued_serial_hex = issue_response_summary
        .certificate_serial_hexes
        .first()
        .cloned()
        .ok_or_else(|| {
            anyhow::anyhow!("CMP p10cr 응답에서 발급 인증서 serial을 찾을 수 없습니다")
        })?;

    let revoke_request = cmp_service::build_rr_pki_message_der(
        std::slice::from_ref(&issued_serial_hex),
        hmac_secret,
    )?;
    let revoke_request_summary = cmp_service::summarize_pki_message_der(&revoke_request)?;
    let revoke_response = post_cmp_pkixcmp(&url, revoke_request).await?;
    let revoke_response_summary = cmp_service::summarize_pki_message_der(&revoke_response)?;

    Ok(CmpIssueRevokeSmokeSummary {
        url,
        issue_request_protected: issue_request_summary.protected,
        issue_response_body_type: issue_response_summary.body_type,
        issued_serial_hex,
        revoke_request_protected: revoke_request_summary.protected,
        revoke_response_body_type: revoke_response_summary.body_type,
        revocation_status_count: revoke_response_summary.revocation_status_count.unwrap_or(0),
    })
}

async fn post_cmp_pkixcmp(url: &str, request_der: Vec<u8>) -> Result<Vec<u8>> {
    let response = reqwest::Client::new()
        .post(url)
        .header(reqwest::header::CONTENT_TYPE, "application/pkixcmp")
        .header(reqwest::header::ACCEPT, "application/pkixcmp")
        .body(request_der)
        .send()
        .await?;
    let status = response.status();
    let response_bytes = response.bytes().await?.to_vec();
    if !status.is_success() {
        let text = String::from_utf8_lossy(&response_bytes);
        let snippet = text.chars().take(500).collect::<String>();
        bail!("CMP 요청 실패: status={status}, body={snippet}");
    }
    Ok(response_bytes)
}

#[derive(Clone)]
struct LoadTestIssuanceOptions {
    total: usize,
    concurrency: usize,
    start_index: usize,
    subject_prefix: String,
    dns_suffix: String,
    ca_id: Option<String>,
    certificate_profile_id: Option<String>,
    end_entity_profile_id: Option<String>,
    validity_days: Option<i64>,
    sample_failures: usize,
}

#[derive(Clone)]
struct SoakTestIssuanceOptions {
    duration_seconds: u64,
    concurrency: usize,
    max_total: Option<usize>,
    start_index: usize,
    subject_prefix: String,
    dns_suffix: String,
    ca_id: Option<String>,
    certificate_profile_id: Option<String>,
    end_entity_profile_id: Option<String>,
    validity_days: Option<i64>,
    sample_failures: usize,
}

#[derive(Debug, Default)]
struct LoadWorkerStats {
    success: usize,
    failure: usize,
    sample_failures: Vec<String>,
}

#[derive(Debug, Serialize)]
struct LoadTestIssuanceSummary {
    total: usize,
    concurrency: usize,
    success: usize,
    failure: usize,
    elapsed_ms: u128,
    certificates_per_second: f64,
    sample_failures: Vec<String>,
}

#[derive(Debug, Serialize)]
struct SoakTestIssuanceSummary {
    duration_seconds: u64,
    max_total: Option<usize>,
    concurrency: usize,
    attempted: usize,
    success: usize,
    failure: usize,
    failure_rate_percent: f64,
    elapsed_ms: u128,
    certificates_per_second: f64,
    stopped_by: String,
    sample_failures: Vec<String>,
}

async fn run_issuance_load_test(
    state: &AppState,
    options: LoadTestIssuanceOptions,
) -> Result<LoadTestIssuanceSummary> {
    if options.total == 0 {
        bail!("--total은 1 이상이어야 합니다");
    }
    if options.concurrency == 0 {
        bail!("--concurrency는 1 이상이어야 합니다");
    }

    let started = Instant::now();
    let next = Arc::new(AtomicUsize::new(0));
    let worker_count = options.concurrency.min(options.total);
    let sample_limit = options.sample_failures.min(100);
    let mut workers = Vec::with_capacity(worker_count);

    for _ in 0..worker_count {
        let state = state.clone();
        let options = options.clone();
        let next = next.clone();
        workers.push(tokio::spawn(async move {
            let mut stats = LoadWorkerStats::default();
            loop {
                let offset = next.fetch_add(1, Ordering::Relaxed);
                if offset >= options.total {
                    break;
                }
                let index = options.start_index.saturating_add(offset);
                let response = cert_service::issue_generated(
                    &state,
                    load_test_request(&options, index),
                    "cli-load-test",
                )
                .await;
                match response {
                    Ok(certificate) => {
                        drop(certificate);
                        stats.success += 1;
                    }
                    Err(err) => {
                        stats.failure += 1;
                        if stats.sample_failures.len() < sample_limit {
                            stats.sample_failures.push(err.to_string());
                        }
                    }
                }
            }
            stats
        }));
    }

    let mut success = 0usize;
    let mut failure = 0usize;
    let mut sample_failures = Vec::new();
    for worker in workers {
        let stats = worker.await?;
        success += stats.success;
        failure += stats.failure;
        if sample_failures.len() < sample_limit {
            let remaining = sample_limit - sample_failures.len();
            sample_failures.extend(stats.sample_failures.into_iter().take(remaining));
        }
    }

    let elapsed = started.elapsed();
    let elapsed_secs = elapsed.as_secs_f64().max(f64::EPSILON);
    Ok(LoadTestIssuanceSummary {
        total: options.total,
        concurrency: worker_count,
        success,
        failure,
        elapsed_ms: elapsed.as_millis(),
        certificates_per_second: success as f64 / elapsed_secs,
        sample_failures,
    })
}

async fn run_issuance_soak_test(
    state: &AppState,
    options: SoakTestIssuanceOptions,
) -> Result<SoakTestIssuanceSummary> {
    if options.duration_seconds == 0 {
        bail!("--duration-seconds는 1 이상이어야 합니다");
    }
    if options.concurrency == 0 {
        bail!("--concurrency는 1 이상이어야 합니다");
    }
    if matches!(options.max_total, Some(0)) {
        bail!("--max-total은 지정하는 경우 1 이상이어야 합니다");
    }

    let started = Instant::now();
    let deadline = started + Duration::from_secs(options.duration_seconds);
    let next = Arc::new(AtomicUsize::new(0));
    let worker_count = options
        .max_total
        .map(|max_total| options.concurrency.min(max_total))
        .unwrap_or(options.concurrency);
    let sample_limit = options.sample_failures.min(100);
    let mut workers = Vec::with_capacity(worker_count);

    for _ in 0..worker_count {
        let state = state.clone();
        let options = options.clone();
        let next = next.clone();
        workers.push(tokio::spawn(async move {
            let mut stats = LoadWorkerStats::default();
            loop {
                if Instant::now() >= deadline {
                    break;
                }
                let offset = next.fetch_add(1, Ordering::Relaxed);
                if options
                    .max_total
                    .map(|max_total| offset >= max_total)
                    .unwrap_or(false)
                {
                    break;
                }
                let index = options.start_index.saturating_add(offset);
                let response = cert_service::issue_generated(
                    &state,
                    issue_test_request(
                        index,
                        &options.subject_prefix,
                        &options.dns_suffix,
                        &options.ca_id,
                        &options.certificate_profile_id,
                        &options.end_entity_profile_id,
                        options.validity_days,
                    ),
                    "cli-soak-test",
                )
                .await;
                match response {
                    Ok(certificate) => {
                        drop(certificate);
                        stats.success += 1;
                    }
                    Err(err) => {
                        stats.failure += 1;
                        if stats.sample_failures.len() < sample_limit {
                            stats.sample_failures.push(err.to_string());
                        }
                    }
                }
            }
            stats
        }));
    }

    let mut success = 0usize;
    let mut failure = 0usize;
    let mut sample_failures = Vec::new();
    for worker in workers {
        let stats = worker.await?;
        success += stats.success;
        failure += stats.failure;
        if sample_failures.len() < sample_limit {
            let remaining = sample_limit - sample_failures.len();
            sample_failures.extend(stats.sample_failures.into_iter().take(remaining));
        }
    }

    let attempted = success + failure;
    let elapsed = started.elapsed();
    let elapsed_secs = elapsed.as_secs_f64().max(f64::EPSILON);
    let failure_rate_percent = if attempted == 0 {
        0.0
    } else {
        failure as f64 * 100.0 / attempted as f64
    };
    let stopped_by = if options
        .max_total
        .map(|max_total| attempted >= max_total)
        .unwrap_or(false)
    {
        "max_total"
    } else {
        "duration"
    };

    Ok(SoakTestIssuanceSummary {
        duration_seconds: options.duration_seconds,
        max_total: options.max_total,
        concurrency: worker_count,
        attempted,
        success,
        failure,
        failure_rate_percent,
        elapsed_ms: elapsed.as_millis(),
        certificates_per_second: success as f64 / elapsed_secs,
        stopped_by: stopped_by.to_string(),
        sample_failures,
    })
}

fn load_test_request(options: &LoadTestIssuanceOptions, index: usize) -> IssueCertificateRequest {
    issue_test_request(
        index,
        &options.subject_prefix,
        &options.dns_suffix,
        &options.ca_id,
        &options.certificate_profile_id,
        &options.end_entity_profile_id,
        options.validity_days,
    )
}

fn issue_test_request(
    index: usize,
    subject_prefix: &str,
    dns_suffix: &str,
    ca_id: &Option<String>,
    certificate_profile_id: &Option<String>,
    end_entity_profile_id: &Option<String>,
    validity_days: Option<i64>,
) -> IssueCertificateRequest {
    let device = format!("{subject_prefix}-{index:08}");
    let dns_suffix = dns_suffix.trim().trim_start_matches('.');
    let dns_names = if dns_suffix.is_empty() {
        Vec::new()
    } else {
        vec![format!("{device}.{dns_suffix}")]
    };
    IssueCertificateRequest {
        end_entity_id: None,
        approval_id: None,
        ca_id: ca_id.clone(),
        certificate_profile_id: certificate_profile_id.clone(),
        end_entity_profile_id: end_entity_profile_id.clone(),
        subject_dn: format!("CN={device},O=ejbca-rs Load Test"),
        dns_names,
        validity_days,
    }
}

fn print_json(value: impl serde::Serialize) -> Result<()> {
    println!("{}", serde_json::to_string_pretty(&value)?);
    Ok(())
}

fn list_limit(requested: Option<i64>, state: &AppState) -> i64 {
    requested
        .unwrap_or(100)
        .clamp(1, state.settings.max_list_limit.max(1))
}

fn clean_filter(value: Option<String>) -> Option<String> {
    value
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

fn non_empty_vec(values: Vec<String>) -> Option<Vec<String>> {
    if values.is_empty() {
        None
    } else {
        Some(values)
    }
}

async fn write_or_print(output_file: Option<String>, bytes: Vec<u8>) -> Result<()> {
    if let Some(path) = output_file {
        tokio::fs::write(path, bytes).await?;
    } else {
        println!("{}", String::from_utf8_lossy(&bytes));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::{path::PathBuf, sync::Arc};

    use tokio::sync::Semaphore;
    use uuid::Uuid;

    use super::*;
    use crate::{ca, config::Settings, profiles, storage::Db};

    async fn test_state() -> (AppState, PathBuf) {
        let data_dir = std::env::temp_dir().join(format!("ejbca-rs-cli-test-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&data_dir).expect("테스트 data dir 생성 실패");
        let settings = Arc::new(Settings {
            config_file: None,
            bind_addr: "127.0.0.1:0".parse().unwrap(),
            data_dir: data_dir.to_string_lossy().to_string(),
            database_url: None,
            admin_token: Some("test-admin-token".to_string()),
            public_base_url: "http://127.0.0.1:0".to_string(),
            ca_key_provider: "database".to_string(),
            ca_key_dir: None,
            max_request_bytes: 100_000,
            max_list_limit: 1000,
            cors_allowed_origins: String::new(),
            adminweb_client_cert_required: false,
            adminweb_client_cert_header: "x-admin-client-cert-pem".to_string(),
            adminweb_client_cert_proxy_secret: None,
            adminweb_client_cert_allowed_fingerprints: String::new(),
            adminweb_client_cert_allowed_subjects: String::new(),
            database_max_connections: 8,
            database_busy_timeout_seconds: 30,
            max_concurrent_issuance: 8,
            validator_webhook_default_timeout_ms: 3000,
            validator_webhook_max_timeout_ms: 30_000,
            validator_webhook_max_response_bytes: 8192,
            json_logs: false,
            log_level: "error".to_string(),
            log_output: "stdout".to_string(),
            log_dir: None,
            log_retention_days: 14,
            log_retention_files: 30,
            metrics_enabled: true,
            metrics_public: false,
            metrics_device_limit: 100,
            metrics_event_retention_days: 90,
            audit_event_retention_days: 365,
            maintenance_enabled: false,
            maintenance_interval_seconds: 3600,
            maintenance_backup: false,
            maintenance_purge_expired_certificates: false,
            maintenance_purge_expired_crls: false,
            maintenance_purge_audit_events: false,
            maintenance_optimize: false,
            maintenance_older_than_days: 30,
            maintenance_batch_size: 100,
            maintenance_generate_crls: false,
            maintenance_crl_validity_days: 7,
            maintenance_crl_partition_count: 1,
            command: None,
        });
        let db = Db::connect(
            &settings.database_url(),
            settings.database_max_connections,
            settings.database_busy_timeout_seconds,
        )
        .await
        .unwrap();
        db.migrate().await.unwrap();
        let state = AppState {
            db,
            settings: settings.clone(),
            http: reqwest::Client::new(),
            issue_limiter: Arc::new(Semaphore::new(settings.max_concurrent_issuance.max(1))),
        };
        ca::service::ensure_default_ca(&state).await.unwrap();
        profiles::service::ensure_default_profiles(&state)
            .await
            .unwrap();
        (state, data_dir)
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn load_test_issuance_uses_real_issue_path_and_records_metrics() {
        let (state, data_dir) = test_state().await;
        let summary = run_issuance_load_test(
            &state,
            LoadTestIssuanceOptions {
                total: 6,
                concurrency: 3,
                start_index: 1000,
                subject_prefix: "load-device".to_string(),
                dns_suffix: "load.example.com".to_string(),
                ca_id: None,
                certificate_profile_id: None,
                end_entity_profile_id: None,
                validity_days: Some(7),
                sample_failures: 5,
            },
        )
        .await
        .unwrap();

        assert_eq!(summary.total, 6);
        assert_eq!(summary.concurrency, 3);
        assert_eq!(summary.success, 6);
        assert_eq!(summary.failure, 0);
        assert!(summary.sample_failures.is_empty());
        assert!(summary.certificates_per_second > 0.0);

        let db_summary = state.db.summary().await.unwrap();
        assert_eq!(db_summary.issue_success_count, 6);
        assert_eq!(db_summary.issue_failure_count, 0);

        std::fs::remove_dir_all(data_dir).ok();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn soak_test_issuance_stops_at_max_total_and_records_metrics() {
        let (state, data_dir) = test_state().await;
        let summary = run_issuance_soak_test(
            &state,
            SoakTestIssuanceOptions {
                duration_seconds: 60,
                concurrency: 3,
                max_total: Some(5),
                start_index: 2000,
                subject_prefix: "soak-device".to_string(),
                dns_suffix: "soak.example.com".to_string(),
                ca_id: None,
                certificate_profile_id: None,
                end_entity_profile_id: None,
                validity_days: Some(7),
                sample_failures: 5,
            },
        )
        .await
        .unwrap();

        assert_eq!(summary.max_total, Some(5));
        assert_eq!(summary.concurrency, 3);
        assert_eq!(summary.attempted, 5);
        assert_eq!(summary.success, 5);
        assert_eq!(summary.failure, 0);
        assert_eq!(summary.failure_rate_percent, 0.0);
        assert_eq!(summary.stopped_by, "max_total");
        assert!(summary.sample_failures.is_empty());
        assert!(summary.certificates_per_second > 0.0);

        let db_summary = state.db.summary().await.unwrap();
        assert_eq!(db_summary.issue_success_count, 5);
        assert_eq!(db_summary.issue_failure_count, 0);

        std::fs::remove_dir_all(data_dir).ok();
    }
}
