--
-- PostgreSQL database dump
--

-- Dumped from database version 15.13
-- Dumped by pg_dump version 15.13

SET statement_timeout = 0;
SET lock_timeout = 0;
SET idle_in_transaction_session_timeout = 0;
SET client_encoding = 'UTF8';
SET standard_conforming_strings = on;
SELECT pg_catalog.set_config('search_path', '', false);
SET check_function_bodies = false;
SET xmloption = content;
SET client_min_messages = warning;
SET row_security = off;

--
-- Name: pg_trgm; Type: EXTENSION; Schema: -; Owner: -
--

CREATE EXTENSION IF NOT EXISTS pg_trgm WITH SCHEMA public;


--
-- Name: EXTENSION pg_trgm; Type: COMMENT; Schema: -; Owner: 
--

COMMENT ON EXTENSION pg_trgm IS 'text similarity measurement and index searching based on trigrams';


--
-- Name: uuid-ossp; Type: EXTENSION; Schema: -; Owner: -
--

CREATE EXTENSION IF NOT EXISTS "uuid-ossp" WITH SCHEMA public;


--
-- Name: EXTENSION "uuid-ossp"; Type: COMMENT; Schema: -; Owner: 
--

COMMENT ON EXTENSION "uuid-ossp" IS 'generate universally unique identifiers (UUIDs)';


--
-- Name: attackpathstatus; Type: TYPE; Schema: public; Owner: postgres
--

CREATE TYPE public.attackpathstatus AS ENUM (
    'IDENTIFIED',
    'VERIFIED',
    'EXPLOITED',
    'BLOCKED',
    'FALSE_POSITIVE'
);


ALTER TYPE public.attackpathstatus OWNER TO postgres;

--
-- Name: bugbountyplatform; Type: TYPE; Schema: public; Owner: postgres
--

CREATE TYPE public.bugbountyplatform AS ENUM (
    'HACKERONE',
    'BUGCROWD',
    'INTIGRITI',
    'YESWEHACK',
    'CUSTOM'
);


ALTER TYPE public.bugbountyplatform OWNER TO postgres;

--
-- Name: portstatus; Type: TYPE; Schema: public; Owner: postgres
--

CREATE TYPE public.portstatus AS ENUM (
    'OPEN',
    'CLOSED',
    'FILTERED',
    'UNFILTERED',
    'OPEN_FILTERED',
    'CLOSED_FILTERED',
    'UNKNOWN'
);


ALTER TYPE public.portstatus OWNER TO postgres;

--
-- Name: reconcategory; Type: TYPE; Schema: public; Owner: postgres
--

CREATE TYPE public.reconcategory AS ENUM (
    'DOMAIN_WHOIS',
    'SUBDOMAIN_ENUMERATION',
    'CERTIFICATE_TRANSPARENCY',
    'PUBLIC_REPOSITORIES',
    'SEARCH_ENGINE_DORKING',
    'DATA_BREACHES',
    'INFRASTRUCTURE_EXPOSURE',
    'ARCHIVE_HISTORICAL',
    'SOCIAL_MEDIA_OSINT',
    'CLOUD_ASSETS'
);


ALTER TYPE public.reconcategory OWNER TO postgres;

--
-- Name: reportformat; Type: TYPE; Schema: public; Owner: postgres
--

CREATE TYPE public.reportformat AS ENUM (
    'PDF',
    'HTML',
    'MARKDOWN',
    'JSON',
    'XML'
);


ALTER TYPE public.reportformat OWNER TO postgres;

--
-- Name: reportstatus; Type: TYPE; Schema: public; Owner: postgres
--

CREATE TYPE public.reportstatus AS ENUM (
    'GENERATING',
    'COMPLETED',
    'FAILED',
    'CANCELLED'
);


ALTER TYPE public.reportstatus OWNER TO postgres;

--
-- Name: reporttype; Type: TYPE; Schema: public; Owner: postgres
--

CREATE TYPE public.reporttype AS ENUM (
    'EXECUTIVE_SUMMARY',
    'TECHNICAL_DETAILED',
    'VULNERABILITY_REPORT',
    'KILL_CHAIN_ANALYSIS',
    'COMPLIANCE_REPORT',
    'CUSTOM'
);


ALTER TYPE public.reporttype OWNER TO postgres;

--
-- Name: servicestatus; Type: TYPE; Schema: public; Owner: postgres
--

CREATE TYPE public.servicestatus AS ENUM (
    'DETECTED',
    'CONFIRMED',
    'UNKNOWN'
);


ALTER TYPE public.servicestatus OWNER TO postgres;

--
-- Name: subdomainstatus; Type: TYPE; Schema: public; Owner: postgres
--

CREATE TYPE public.subdomainstatus AS ENUM (
    'ACTIVE',
    'INACTIVE',
    'UNKNOWN'
);


ALTER TYPE public.subdomainstatus OWNER TO postgres;

--
-- Name: targetstatus; Type: TYPE; Schema: public; Owner: postgres
--

CREATE TYPE public.targetstatus AS ENUM (
    'ACTIVE',
    'INACTIVE'
);


ALTER TYPE public.targetstatus OWNER TO postgres;

--
-- Name: vulnerabilityseverity; Type: TYPE; Schema: public; Owner: postgres
--

CREATE TYPE public.vulnerabilityseverity AS ENUM (
    'CRITICAL',
    'HIGH',
    'MEDIUM',
    'LOW',
    'INFO'
);


ALTER TYPE public.vulnerabilityseverity OWNER TO postgres;

--
-- Name: vulnerabilitystatus; Type: TYPE; Schema: public; Owner: postgres
--

CREATE TYPE public.vulnerabilitystatus AS ENUM (
    'OPEN',
    'VERIFIED',
    'FALSE_POSITIVE',
    'FIXED',
    'WONT_FIX',
    'DUPLICATE'
);


ALTER TYPE public.vulnerabilitystatus OWNER TO postgres;

--
-- Name: vulnerabilitytype; Type: TYPE; Schema: public; Owner: postgres
--

CREATE TYPE public.vulnerabilitytype AS ENUM (
    'SQL_INJECTION',
    'XSS',
    'CSRF',
    'SSRF',
    'RCE',
    'LFI',
    'RFI',
    'IDOR',
    'BROKEN_AUTH',
    'SENSITIVE_DATA_EXPOSURE',
    'SECURITY_MISCONFIGURATION',
    'INSECURE_DESERIALIZATION',
    'COMPONENTS_WITH_KNOWN_VULNERABILITIES',
    'INSUFFICIENT_LOGGING',
    'OTHER'
);


ALTER TYPE public.vulnerabilitytype OWNER TO postgres;

--
-- Name: workflowstage; Type: TYPE; Schema: public; Owner: postgres
--

CREATE TYPE public.workflowstage AS ENUM (
    'PASSIVE_RECON',
    'ACTIVE_RECON',
    'VULN_SCAN',
    'VULN_TEST',
    'KILL_CHAIN',
    'REPORT'
);


ALTER TYPE public.workflowstage OWNER TO postgres;

--
-- Name: workflowstatus; Type: TYPE; Schema: public; Owner: postgres
--

CREATE TYPE public.workflowstatus AS ENUM (
    'PENDING',
    'RUNNING',
    'COMPLETED',
    'FAILED',
    'CANCELLED',
    'PAUSED'
);


ALTER TYPE public.workflowstatus OWNER TO postgres;

SET default_tablespace = '';

SET default_table_access_method = heap;

--
-- Name: active_recon_results; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.active_recon_results (
    execution_id character varying(255) NOT NULL,
    tools_used jsonb,
    configuration jsonb,
    scan_type character varying(100),
    hosts_scanned jsonb NOT NULL,
    total_hosts_scanned integer NOT NULL,
    hosts_with_open_ports integer NOT NULL,
    total_open_ports integer NOT NULL,
    total_services_detected integer NOT NULL,
    raw_output jsonb,
    processed_data jsonb,
    execution_time double precision,
    errors jsonb,
    target_id uuid NOT NULL,
    id uuid NOT NULL,
    created_at timestamp with time zone NOT NULL,
    updated_at timestamp with time zone NOT NULL,
    notes text
);


ALTER TABLE public.active_recon_results OWNER TO postgres;

--
-- Name: alembic_version; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.alembic_version (
    version_num character varying(32) NOT NULL
);


ALTER TABLE public.alembic_version OWNER TO postgres;

--
-- Name: archive_findings; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.archive_findings (
    id uuid NOT NULL,
    created_at timestamp with time zone NOT NULL,
    updated_at timestamp with time zone NOT NULL,
    archive_source character varying(50) NOT NULL,
    finding_type character varying(100) NOT NULL,
    original_url character varying(500),
    archived_url character varying(500),
    archive_date character varying(50),
    content text,
    parameters jsonb,
    secrets_found jsonb,
    passive_recon_result_id uuid NOT NULL
);


ALTER TABLE public.archive_findings OWNER TO postgres;

--
-- Name: attack_paths; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.attack_paths (
    name character varying(500) NOT NULL,
    description text,
    status public.attackpathstatus NOT NULL,
    attack_path_type character varying(100),
    severity character varying(50),
    stages jsonb,
    entry_points jsonb,
    exit_points jsonb,
    prerequisites jsonb,
    techniques jsonb,
    tools_required jsonb,
    evidence text,
    proof_of_concept text,
    screenshots jsonb,
    risk_score double precision,
    impact_assessment text,
    remediation text,
    attack_path_metadata jsonb,
    phases jsonb,
    tactics jsonb,
    intermediate_nodes jsonb,
    likelihood character varying(50),
    impact character varying(50),
    is_verified boolean NOT NULL,
    verification_evidence jsonb,
    verification_notes text,
    is_exploitable boolean NOT NULL,
    exploitation_evidence jsonb,
    exploitation_notes text,
    mitigation_controls jsonb,
    recommended_controls jsonb,
    tags jsonb,
    notes text,
    kill_chain_id uuid NOT NULL,
    id uuid NOT NULL,
    created_at timestamp with time zone NOT NULL,
    updated_at timestamp with time zone NOT NULL
);


ALTER TABLE public.attack_paths OWNER TO postgres;

--
-- Name: breach_records; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.breach_records (
    id uuid NOT NULL,
    created_at timestamp with time zone NOT NULL,
    updated_at timestamp with time zone NOT NULL,
    breach_source character varying(255) NOT NULL,
    breach_type character varying(100) NOT NULL,
    email character varying(255),
    username character varying(255),
    password_hash character varying(255),
    personal_info jsonb,
    breach_date character varying(50),
    breach_name character varying(255),
    severity character varying(50),
    passive_recon_result_id uuid NOT NULL
);


ALTER TABLE public.breach_records OWNER TO postgres;

--
-- Name: certificate_logs; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.certificate_logs (
    id uuid NOT NULL,
    created_at timestamp with time zone NOT NULL,
    updated_at timestamp with time zone NOT NULL,
    domain character varying(500) NOT NULL,
    certificate_id character varying(255),
    issuer character varying(255),
    subject_alt_names jsonb,
    not_before character varying(50),
    not_after character varying(50),
    serial_number character varying(255),
    fingerprint character varying(255),
    log_index character varying(255),
    passive_recon_result_id uuid NOT NULL
);


ALTER TABLE public.certificate_logs OWNER TO postgres;

--
-- Name: cloud_assets; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.cloud_assets (
    id uuid NOT NULL,
    created_at timestamp with time zone NOT NULL,
    updated_at timestamp with time zone NOT NULL,
    provider character varying(50) NOT NULL,
    asset_type character varying(100) NOT NULL,
    asset_name character varying(255),
    asset_url character varying(500),
    is_public boolean NOT NULL,
    permissions jsonb,
    contents jsonb,
    misconfiguration text,
    passive_recon_result_id uuid NOT NULL
);


ALTER TABLE public.cloud_assets OWNER TO postgres;

--
-- Name: infrastructure_exposures; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.infrastructure_exposures (
    id uuid NOT NULL,
    created_at timestamp with time zone NOT NULL,
    updated_at timestamp with time zone NOT NULL,
    source character varying(50) NOT NULL,
    ip_address character varying(45),
    port integer,
    service character varying(100),
    banner text,
    ssl_info jsonb,
    vulnerabilities jsonb,
    location jsonb,
    organization character varying(255),
    passive_recon_result_id uuid NOT NULL
);


ALTER TABLE public.infrastructure_exposures OWNER TO postgres;

--
-- Name: kill_chains; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.kill_chains (
    execution_id character varying(255),
    total_paths_identified integer NOT NULL,
    critical_paths integer NOT NULL,
    high_paths integer NOT NULL,
    medium_paths integer NOT NULL,
    low_paths integer NOT NULL,
    info_paths integer NOT NULL,
    verified_paths integer NOT NULL,
    execution_time double precision,
    analysis_config jsonb,
    raw_output jsonb,
    kill_chain_metadata jsonb,
    analysis_type character varying(100),
    methodology character varying(255),
    configuration jsonb,
    exploitable_paths integer NOT NULL,
    blocked_paths integer NOT NULL,
    raw_analysis jsonb,
    processed_paths jsonb,
    errors jsonb,
    target_id uuid NOT NULL,
    id uuid NOT NULL,
    created_at timestamp with time zone NOT NULL,
    updated_at timestamp with time zone NOT NULL,
    notes text
);


ALTER TABLE public.kill_chains OWNER TO postgres;

--
-- Name: passive_recon_results; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.passive_recon_results (
    execution_id character varying(255) NOT NULL,
    tools_used jsonb,
    configuration jsonb,
    total_subdomains integer NOT NULL,
    unique_subdomains integer NOT NULL,
    total_ips integer NOT NULL,
    unique_ips integer NOT NULL,
    raw_output jsonb,
    processed_data jsonb,
    execution_time character varying(50),
    errors jsonb,
    extra_metadata jsonb,
    target_id uuid NOT NULL,
    id uuid NOT NULL,
    created_at timestamp with time zone NOT NULL,
    updated_at timestamp with time zone NOT NULL,
    notes text
);


ALTER TABLE public.passive_recon_results OWNER TO postgres;

--
-- Name: ports; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.ports (
    host character varying(255) NOT NULL,
    port_number integer NOT NULL,
    protocol character varying(10) NOT NULL,
    status public.portstatus NOT NULL,
    is_open boolean NOT NULL,
    service_name character varying(255),
    service_version character varying(255),
    service_product character varying(255),
    banner text,
    script_output jsonb,
    notes text,
    active_recon_result_id uuid NOT NULL,
    id uuid NOT NULL,
    created_at timestamp with time zone NOT NULL,
    updated_at timestamp with time zone NOT NULL
);


ALTER TABLE public.ports OWNER TO postgres;

--
-- Name: reports; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.reports (
    name character varying(255) NOT NULL,
    report_type public.reporttype NOT NULL,
    format public.reportformat NOT NULL,
    status public.reportstatus NOT NULL,
    is_public boolean NOT NULL,
    content text,
    file_path character varying(1000),
    file_size character varying(50),
    template_used character varying(255),
    configuration jsonb,
    summary text,
    key_findings jsonb,
    statistics jsonb,
    generation_time character varying(50),
    generated_by character varying(255),
    errors jsonb,
    access_token character varying(255),
    expires_at character varying(50),
    target_id uuid NOT NULL,
    workflow_id uuid NOT NULL,
    id uuid NOT NULL,
    created_at timestamp with time zone NOT NULL,
    updated_at timestamp with time zone NOT NULL,
    notes text
);


ALTER TABLE public.reports OWNER TO postgres;

--
-- Name: repository_findings; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.repository_findings (
    id uuid NOT NULL,
    created_at timestamp with time zone NOT NULL,
    updated_at timestamp with time zone NOT NULL,
    platform character varying(50) NOT NULL,
    repository_url character varying(500),
    file_path character varying(500),
    finding_type character varying(100) NOT NULL,
    content text,
    line_number integer,
    commit_hash character varying(255),
    severity character varying(50),
    passive_recon_result_id uuid NOT NULL
);


ALTER TABLE public.repository_findings OWNER TO postgres;

--
-- Name: search_dork_results; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.search_dork_results (
    id uuid NOT NULL,
    created_at timestamp with time zone NOT NULL,
    updated_at timestamp with time zone NOT NULL,
    search_query character varying(500) NOT NULL,
    result_type character varying(100) NOT NULL,
    url character varying(500),
    title character varying(500),
    snippet text,
    file_type character varying(50),
    file_size character varying(50),
    passive_recon_result_id uuid NOT NULL
);


ALTER TABLE public.search_dork_results OWNER TO postgres;

--
-- Name: services; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.services (
    name character varying(255) NOT NULL,
    version character varying(255),
    product character varying(255),
    extrainfo character varying(500),
    status public.servicestatus NOT NULL,
    is_confirmed boolean NOT NULL,
    banner text,
    fingerprint jsonb,
    cpe character varying(500),
    tags jsonb,
    notes text,
    port_id uuid NOT NULL,
    active_recon_result_id uuid NOT NULL,
    id uuid NOT NULL,
    created_at timestamp with time zone NOT NULL,
    updated_at timestamp with time zone NOT NULL
);


ALTER TABLE public.services OWNER TO postgres;

--
-- Name: social_media_intel; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.social_media_intel (
    id uuid NOT NULL,
    created_at timestamp with time zone NOT NULL,
    updated_at timestamp with time zone NOT NULL,
    platform character varying(50) NOT NULL,
    intel_type character varying(100) NOT NULL,
    username character varying(255),
    profile_url character varying(500),
    content text,
    intel_metadata jsonb,
    relevance_score integer,
    passive_recon_result_id uuid NOT NULL
);


ALTER TABLE public.social_media_intel OWNER TO postgres;

--
-- Name: subdomains; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.subdomains (
    name character varying(500) NOT NULL,
    domain character varying(255) NOT NULL,
    subdomain_part character varying(255) NOT NULL,
    status public.subdomainstatus NOT NULL,
    is_verified boolean NOT NULL,
    ip_addresses jsonb,
    cname character varying(500),
    mx_records jsonb,
    txt_records jsonb,
    ns_records jsonb,
    sources jsonb,
    first_seen character varying(50),
    last_seen character varying(50),
    tags jsonb,
    notes text,
    extra_metadata jsonb,
    passive_recon_result_id uuid NOT NULL,
    id uuid NOT NULL,
    created_at timestamp with time zone NOT NULL,
    updated_at timestamp with time zone NOT NULL
);


ALTER TABLE public.subdomains OWNER TO postgres;

--
-- Name: targets; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.targets (
    target character varying(255),
    domain character varying(500),
    is_primary boolean NOT NULL,
    status public.targetstatus NOT NULL,
    platform public.bugbountyplatform,
    login_email character varying(255),
    researcher_email character varying(255),
    in_scope jsonb,
    out_of_scope jsonb,
    rate_limit_requests integer,
    rate_limit_seconds integer,
    custom_headers jsonb,
    additional_info jsonb,
    notes text,
    id uuid NOT NULL,
    created_at timestamp with time zone NOT NULL,
    updated_at timestamp with time zone NOT NULL
);


ALTER TABLE public.targets OWNER TO postgres;

--
-- Name: vulnerabilities; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.vulnerabilities (
    execution_id character varying(255) NOT NULL,
    scan_type character varying(100),
    tools_used jsonb,
    configuration jsonb,
    scan_targets jsonb,
    total_findings integer NOT NULL,
    critical_findings integer NOT NULL,
    high_findings integer NOT NULL,
    medium_findings integer NOT NULL,
    low_findings integer NOT NULL,
    info_findings integer NOT NULL,
    raw_output jsonb,
    processed_data jsonb,
    execution_time character varying(50),
    errors jsonb,
    target_id uuid NOT NULL,
    id uuid NOT NULL,
    created_at timestamp with time zone NOT NULL,
    updated_at timestamp with time zone NOT NULL,
    notes text
);


ALTER TABLE public.vulnerabilities OWNER TO postgres;

--
-- Name: vulnerability_findings; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.vulnerability_findings (
    title character varying(500) NOT NULL,
    vuln_type public.vulnerabilitytype NOT NULL,
    severity public.vulnerabilityseverity NOT NULL,
    status public.vulnerabilitystatus NOT NULL,
    description text,
    cve_id character varying(50),
    cvss_score double precision,
    cvss_vector character varying(100),
    affected_host character varying(255),
    affected_port integer,
    affected_service character varying(255),
    affected_url character varying(1000),
    proof_of_concept text,
    remediation text,
    "references" jsonb,
    detection_tool character varying(255),
    detection_method character varying(255),
    confidence character varying(50),
    is_verified boolean NOT NULL,
    verification_notes text,
    tags jsonb,
    notes text,
    vulnerability_id uuid NOT NULL,
    id uuid NOT NULL,
    created_at timestamp with time zone NOT NULL,
    updated_at timestamp with time zone NOT NULL
);


ALTER TABLE public.vulnerability_findings OWNER TO postgres;

--
-- Name: whois_records; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.whois_records (
    id uuid NOT NULL,
    created_at timestamp with time zone NOT NULL,
    updated_at timestamp with time zone NOT NULL,
    domain character varying(500) NOT NULL,
    registrar character varying(255),
    registrant_name character varying(255),
    registrant_email character varying(255),
    registrant_organization character varying(255),
    creation_date character varying(50),
    expiration_date character varying(50),
    updated_date character varying(50),
    name_servers jsonb,
    status jsonb,
    raw_data text,
    passive_recon_result_id uuid NOT NULL
);


ALTER TABLE public.whois_records OWNER TO postgres;

--
-- Name: workflow_executions; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.workflow_executions (
    stage public.workflowstage NOT NULL,
    execution_id character varying(255) NOT NULL,
    status public.workflowstatus NOT NULL,
    started_at timestamp without time zone,
    completed_at timestamp without time zone,
    configuration jsonb,
    results jsonb,
    errors jsonb,
    progress_percentage character varying(10),
    current_step character varying(255),
    workflow_id uuid NOT NULL,
    id uuid NOT NULL,
    created_at timestamp with time zone NOT NULL,
    updated_at timestamp with time zone NOT NULL,
    notes text
);


ALTER TABLE public.workflow_executions OWNER TO postgres;

--
-- Name: workflows; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.workflows (
    name character varying(255) NOT NULL,
    description text,
    stages jsonb NOT NULL,
    dependencies jsonb,
    settings jsonb,
    status public.workflowstatus NOT NULL,
    current_stage public.workflowstage,
    progress character varying(50),
    target_id uuid NOT NULL,
    id uuid NOT NULL,
    created_at timestamp with time zone NOT NULL,
    updated_at timestamp with time zone NOT NULL,
    notes text
);


ALTER TABLE public.workflows OWNER TO postgres;

--
-- Data for Name: active_recon_results; Type: TABLE DATA; Schema: public; Owner: postgres
--

COPY public.active_recon_results (execution_id, tools_used, configuration, scan_type, hosts_scanned, total_hosts_scanned, hosts_with_open_ports, total_open_ports, total_services_detected, raw_output, processed_data, execution_time, errors, target_id, id, created_at, updated_at, notes) FROM stdin;
\.


--
-- Data for Name: alembic_version; Type: TABLE DATA; Schema: public; Owner: postgres
--

COPY public.alembic_version (version_num) FROM stdin;
enhanced_osint_models
\.


--
-- Data for Name: archive_findings; Type: TABLE DATA; Schema: public; Owner: postgres
--

COPY public.archive_findings (id, created_at, updated_at, archive_source, finding_type, original_url, archived_url, archive_date, content, parameters, secrets_found, passive_recon_result_id) FROM stdin;
\.


--
-- Data for Name: attack_paths; Type: TABLE DATA; Schema: public; Owner: postgres
--

COPY public.attack_paths (name, description, status, attack_path_type, severity, stages, entry_points, exit_points, prerequisites, techniques, tools_required, evidence, proof_of_concept, screenshots, risk_score, impact_assessment, remediation, attack_path_metadata, phases, tactics, intermediate_nodes, likelihood, impact, is_verified, verification_evidence, verification_notes, is_exploitable, exploitation_evidence, exploitation_notes, mitigation_controls, recommended_controls, tags, notes, kill_chain_id, id, created_at, updated_at) FROM stdin;
\.


--
-- Data for Name: breach_records; Type: TABLE DATA; Schema: public; Owner: postgres
--

COPY public.breach_records (id, created_at, updated_at, breach_source, breach_type, email, username, password_hash, personal_info, breach_date, breach_name, severity, passive_recon_result_id) FROM stdin;
\.


--
-- Data for Name: certificate_logs; Type: TABLE DATA; Schema: public; Owner: postgres
--

COPY public.certificate_logs (id, created_at, updated_at, domain, certificate_id, issuer, subject_alt_names, not_before, not_after, serial_number, fingerprint, log_index, passive_recon_result_id) FROM stdin;
\.


--
-- Data for Name: cloud_assets; Type: TABLE DATA; Schema: public; Owner: postgres
--

COPY public.cloud_assets (id, created_at, updated_at, provider, asset_type, asset_name, asset_url, is_public, permissions, contents, misconfiguration, passive_recon_result_id) FROM stdin;
\.


--
-- Data for Name: infrastructure_exposures; Type: TABLE DATA; Schema: public; Owner: postgres
--

COPY public.infrastructure_exposures (id, created_at, updated_at, source, ip_address, port, service, banner, ssl_info, vulnerabilities, location, organization, passive_recon_result_id) FROM stdin;
\.


--
-- Data for Name: kill_chains; Type: TABLE DATA; Schema: public; Owner: postgres
--

COPY public.kill_chains (execution_id, total_paths_identified, critical_paths, high_paths, medium_paths, low_paths, info_paths, verified_paths, execution_time, analysis_config, raw_output, kill_chain_metadata, analysis_type, methodology, configuration, exploitable_paths, blocked_paths, raw_analysis, processed_paths, errors, target_id, id, created_at, updated_at, notes) FROM stdin;
\.


--
-- Data for Name: passive_recon_results; Type: TABLE DATA; Schema: public; Owner: postgres
--

COPY public.passive_recon_results (execution_id, tools_used, configuration, total_subdomains, unique_subdomains, total_ips, unique_ips, raw_output, processed_data, execution_time, errors, extra_metadata, target_id, id, created_at, updated_at, notes) FROM stdin;
\.


--
-- Data for Name: ports; Type: TABLE DATA; Schema: public; Owner: postgres
--

COPY public.ports (host, port_number, protocol, status, is_open, service_name, service_version, service_product, banner, script_output, notes, active_recon_result_id, id, created_at, updated_at) FROM stdin;
\.


--
-- Data for Name: reports; Type: TABLE DATA; Schema: public; Owner: postgres
--

COPY public.reports (name, report_type, format, status, is_public, content, file_path, file_size, template_used, configuration, summary, key_findings, statistics, generation_time, generated_by, errors, access_token, expires_at, target_id, workflow_id, id, created_at, updated_at, notes) FROM stdin;
\.


--
-- Data for Name: repository_findings; Type: TABLE DATA; Schema: public; Owner: postgres
--

COPY public.repository_findings (id, created_at, updated_at, platform, repository_url, file_path, finding_type, content, line_number, commit_hash, severity, passive_recon_result_id) FROM stdin;
\.


--
-- Data for Name: search_dork_results; Type: TABLE DATA; Schema: public; Owner: postgres
--

COPY public.search_dork_results (id, created_at, updated_at, search_query, result_type, url, title, snippet, file_type, file_size, passive_recon_result_id) FROM stdin;
\.


--
-- Data for Name: services; Type: TABLE DATA; Schema: public; Owner: postgres
--

COPY public.services (name, version, product, extrainfo, status, is_confirmed, banner, fingerprint, cpe, tags, notes, port_id, active_recon_result_id, id, created_at, updated_at) FROM stdin;
\.


--
-- Data for Name: social_media_intel; Type: TABLE DATA; Schema: public; Owner: postgres
--

COPY public.social_media_intel (id, created_at, updated_at, platform, intel_type, username, profile_url, content, intel_metadata, relevance_score, passive_recon_result_id) FROM stdin;
\.


--
-- Data for Name: subdomains; Type: TABLE DATA; Schema: public; Owner: postgres
--

COPY public.subdomains (name, domain, subdomain_part, status, is_verified, ip_addresses, cname, mx_records, txt_records, ns_records, sources, first_seen, last_seen, tags, notes, extra_metadata, passive_recon_result_id, id, created_at, updated_at) FROM stdin;
\.


--
-- Data for Name: targets; Type: TABLE DATA; Schema: public; Owner: postgres
--

COPY public.targets (target, domain, is_primary, status, platform, login_email, researcher_email, in_scope, out_of_scope, rate_limit_requests, rate_limit_seconds, custom_headers, additional_info, notes, id, created_at, updated_at) FROM stdin;
example llc	example.com	t	ACTIVE	HACKERONE	example@example.com	example@example.com	["example.com"]	["example.org"]	5	1	[{"name": "dfgd:", "value": "hkjk"}]	["hkjh"]	kjhk	e0050d4f-e2a7-4bcc-b46a-93cf5fb069aa	2025-08-06 08:49:35.111693+00	2025-08-06 09:20:08.766514+00
\.


--
-- Data for Name: vulnerabilities; Type: TABLE DATA; Schema: public; Owner: postgres
--

COPY public.vulnerabilities (execution_id, scan_type, tools_used, configuration, scan_targets, total_findings, critical_findings, high_findings, medium_findings, low_findings, info_findings, raw_output, processed_data, execution_time, errors, target_id, id, created_at, updated_at, notes) FROM stdin;
\.


--
-- Data for Name: vulnerability_findings; Type: TABLE DATA; Schema: public; Owner: postgres
--

COPY public.vulnerability_findings (title, vuln_type, severity, status, description, cve_id, cvss_score, cvss_vector, affected_host, affected_port, affected_service, affected_url, proof_of_concept, remediation, "references", detection_tool, detection_method, confidence, is_verified, verification_notes, tags, notes, vulnerability_id, id, created_at, updated_at) FROM stdin;
\.


--
-- Data for Name: whois_records; Type: TABLE DATA; Schema: public; Owner: postgres
--

COPY public.whois_records (id, created_at, updated_at, domain, registrar, registrant_name, registrant_email, registrant_organization, creation_date, expiration_date, updated_date, name_servers, status, raw_data, passive_recon_result_id) FROM stdin;
\.


--
-- Data for Name: workflow_executions; Type: TABLE DATA; Schema: public; Owner: postgres
--

COPY public.workflow_executions (stage, execution_id, status, started_at, completed_at, configuration, results, errors, progress_percentage, current_step, workflow_id, id, created_at, updated_at, notes) FROM stdin;
\.


--
-- Data for Name: workflows; Type: TABLE DATA; Schema: public; Owner: postgres
--

COPY public.workflows (name, description, stages, dependencies, settings, status, current_stage, progress, target_id, id, created_at, updated_at, notes) FROM stdin;
\.


--
-- Name: active_recon_results active_recon_results_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.active_recon_results
    ADD CONSTRAINT active_recon_results_pkey PRIMARY KEY (id);


--
-- Name: alembic_version alembic_version_pkc; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.alembic_version
    ADD CONSTRAINT alembic_version_pkc PRIMARY KEY (version_num);


--
-- Name: archive_findings archive_findings_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.archive_findings
    ADD CONSTRAINT archive_findings_pkey PRIMARY KEY (id);


--
-- Name: attack_paths attack_paths_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.attack_paths
    ADD CONSTRAINT attack_paths_pkey PRIMARY KEY (id);


--
-- Name: breach_records breach_records_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.breach_records
    ADD CONSTRAINT breach_records_pkey PRIMARY KEY (id);


--
-- Name: certificate_logs certificate_logs_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.certificate_logs
    ADD CONSTRAINT certificate_logs_pkey PRIMARY KEY (id);


--
-- Name: cloud_assets cloud_assets_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.cloud_assets
    ADD CONSTRAINT cloud_assets_pkey PRIMARY KEY (id);


--
-- Name: infrastructure_exposures infrastructure_exposures_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.infrastructure_exposures
    ADD CONSTRAINT infrastructure_exposures_pkey PRIMARY KEY (id);


--
-- Name: kill_chains kill_chains_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.kill_chains
    ADD CONSTRAINT kill_chains_pkey PRIMARY KEY (id);


--
-- Name: passive_recon_results passive_recon_results_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.passive_recon_results
    ADD CONSTRAINT passive_recon_results_pkey PRIMARY KEY (id);


--
-- Name: ports ports_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.ports
    ADD CONSTRAINT ports_pkey PRIMARY KEY (id);


--
-- Name: reports reports_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.reports
    ADD CONSTRAINT reports_pkey PRIMARY KEY (id);


--
-- Name: repository_findings repository_findings_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.repository_findings
    ADD CONSTRAINT repository_findings_pkey PRIMARY KEY (id);


--
-- Name: search_dork_results search_dork_results_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.search_dork_results
    ADD CONSTRAINT search_dork_results_pkey PRIMARY KEY (id);


--
-- Name: services services_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.services
    ADD CONSTRAINT services_pkey PRIMARY KEY (id);


--
-- Name: social_media_intel social_media_intel_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.social_media_intel
    ADD CONSTRAINT social_media_intel_pkey PRIMARY KEY (id);


--
-- Name: subdomains subdomains_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.subdomains
    ADD CONSTRAINT subdomains_pkey PRIMARY KEY (id);


--
-- Name: targets targets_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.targets
    ADD CONSTRAINT targets_pkey PRIMARY KEY (id);


--
-- Name: vulnerabilities vulnerabilities_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.vulnerabilities
    ADD CONSTRAINT vulnerabilities_pkey PRIMARY KEY (id);


--
-- Name: vulnerability_findings vulnerability_findings_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.vulnerability_findings
    ADD CONSTRAINT vulnerability_findings_pkey PRIMARY KEY (id);


--
-- Name: whois_records whois_records_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.whois_records
    ADD CONSTRAINT whois_records_pkey PRIMARY KEY (id);


--
-- Name: workflow_executions workflow_executions_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.workflow_executions
    ADD CONSTRAINT workflow_executions_pkey PRIMARY KEY (id);


--
-- Name: workflows workflows_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.workflows
    ADD CONSTRAINT workflows_pkey PRIMARY KEY (id);


--
-- Name: idx_active_recon_created; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_active_recon_created ON public.active_recon_results USING btree (created_at);


--
-- Name: idx_active_recon_execution; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_active_recon_execution ON public.active_recon_results USING btree (execution_id);


--
-- Name: idx_active_recon_target; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_active_recon_target ON public.active_recon_results USING btree (target_id);


--
-- Name: idx_archive_passive_recon; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_archive_passive_recon ON public.archive_findings USING btree (passive_recon_result_id);


--
-- Name: idx_archive_source; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_archive_source ON public.archive_findings USING btree (archive_source);


--
-- Name: idx_archive_type; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_archive_type ON public.archive_findings USING btree (finding_type);


--
-- Name: idx_attack_paths_exploitable; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_attack_paths_exploitable ON public.attack_paths USING btree (is_exploitable);


--
-- Name: idx_attack_paths_kill_chain; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_attack_paths_kill_chain ON public.attack_paths USING btree (kill_chain_id);


--
-- Name: idx_attack_paths_name; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_attack_paths_name ON public.attack_paths USING btree (name);


--
-- Name: idx_attack_paths_status; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_attack_paths_status ON public.attack_paths USING btree (status);


--
-- Name: idx_attack_paths_verified; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_attack_paths_verified ON public.attack_paths USING btree (is_verified);


--
-- Name: idx_breach_passive_recon; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_breach_passive_recon ON public.breach_records USING btree (passive_recon_result_id);


--
-- Name: idx_breach_source; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_breach_source ON public.breach_records USING btree (breach_source);


--
-- Name: idx_breach_type; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_breach_type ON public.breach_records USING btree (breach_type);


--
-- Name: idx_cert_domain; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_cert_domain ON public.certificate_logs USING btree (domain);


--
-- Name: idx_cert_issuer; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_cert_issuer ON public.certificate_logs USING btree (issuer);


--
-- Name: idx_cert_passive_recon; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_cert_passive_recon ON public.certificate_logs USING btree (passive_recon_result_id);


--
-- Name: idx_cloud_passive_recon; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_cloud_passive_recon ON public.cloud_assets USING btree (passive_recon_result_id);


--
-- Name: idx_cloud_provider; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_cloud_provider ON public.cloud_assets USING btree (provider);


--
-- Name: idx_cloud_type; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_cloud_type ON public.cloud_assets USING btree (asset_type);


--
-- Name: idx_dork_passive_recon; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_dork_passive_recon ON public.search_dork_results USING btree (passive_recon_result_id);


--
-- Name: idx_dork_query; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_dork_query ON public.search_dork_results USING btree (search_query);


--
-- Name: idx_dork_type; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_dork_type ON public.search_dork_results USING btree (result_type);


--
-- Name: idx_infra_passive_recon; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_infra_passive_recon ON public.infrastructure_exposures USING btree (passive_recon_result_id);


--
-- Name: idx_infra_service; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_infra_service ON public.infrastructure_exposures USING btree (service);


--
-- Name: idx_infra_source; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_infra_source ON public.infrastructure_exposures USING btree (source);


--
-- Name: idx_kill_chains_created; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_kill_chains_created ON public.kill_chains USING btree (created_at);


--
-- Name: idx_kill_chains_execution; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_kill_chains_execution ON public.kill_chains USING btree (execution_id);


--
-- Name: idx_kill_chains_target; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_kill_chains_target ON public.kill_chains USING btree (target_id);


--
-- Name: idx_passive_recon_created; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_passive_recon_created ON public.passive_recon_results USING btree (created_at);


--
-- Name: idx_passive_recon_execution; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_passive_recon_execution ON public.passive_recon_results USING btree (execution_id);


--
-- Name: idx_passive_recon_target; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_passive_recon_target ON public.passive_recon_results USING btree (target_id);


--
-- Name: idx_ports_active_recon; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_ports_active_recon ON public.ports USING btree (active_recon_result_id);


--
-- Name: idx_ports_host; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_ports_host ON public.ports USING btree (host);


--
-- Name: idx_ports_host_port; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_ports_host_port ON public.ports USING btree (host, port_number, protocol);


--
-- Name: idx_ports_number; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_ports_number ON public.ports USING btree (port_number);


--
-- Name: idx_ports_open; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_ports_open ON public.ports USING btree (is_open);


--
-- Name: idx_ports_protocol; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_ports_protocol ON public.ports USING btree (protocol);


--
-- Name: idx_ports_service; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_ports_service ON public.ports USING btree (service_name);


--
-- Name: idx_ports_status; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_ports_status ON public.ports USING btree (status);


--
-- Name: idx_repo_passive_recon; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_repo_passive_recon ON public.repository_findings USING btree (passive_recon_result_id);


--
-- Name: idx_repo_platform; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_repo_platform ON public.repository_findings USING btree (platform);


--
-- Name: idx_repo_type; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_repo_type ON public.repository_findings USING btree (finding_type);


--
-- Name: idx_reports_created; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_reports_created ON public.reports USING btree (created_at);


--
-- Name: idx_reports_format; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_reports_format ON public.reports USING btree (format);


--
-- Name: idx_reports_name; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_reports_name ON public.reports USING btree (name);


--
-- Name: idx_reports_status; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_reports_status ON public.reports USING btree (status);


--
-- Name: idx_reports_target; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_reports_target ON public.reports USING btree (target_id);


--
-- Name: idx_reports_type; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_reports_type ON public.reports USING btree (report_type);


--
-- Name: idx_reports_workflow; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_reports_workflow ON public.reports USING btree (workflow_id);


--
-- Name: idx_services_active_recon; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_services_active_recon ON public.services USING btree (active_recon_result_id);


--
-- Name: idx_services_confirmed; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_services_confirmed ON public.services USING btree (is_confirmed);


--
-- Name: idx_services_name; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_services_name ON public.services USING btree (name);


--
-- Name: idx_services_port; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_services_port ON public.services USING btree (port_id);


--
-- Name: idx_services_product; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_services_product ON public.services USING btree (product);


--
-- Name: idx_services_status; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_services_status ON public.services USING btree (status);


--
-- Name: idx_social_passive_recon; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_social_passive_recon ON public.social_media_intel USING btree (passive_recon_result_id);


--
-- Name: idx_social_platform; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_social_platform ON public.social_media_intel USING btree (platform);


--
-- Name: idx_social_type; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_social_type ON public.social_media_intel USING btree (intel_type);


--
-- Name: idx_subdomains_domain; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_subdomains_domain ON public.subdomains USING btree (domain);


--
-- Name: idx_subdomains_name; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_subdomains_name ON public.subdomains USING btree (name);


--
-- Name: idx_subdomains_passive_recon; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_subdomains_passive_recon ON public.subdomains USING btree (passive_recon_result_id);


--
-- Name: idx_subdomains_status; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_subdomains_status ON public.subdomains USING btree (status);


--
-- Name: idx_subdomains_verified; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_subdomains_verified ON public.subdomains USING btree (is_verified);


--
-- Name: idx_targets_domain; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_targets_domain ON public.targets USING btree (domain);


--
-- Name: idx_targets_status; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_targets_status ON public.targets USING btree (status);


--
-- Name: idx_vulnerabilities_created; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_vulnerabilities_created ON public.vulnerabilities USING btree (created_at);


--
-- Name: idx_vulnerabilities_execution; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_vulnerabilities_execution ON public.vulnerabilities USING btree (execution_id);


--
-- Name: idx_vulnerabilities_target; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_vulnerabilities_target ON public.vulnerabilities USING btree (target_id);


--
-- Name: idx_vulnerability_findings_cve; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_vulnerability_findings_cve ON public.vulnerability_findings USING btree (cve_id);


--
-- Name: idx_vulnerability_findings_host; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_vulnerability_findings_host ON public.vulnerability_findings USING btree (affected_host);


--
-- Name: idx_vulnerability_findings_severity; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_vulnerability_findings_severity ON public.vulnerability_findings USING btree (severity);


--
-- Name: idx_vulnerability_findings_status; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_vulnerability_findings_status ON public.vulnerability_findings USING btree (status);


--
-- Name: idx_vulnerability_findings_title; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_vulnerability_findings_title ON public.vulnerability_findings USING btree (title);


--
-- Name: idx_vulnerability_findings_type; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_vulnerability_findings_type ON public.vulnerability_findings USING btree (vuln_type);


--
-- Name: idx_vulnerability_findings_verified; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_vulnerability_findings_verified ON public.vulnerability_findings USING btree (is_verified);


--
-- Name: idx_vulnerability_findings_vulnerability; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_vulnerability_findings_vulnerability ON public.vulnerability_findings USING btree (vulnerability_id);


--
-- Name: idx_whois_domain; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_whois_domain ON public.whois_records USING btree (domain);


--
-- Name: idx_whois_passive_recon; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_whois_passive_recon ON public.whois_records USING btree (passive_recon_result_id);


--
-- Name: idx_whois_registrar; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_whois_registrar ON public.whois_records USING btree (registrar);


--
-- Name: idx_workflow_executions_execution_id; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_workflow_executions_execution_id ON public.workflow_executions USING btree (execution_id);


--
-- Name: idx_workflow_executions_stage; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_workflow_executions_stage ON public.workflow_executions USING btree (stage);


--
-- Name: idx_workflow_executions_status; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_workflow_executions_status ON public.workflow_executions USING btree (status);


--
-- Name: idx_workflow_executions_workflow; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_workflow_executions_workflow ON public.workflow_executions USING btree (workflow_id);


--
-- Name: idx_workflows_current_stage; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_workflows_current_stage ON public.workflows USING btree (current_stage);


--
-- Name: idx_workflows_status; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_workflows_status ON public.workflows USING btree (status);


--
-- Name: idx_workflows_target; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_workflows_target ON public.workflows USING btree (target_id);


--
-- Name: ix_public_active_recon_results_created_at; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX ix_public_active_recon_results_created_at ON public.active_recon_results USING btree (created_at);


--
-- Name: ix_public_active_recon_results_execution_id; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX ix_public_active_recon_results_execution_id ON public.active_recon_results USING btree (execution_id);


--
-- Name: ix_public_active_recon_results_id; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX ix_public_active_recon_results_id ON public.active_recon_results USING btree (id);


--
-- Name: ix_public_attack_paths_created_at; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX ix_public_attack_paths_created_at ON public.attack_paths USING btree (created_at);


--
-- Name: ix_public_attack_paths_id; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX ix_public_attack_paths_id ON public.attack_paths USING btree (id);


--
-- Name: ix_public_attack_paths_is_exploitable; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX ix_public_attack_paths_is_exploitable ON public.attack_paths USING btree (is_exploitable);


--
-- Name: ix_public_attack_paths_is_verified; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX ix_public_attack_paths_is_verified ON public.attack_paths USING btree (is_verified);


--
-- Name: ix_public_attack_paths_name; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX ix_public_attack_paths_name ON public.attack_paths USING btree (name);


--
-- Name: ix_public_attack_paths_status; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX ix_public_attack_paths_status ON public.attack_paths USING btree (status);


--
-- Name: ix_public_kill_chains_created_at; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX ix_public_kill_chains_created_at ON public.kill_chains USING btree (created_at);


--
-- Name: ix_public_kill_chains_execution_id; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX ix_public_kill_chains_execution_id ON public.kill_chains USING btree (execution_id);


--
-- Name: ix_public_kill_chains_id; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX ix_public_kill_chains_id ON public.kill_chains USING btree (id);


--
-- Name: ix_public_passive_recon_results_created_at; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX ix_public_passive_recon_results_created_at ON public.passive_recon_results USING btree (created_at);


--
-- Name: ix_public_passive_recon_results_execution_id; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX ix_public_passive_recon_results_execution_id ON public.passive_recon_results USING btree (execution_id);


--
-- Name: ix_public_passive_recon_results_id; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX ix_public_passive_recon_results_id ON public.passive_recon_results USING btree (id);


--
-- Name: ix_public_ports_created_at; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX ix_public_ports_created_at ON public.ports USING btree (created_at);


--
-- Name: ix_public_ports_host; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX ix_public_ports_host ON public.ports USING btree (host);


--
-- Name: ix_public_ports_id; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX ix_public_ports_id ON public.ports USING btree (id);


--
-- Name: ix_public_ports_is_open; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX ix_public_ports_is_open ON public.ports USING btree (is_open);


--
-- Name: ix_public_ports_port_number; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX ix_public_ports_port_number ON public.ports USING btree (port_number);


--
-- Name: ix_public_ports_protocol; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX ix_public_ports_protocol ON public.ports USING btree (protocol);


--
-- Name: ix_public_ports_service_name; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX ix_public_ports_service_name ON public.ports USING btree (service_name);


--
-- Name: ix_public_ports_status; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX ix_public_ports_status ON public.ports USING btree (status);


--
-- Name: ix_public_reports_access_token; Type: INDEX; Schema: public; Owner: postgres
--

CREATE UNIQUE INDEX ix_public_reports_access_token ON public.reports USING btree (access_token);


--
-- Name: ix_public_reports_created_at; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX ix_public_reports_created_at ON public.reports USING btree (created_at);


--
-- Name: ix_public_reports_format; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX ix_public_reports_format ON public.reports USING btree (format);


--
-- Name: ix_public_reports_id; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX ix_public_reports_id ON public.reports USING btree (id);


--
-- Name: ix_public_reports_is_public; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX ix_public_reports_is_public ON public.reports USING btree (is_public);


--
-- Name: ix_public_reports_name; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX ix_public_reports_name ON public.reports USING btree (name);


--
-- Name: ix_public_reports_report_type; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX ix_public_reports_report_type ON public.reports USING btree (report_type);


--
-- Name: ix_public_reports_status; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX ix_public_reports_status ON public.reports USING btree (status);


--
-- Name: ix_public_reports_workflow_id; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX ix_public_reports_workflow_id ON public.reports USING btree (workflow_id);


--
-- Name: ix_public_services_created_at; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX ix_public_services_created_at ON public.services USING btree (created_at);


--
-- Name: ix_public_services_id; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX ix_public_services_id ON public.services USING btree (id);


--
-- Name: ix_public_services_is_confirmed; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX ix_public_services_is_confirmed ON public.services USING btree (is_confirmed);


--
-- Name: ix_public_services_name; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX ix_public_services_name ON public.services USING btree (name);


--
-- Name: ix_public_services_status; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX ix_public_services_status ON public.services USING btree (status);


--
-- Name: ix_public_subdomains_created_at; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX ix_public_subdomains_created_at ON public.subdomains USING btree (created_at);


--
-- Name: ix_public_subdomains_domain; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX ix_public_subdomains_domain ON public.subdomains USING btree (domain);


--
-- Name: ix_public_subdomains_id; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX ix_public_subdomains_id ON public.subdomains USING btree (id);


--
-- Name: ix_public_subdomains_is_verified; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX ix_public_subdomains_is_verified ON public.subdomains USING btree (is_verified);


--
-- Name: ix_public_subdomains_name; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX ix_public_subdomains_name ON public.subdomains USING btree (name);


--
-- Name: ix_public_subdomains_status; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX ix_public_subdomains_status ON public.subdomains USING btree (status);


--
-- Name: ix_public_subdomains_subdomain_part; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX ix_public_subdomains_subdomain_part ON public.subdomains USING btree (subdomain_part);


--
-- Name: ix_public_targets_created_at; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX ix_public_targets_created_at ON public.targets USING btree (created_at);


--
-- Name: ix_public_targets_domain; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX ix_public_targets_domain ON public.targets USING btree (domain);


--
-- Name: ix_public_targets_id; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX ix_public_targets_id ON public.targets USING btree (id);


--
-- Name: ix_public_targets_target; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX ix_public_targets_target ON public.targets USING btree (target);


--
-- Name: ix_public_vulnerabilities_created_at; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX ix_public_vulnerabilities_created_at ON public.vulnerabilities USING btree (created_at);


--
-- Name: ix_public_vulnerabilities_execution_id; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX ix_public_vulnerabilities_execution_id ON public.vulnerabilities USING btree (execution_id);


--
-- Name: ix_public_vulnerabilities_id; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX ix_public_vulnerabilities_id ON public.vulnerabilities USING btree (id);


--
-- Name: ix_public_vulnerability_findings_affected_host; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX ix_public_vulnerability_findings_affected_host ON public.vulnerability_findings USING btree (affected_host);


--
-- Name: ix_public_vulnerability_findings_created_at; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX ix_public_vulnerability_findings_created_at ON public.vulnerability_findings USING btree (created_at);


--
-- Name: ix_public_vulnerability_findings_cve_id; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX ix_public_vulnerability_findings_cve_id ON public.vulnerability_findings USING btree (cve_id);


--
-- Name: ix_public_vulnerability_findings_id; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX ix_public_vulnerability_findings_id ON public.vulnerability_findings USING btree (id);


--
-- Name: ix_public_vulnerability_findings_is_verified; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX ix_public_vulnerability_findings_is_verified ON public.vulnerability_findings USING btree (is_verified);


--
-- Name: ix_public_vulnerability_findings_severity; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX ix_public_vulnerability_findings_severity ON public.vulnerability_findings USING btree (severity);


--
-- Name: ix_public_vulnerability_findings_status; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX ix_public_vulnerability_findings_status ON public.vulnerability_findings USING btree (status);


--
-- Name: ix_public_vulnerability_findings_title; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX ix_public_vulnerability_findings_title ON public.vulnerability_findings USING btree (title);


--
-- Name: ix_public_vulnerability_findings_vuln_type; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX ix_public_vulnerability_findings_vuln_type ON public.vulnerability_findings USING btree (vuln_type);


--
-- Name: ix_public_workflow_executions_created_at; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX ix_public_workflow_executions_created_at ON public.workflow_executions USING btree (created_at);


--
-- Name: ix_public_workflow_executions_execution_id; Type: INDEX; Schema: public; Owner: postgres
--

CREATE UNIQUE INDEX ix_public_workflow_executions_execution_id ON public.workflow_executions USING btree (execution_id);


--
-- Name: ix_public_workflow_executions_id; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX ix_public_workflow_executions_id ON public.workflow_executions USING btree (id);


--
-- Name: ix_public_workflow_executions_stage; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX ix_public_workflow_executions_stage ON public.workflow_executions USING btree (stage);


--
-- Name: ix_public_workflow_executions_status; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX ix_public_workflow_executions_status ON public.workflow_executions USING btree (status);


--
-- Name: ix_public_workflows_created_at; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX ix_public_workflows_created_at ON public.workflows USING btree (created_at);


--
-- Name: ix_public_workflows_id; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX ix_public_workflows_id ON public.workflows USING btree (id);


--
-- Name: ix_public_workflows_name; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX ix_public_workflows_name ON public.workflows USING btree (name);


--
-- Name: ix_public_workflows_status; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX ix_public_workflows_status ON public.workflows USING btree (status);


--
-- Name: active_recon_results active_recon_results_target_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.active_recon_results
    ADD CONSTRAINT active_recon_results_target_id_fkey FOREIGN KEY (target_id) REFERENCES public.targets(id);


--
-- Name: archive_findings archive_findings_passive_recon_result_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.archive_findings
    ADD CONSTRAINT archive_findings_passive_recon_result_id_fkey FOREIGN KEY (passive_recon_result_id) REFERENCES public.passive_recon_results(id);


--
-- Name: attack_paths attack_paths_kill_chain_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.attack_paths
    ADD CONSTRAINT attack_paths_kill_chain_id_fkey FOREIGN KEY (kill_chain_id) REFERENCES public.kill_chains(id);


--
-- Name: breach_records breach_records_passive_recon_result_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.breach_records
    ADD CONSTRAINT breach_records_passive_recon_result_id_fkey FOREIGN KEY (passive_recon_result_id) REFERENCES public.passive_recon_results(id);


--
-- Name: certificate_logs certificate_logs_passive_recon_result_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.certificate_logs
    ADD CONSTRAINT certificate_logs_passive_recon_result_id_fkey FOREIGN KEY (passive_recon_result_id) REFERENCES public.passive_recon_results(id);


--
-- Name: cloud_assets cloud_assets_passive_recon_result_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.cloud_assets
    ADD CONSTRAINT cloud_assets_passive_recon_result_id_fkey FOREIGN KEY (passive_recon_result_id) REFERENCES public.passive_recon_results(id);


--
-- Name: infrastructure_exposures infrastructure_exposures_passive_recon_result_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.infrastructure_exposures
    ADD CONSTRAINT infrastructure_exposures_passive_recon_result_id_fkey FOREIGN KEY (passive_recon_result_id) REFERENCES public.passive_recon_results(id);


--
-- Name: kill_chains kill_chains_target_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.kill_chains
    ADD CONSTRAINT kill_chains_target_id_fkey FOREIGN KEY (target_id) REFERENCES public.targets(id);


--
-- Name: passive_recon_results passive_recon_results_target_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.passive_recon_results
    ADD CONSTRAINT passive_recon_results_target_id_fkey FOREIGN KEY (target_id) REFERENCES public.targets(id);


--
-- Name: ports ports_active_recon_result_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.ports
    ADD CONSTRAINT ports_active_recon_result_id_fkey FOREIGN KEY (active_recon_result_id) REFERENCES public.active_recon_results(id);


--
-- Name: reports reports_target_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.reports
    ADD CONSTRAINT reports_target_id_fkey FOREIGN KEY (target_id) REFERENCES public.targets(id);


--
-- Name: reports reports_workflow_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.reports
    ADD CONSTRAINT reports_workflow_id_fkey FOREIGN KEY (workflow_id) REFERENCES public.workflows(id);


--
-- Name: repository_findings repository_findings_passive_recon_result_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.repository_findings
    ADD CONSTRAINT repository_findings_passive_recon_result_id_fkey FOREIGN KEY (passive_recon_result_id) REFERENCES public.passive_recon_results(id);


--
-- Name: search_dork_results search_dork_results_passive_recon_result_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.search_dork_results
    ADD CONSTRAINT search_dork_results_passive_recon_result_id_fkey FOREIGN KEY (passive_recon_result_id) REFERENCES public.passive_recon_results(id);


--
-- Name: services services_active_recon_result_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.services
    ADD CONSTRAINT services_active_recon_result_id_fkey FOREIGN KEY (active_recon_result_id) REFERENCES public.active_recon_results(id);


--
-- Name: services services_port_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.services
    ADD CONSTRAINT services_port_id_fkey FOREIGN KEY (port_id) REFERENCES public.ports(id);


--
-- Name: social_media_intel social_media_intel_passive_recon_result_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.social_media_intel
    ADD CONSTRAINT social_media_intel_passive_recon_result_id_fkey FOREIGN KEY (passive_recon_result_id) REFERENCES public.passive_recon_results(id);


--
-- Name: subdomains subdomains_passive_recon_result_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.subdomains
    ADD CONSTRAINT subdomains_passive_recon_result_id_fkey FOREIGN KEY (passive_recon_result_id) REFERENCES public.passive_recon_results(id);


--
-- Name: vulnerabilities vulnerabilities_target_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.vulnerabilities
    ADD CONSTRAINT vulnerabilities_target_id_fkey FOREIGN KEY (target_id) REFERENCES public.targets(id);


--
-- Name: vulnerability_findings vulnerability_findings_vulnerability_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.vulnerability_findings
    ADD CONSTRAINT vulnerability_findings_vulnerability_id_fkey FOREIGN KEY (vulnerability_id) REFERENCES public.vulnerabilities(id);


--
-- Name: whois_records whois_records_passive_recon_result_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.whois_records
    ADD CONSTRAINT whois_records_passive_recon_result_id_fkey FOREIGN KEY (passive_recon_result_id) REFERENCES public.passive_recon_results(id);


--
-- Name: workflow_executions workflow_executions_workflow_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.workflow_executions
    ADD CONSTRAINT workflow_executions_workflow_id_fkey FOREIGN KEY (workflow_id) REFERENCES public.workflows(id);


--
-- Name: workflows workflows_target_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.workflows
    ADD CONSTRAINT workflows_target_id_fkey FOREIGN KEY (target_id) REFERENCES public.targets(id);


--
-- PostgreSQL database dump complete
--

