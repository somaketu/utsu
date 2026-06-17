use pyo3::prelude::*;
use pyo3::types::PyDict;
use reqwest::blocking::Client;
use reqwest::header::{HeaderMap, HeaderName, HeaderValue};
use scraper::{Html, Selector};
use std::collections::{HashSet, HashMap};
use std::net::{IpAddr, ToSocketAddrs};
use std::time::Duration;
use url::Url;
use regex::Regex;

fn is_safe_host(host: &str) -> bool {
    if let Ok(mut addrs) = format!("{}:80", host).to_socket_addrs() {
        if let Some(addr) = addrs.next() {
            let ip = addr.ip();
            match ip {
                IpAddr::V4(ipv4) => {
                    if ipv4.is_loopback() || ipv4.is_private() || ipv4.is_link_local() || ipv4.is_unspecified() || ipv4.is_broadcast() || ipv4.is_documentation() {
                        return false;
                    }
                }
                IpAddr::V6(ipv6) => {
                    if ipv6.is_loopback() || ipv6.is_unspecified() {
                        return false;
                    }
                }
            }
            return true;
        }
    }
    false 
}

#[pyfunction]
#[pyo3(signature = (target_url, max_depth, headers=None))]
fn crawl_url(py: Python, target_url: String, max_depth: u32, headers: Option<Vec<String>>) -> PyResult<Py<PyDict>> {
    let mut visited = HashSet::new();
    let mut links = HashSet::new();
    let mut scripts = HashSet::new();
    let mut forms = HashSet::new();
    
    let mut safe_hosts_cache: HashMap<String, bool> = HashMap::new();

    let mut header_map = HeaderMap::new();
    if let Some(h_list) = headers {
        for h in h_list {
            if let Some((k, v)) = h.split_once(':') {
                if let (Ok(k_name), Ok(v_val)) = (HeaderName::from_bytes(k.trim().as_bytes()), HeaderValue::from_str(v.trim())) {
                    header_map.insert(k_name, v_val);
                }
            }
        }
    }

    let client = Client::builder()
        .timeout(Duration::from_secs(10))
        .danger_accept_invalid_certs(true)
        .user_agent("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/149.0.0.0 Safari/537.36")
        .default_headers(header_map)
        .build()
        .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(format!("Failed to build client: {}", e)))?;

    let base_url = Url::parse(&target_url)
        .map_err(|e| pyo3::exceptions::PyValueError::new_err(format!("Invalid Target URL: {}", e)))?;
    
    let mut queue = vec![(base_url.clone(), 0)];

    while let Some((current_url, depth)) = queue.pop() {
        if depth > max_depth || !visited.insert(current_url.to_string()) {
            continue;
        }

        let host = match current_url.host_str() {
            Some(h) => h,
            None => continue,
        };

        let is_safe = *safe_hosts_cache.entry(host.to_string()).or_insert_with(|| is_safe_host(host));
        if !is_safe {
            continue; 
        }

        let text = py.allow_threads(|| {
            client.get(current_url.clone()).send().and_then(|res| res.text())
        });

        let html_content = match text {
            Ok(t) => t,
            Err(_) => continue, 
        };

        let document = Html::parse_document(&html_content);
        
        if let Ok(a_selector) = Selector::parse("a[href]") {
            for element in document.select(&a_selector) {
                if let Some(href) = element.attr("href") {
                    if let Ok(parsed) = current_url.join(href) {
                        if parsed.scheme() == "http" || parsed.scheme() == "https" {
                            links.insert(parsed.to_string());
                            if depth < max_depth && parsed.host_str() == base_url.host_str() {
                                queue.push((parsed, depth + 1));
                            }
                        }
                    }
                }
            }
        }

        if let Ok(script_selector) = Selector::parse("script[src]") {
            for element in document.select(&script_selector) {
                if let Some(src) = element.attr("src") {
                    if let Ok(parsed) = current_url.join(src) {
                        scripts.insert(parsed.to_string());
                    }
                }
            }
        }

        if let Ok(form_selector) = Selector::parse("form[action]") {
            for element in document.select(&form_selector) {
                if let Some(action) = element.attr("action") {
                    if let Ok(parsed) = current_url.join(action) {
                        forms.insert(parsed.to_string());
                    }
                }
            }
        }
    }

    let dict = PyDict::new(py);
    dict.set_item("links", links.into_iter().collect::<Vec<String>>())?;
    dict.set_item("scripts", scripts.into_iter().collect::<Vec<String>>())?;
    dict.set_item("forms", forms.into_iter().collect::<Vec<String>>())?;

    Ok(dict.into())
}

#[pyfunction]
fn extract_security_intel(content: String) -> PyResult<Py<PyDict>> {
    let mut secrets = HashSet::new();
    let mut endpoints = HashSet::new();

    let triggers = ["AIza", "AKIA", "ghp_", "sq0csp-", "xoxb-", "Bearer ", "X-Shopify-Access-Token"];
    for trigger in triggers.iter() {
        if content.contains(trigger) {
            secrets.insert(format!("Potential credential/token identified: {}", trigger));
        }
    }

    let re = Regex::new(r#"(?i)(?:\"|\'|\`)(/?(?:api|admin/internal|graphql|operations|v[0-9]+)/[a-zA-Z0-9_/\-\.]+)(?:\"|\'|\`)"#).unwrap();
    
    for cap in re.captures_iter(&content) {
        if let Some(matched) = cap.get(1) {
            endpoints.insert(matched.as_str().to_string());
        }
    }

    Python::with_gil(|py| {
        let dict = PyDict::new(py);
        dict.set_item("secrets", secrets.into_iter().collect::<Vec<String>>()).unwrap();
        dict.set_item("endpoints", endpoints.into_iter().collect::<Vec<String>>()).unwrap();
        Ok(dict.into())
    })
}

#[pymodule]
fn utsu_rust_core(_py: Python, m: &PyModule) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(crawl_url, m)?)?;
    m.add_function(wrap_pyfunction!(extract_security_intel, m)?)?;
    Ok(())
}